package utils

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/slack-go/slack"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSlackArtifactItems_FiltersEmptyAndAppliesDefaults(t *testing.T) {
	items := buildSlackArtifactItems(
		[]string{"linux"},
		[]string{"amd64", "", "", "arm64"},
		[]string{" https://example.com/linux.zip ", "", "   ", "https://example.com/macos.dmg"},
		[]string{".zip", "", "", ".dmg"},
	)

	require.Len(t, items, 2)

	assert.Equal(t, slackArtifactItem{
		Link:      "https://example.com/linux.zip",
		Extension: "zip",
		Platform:  "linux",
		Arch:      "amd64",
	}, items[0])

	assert.Equal(t, slackArtifactItem{
		Link:      "https://example.com/macos.dmg",
		Extension: "dmg",
		Platform:  "unknown",
		Arch:      "arm64",
	}, items[1])
}

func TestBuildSlackNotificationBlocks_OmitsArtifactsSectionWhenNoValidArtifacts(t *testing.T) {
	blocks := buildSlackNotificationBlocks(
		"Demo App",
		"stable",
		"1.2.3",
		[]string{"linux"},
		[]string{"amd64"},
		[]string{"", "   "},
		nil,
		[]string{".zip"},
		true,
		false,
	)

	require.Len(t, blocks, 2)
	assert.Equal(t, slack.MBTHeader, blocks[0].BlockType())
	assert.Equal(t, slack.MBTSection, blocks[1].BlockType())
}

func TestBuildSlackNotificationBlocks_IncludesArtifactsAndChangelogSections(t *testing.T) {
	blocks := buildSlackNotificationBlocks(
		"Demo App",
		"stable",
		"1.2.3",
		[]string{"linux"},
		[]string{"amd64"},
		[]string{"https://example.com/linux.zip"},
		[]string{"Added delta updates", "Improved startup time"},
		[]string{".zip"},
		true,
		false,
	)

	require.Len(t, blocks, 8)

	headerTexts := make([]string, 0)
	for _, block := range blocks {
		header, ok := block.(*slack.HeaderBlock)
		if ok && header.Text != nil {
			headerTexts = append(headerTexts, header.Text.Text)
		}
	}

	assert.Contains(t, headerTexts, "Application version upload")
	assert.Contains(t, headerTexts, "Artifacts")
	assert.Contains(t, headerTexts, "Changelog")

	artifactSection, ok := blocks[4].(*slack.SectionBlock)
	require.True(t, ok)
	require.NotNil(t, artifactSection.Text)
	assert.Contains(t, artifactSection.Text.Text, "Download for linux")
}

func TestGetSlackNotificationTTL_DefaultWhenUnset(t *testing.T) {
	env := viper.New()

	assert.Equal(t, defaultSlackNotificationTTL, getSlackNotificationTTL(env))
}

func TestGetSlackNotificationTTL_UsesConfiguredDuration(t *testing.T) {
	env := viper.New()
	env.Set("SLACK_NOTIFICATION_TTL", "90m")

	assert.Equal(t, 90*time.Minute, getSlackNotificationTTL(env))
}

func TestGetSlackNotificationTTL_FallsBackOnInvalidValue(t *testing.T) {
	env := viper.New()
	env.Set("SLACK_NOTIFICATION_TTL", "not-a-duration")

	assert.Equal(t, defaultSlackNotificationTTL, getSlackNotificationTTL(env))
}

func TestBuildSlackNotificationStateKey_AvoidsColonAmbiguity(t *testing.T) {
	keyWithChannelColon := buildSlackNotificationStateKey("alice", "stable:beta", "demo", "1")
	keyWithOwnerColon := buildSlackNotificationStateKey("alice:stable", "beta", "demo", "1")

	assert.NotEqual(t, keyWithChannelColon, keyWithOwnerColon)
}

func TestGetSlackNotificationState_Success(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	stateKey := buildSlackNotificationStateKey("alice", "stable", "demo", "1.2.3")

	err := client.Set(context.Background(), stateKey, `{"channel":"C123","ts":"1712345678.000100"}`, 0).Err()
	require.NoError(t, err)

	state, err := getSlackNotificationState(context.Background(), client, "alice", "stable", "demo", "1.2.3")
	require.NoError(t, err)
	assert.Equal(t, "C123", state.Channel)
	assert.Equal(t, "1712345678.000100", state.TS)
}

func TestGetSlackNotificationState_DeletesInvalidJSONAndTreatsItAsMissing(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	stateKey := buildSlackNotificationStateKey("alice", "stable", "demo", "1.2.3")

	err := client.Set(context.Background(), stateKey, `{"channel":`, 0).Err()
	require.NoError(t, err)

	state, err := getSlackNotificationState(context.Background(), client, "alice", "stable", "demo", "1.2.3")
	assert.Nil(t, state)
	assert.Equal(t, redis.Nil, err)

	_, err = client.Get(context.Background(), stateKey).Result()
	assert.Equal(t, redis.Nil, err)
}

func TestGetSlackNotificationState_DeletesIncompleteStateAndTreatsItAsMissing(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	stateKey := buildSlackNotificationStateKey("alice", "stable", "demo", "1.2.3")

	err := client.Set(context.Background(), stateKey, `{"channel":"C123","ts":""}`, 0).Err()
	require.NoError(t, err)

	state, err := getSlackNotificationState(context.Background(), client, "alice", "stable", "demo", "1.2.3")
	assert.Nil(t, state)
	assert.Equal(t, redis.Nil, err)

	_, err = client.Get(context.Background(), stateKey).Result()
	assert.Equal(t, redis.Nil, err)
}

func TestGetSlackNotificationState_FallsBackToLegacyKey(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	stateKey := buildLegacySlackNotificationStateKey("alice:team", "stable", "demo", "1.2.3")

	err := client.Set(context.Background(), stateKey, `{"channel":"C123","ts":"1712345678.000100"}`, 0).Err()
	require.NoError(t, err)

	state, err := getSlackNotificationState(context.Background(), client, "alice:team", "stable", "demo", "1.2.3")
	require.NoError(t, err)
	assert.Equal(t, "C123", state.Channel)
	assert.Equal(t, "1712345678.000100", state.TS)
}

func TestUpdateExistingSlackNotification_ReturnsNilWhenStateMissing(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	err := updateExistingSlackNotification(context.Background(), client, nil, "alice", "stable", "demo", "1.2.3", nil)
	require.NoError(t, err)
}

func TestDeleteSlackNotificationState_RemovesKey(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	stateKey := buildSlackNotificationStateKey("alice", "stable", "demo", "1.2.3")

	err := client.Set(context.Background(), stateKey, `{"channel":"C123","ts":"1712345678.000100"}`, 0).Err()
	require.NoError(t, err)

	err = DeleteSlackNotificationState("alice", "stable", "demo", "1.2.3", client)
	require.NoError(t, err)

	_, err = client.Get(context.Background(), stateKey).Result()
	assert.Equal(t, redis.Nil, err)
}

func TestDeleteSlackNotificationState_RemovesLegacyKey(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	stateKey := buildLegacySlackNotificationStateKey("alice:team", "stable", "demo", "1.2.3")

	err := client.Set(context.Background(), stateKey, `{"channel":"C123","ts":"1712345678.000100"}`, 0).Err()
	require.NoError(t, err)

	err = DeleteSlackNotificationState("alice:team", "stable", "demo", "1.2.3", client)
	require.NoError(t, err)

	_, err = client.Get(context.Background(), stateKey).Result()
	assert.Equal(t, redis.Nil, err)
}
