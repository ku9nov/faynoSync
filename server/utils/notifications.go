package utils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/spf13/viper"
)

const (
	defaultSlackNotificationTTL   = 24 * time.Hour
	defaultSlackNotificationLock  = 20 * time.Second
	defaultSlackNotificationRetry = 250 * time.Millisecond
	maxSlackNotificationRetries   = int(defaultSlackNotificationLock/defaultSlackNotificationRetry) + 1
)

type slackNotificationState struct {
	Channel string `json:"channel"`
	TS      string `json:"ts"`
}

type slackArtifactItem struct {
	Link      string
	Extension string
	Platform  string
	Arch      string
}

func SendSlackNotification(owner, appName, channel, version string, platforms, arches, artifacts, changelog, extensions []string, env *viper.Viper, rdb *redis.Client, publish, critical bool) {
	token := env.GetString("SLACK_BOT_TOKEN")
	channelID := env.GetString("SLACK_CHANNEL")
	if token == "" || channelID == "" {
		logrus.Warn("Slack notification skipped because SLACK_BOT_TOKEN or SLACK_CHANNEL is empty")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	api := slack.New(token)
	blocks := buildSlackNotificationBlocks(appName, channel, version, platforms, arches, artifacts, changelog, extensions, publish, critical)

	logrus.WithFields(logrus.Fields{
		"App Name":            appName,
		"Channel":             channel,
		"Version":             version,
		"Platforms":           platforms,
		"Archs":               arches,
		"Number of Artifacts": len(artifacts),
		"Changelog Entries":   len(changelog),
	}).Debug("Preparing Slack message with the following details")

	if rdb == nil {
		if err := postSlackNotification(ctx, api, channelID, blocks); err != nil {
			logrus.Errorf("Error sending Slack message: %s", err)
		}
		return
	}

	ttl := getSlackNotificationTTL(env)

	if err := upsertSlackNotification(ctx, rdb, api, owner, channel, appName, version, channelID, blocks, ttl); err != nil {
		logrus.Errorf("Error upserting Slack message: %s", err)
	}
}

func UpdateSlackNotificationIfExists(owner, appName, channel, version string, platforms, arches, artifacts, changelog, extensions []string, env *viper.Viper, rdb *redis.Client, publish, critical bool) {
	if rdb == nil {
		return
	}

	token := env.GetString("SLACK_BOT_TOKEN")
	channelID := env.GetString("SLACK_CHANNEL")
	if token == "" || channelID == "" {
		logrus.Warn("Slack notification update skipped because SLACK_BOT_TOKEN or SLACK_CHANNEL is empty")
		return
	}

	api := slack.New(token)
	blocks := buildSlackNotificationBlocks(appName, channel, version, platforms, arches, artifacts, changelog, extensions, publish, critical)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := updateExistingSlackNotification(ctx, rdb, api, owner, channel, appName, version, blocks); err != nil {
		logrus.Errorf("Error updating existing Slack message: %s", err)
	}
}

func DeleteSlackNotificationState(owner, channel, appName, version string, rdb *redis.Client) error {
	if rdb == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stateKeys := buildSlackNotificationStateKeys(owner, channel, appName, version)
	if err := rdb.Del(ctx, stateKeys...).Err(); err != nil {
		return fmt.Errorf("failed to delete Slack notification state for key %s: %w", stateKeys[0], err)
	}

	return nil
}

func buildSlackNotificationBlocks(appName, channel, version string, platforms, arches, artifacts, changelog, extensions []string, publish, critical bool) []slack.Block {
	blocks := []slack.Block{
		slack.NewHeaderBlock(&slack.TextBlockObject{
			Type:  slack.PlainTextType,
			Text:  "Application version upload",
			Emoji: true,
		}),
		slack.NewSectionBlock(nil, []*slack.TextBlockObject{
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf(":package: *App name:*\n%s", appName), false, false),
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf(":bubbles: *Channel name:*\n%s", channel), false, false),
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf(":vs: *Version:*\n%s", version), false, false),
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf(":loudspeaker: *Published:*\n%t", publish), false, false),
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf(":warning: *Critical:*\n%t", critical), false, false),
		}, nil),
	}

	artifactItems := buildSlackArtifactItems(platforms, arches, artifacts, extensions)
	if len(artifactItems) > 0 {
		blocks = append(blocks, slack.NewDividerBlock(), slack.NewHeaderBlock(&slack.TextBlockObject{
			Type:  slack.PlainTextType,
			Text:  "Artifacts",
			Emoji: true,
		}))
	}

	for i, artifact := range artifactItems {
		logrus.Debugf("Adding artifact #%d for platform=%s arch=%s", i+1, artifact.Platform, artifact.Arch)

		downloadText := fmt.Sprintf("*Download for %s (architecture: %s):*", artifact.Platform, artifact.Arch)
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", downloadText, false, false),
			nil,
			slack.NewAccessory(slack.NewButtonBlockElement(
				"button-action",
				fmt.Sprintf("artifact-%d", i),
				slack.NewTextBlockObject("plain_text", artifact.Extension, true, false),
			).WithURL(artifact.Link)),
		))
	}

	if len(changelog) > 0 {
		blocks = append(blocks, slack.NewDividerBlock(), slack.NewHeaderBlock(&slack.TextBlockObject{
			Type: slack.PlainTextType,
			Text: "Changelog",
		}))

		changelogText := strings.Join(changelog, "\n- ")
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("```%s```", changelogText), false, false),
			nil,
			nil,
		))
	}

	return blocks
}

func buildSlackArtifactItems(platforms, arches, artifacts, extensions []string) []slackArtifactItem {
	items := make([]slackArtifactItem, 0, len(artifacts))

	for i, artifact := range artifacts {
		link := strings.TrimSpace(artifact)
		if link == "" {
			continue
		}

		extension := "no-ext"
		if i < len(extensions) && strings.TrimSpace(extensions[i]) != "" {
			extension = strings.TrimPrefix(strings.TrimSpace(extensions[i]), ".")
		}

		platform := "unknown"
		if i < len(platforms) && strings.TrimSpace(platforms[i]) != "" {
			platform = strings.TrimSpace(platforms[i])
		}

		arch := "unknown"
		if i < len(arches) && strings.TrimSpace(arches[i]) != "" {
			arch = strings.TrimSpace(arches[i])
		}

		items = append(items, slackArtifactItem{
			Link:      link,
			Extension: extension,
			Platform:  platform,
			Arch:      arch,
		})
	}

	return items
}

func getSlackNotificationTTL(env *viper.Viper) time.Duration {
	rawTTL := strings.TrimSpace(env.GetString("SLACK_NOTIFICATION_TTL"))
	if rawTTL == "" {
		return defaultSlackNotificationTTL
	}

	ttl, err := time.ParseDuration(rawTTL)
	if err != nil || ttl <= 0 {
		logrus.Warnf("Invalid SLACK_NOTIFICATION_TTL value %q, falling back to %s", rawTTL, defaultSlackNotificationTTL)
		return defaultSlackNotificationTTL
	}

	return ttl
}

func buildSlackNotificationStateKey(owner, channel, appName, version string) string {
	parts := []string{owner, channel, appName, version}
	encodedParts := make([]string, len(parts))
	for i, part := range parts {
		encodedParts[i] = base64.RawURLEncoding.EncodeToString([]byte(part))
	}

	return "slack_notification:" + strings.Join(encodedParts, ":")
}

func buildLegacySlackNotificationStateKey(owner, channel, appName, version string) string {
	return fmt.Sprintf("slack_notification:%s:%s:%s:%s", owner, channel, appName, version)
}

func buildSlackNotificationStateKeys(owner, channel, appName, version string) []string {
	stateKey := buildSlackNotificationStateKey(owner, channel, appName, version)
	legacyKey := buildLegacySlackNotificationStateKey(owner, channel, appName, version)
	if legacyKey == stateKey {
		return []string{stateKey}
	}

	return []string{stateKey, legacyKey}
}

func upsertSlackNotification(ctx context.Context, rdb *redis.Client, api *slack.Client, owner, channel, appName, version, fallbackChannel string, blocks []slack.Block, ttl time.Duration) error {
	stateKey := buildSlackNotificationStateKey(owner, channel, appName, version)
	lockKey := stateKey + ":lock"

	for attempt := 0; attempt < maxSlackNotificationRetries; attempt++ {
		state, err := getSlackNotificationState(ctx, rdb, owner, channel, appName, version)
		if err == nil {
			return updateSlackNotification(ctx, api, state, blocks)
		}
		if err != redis.Nil {
			return err
		}

		locked, err := rdb.SetNX(ctx, lockKey, "1", defaultSlackNotificationLock).Result()
		if err != nil {
			return err
		}
		if locked {
			defer func() {
				if err := rdb.Del(context.Background(), lockKey).Err(); err != nil {
					logrus.Warnf("Failed to release Slack notification lock %s: %v", lockKey, err)
				}
			}()

			state, err = getSlackNotificationState(ctx, rdb, owner, channel, appName, version)
			if err == nil {
				return updateSlackNotification(ctx, api, state, blocks)
			}
			if err != redis.Nil {
				return err
			}

			channelID, timestamp, err := api.PostMessageContext(
				ctx,
				fallbackChannel,
				slack.MsgOptionBlocks(blocks...),
			)
			if err != nil {
				return err
			}

			payload, err := json.Marshal(slackNotificationState{
				Channel: channelID,
				TS:      timestamp,
			})
			if err != nil {
				return err
			}

			if err := rdb.Set(ctx, stateKey, payload, ttl).Err(); err != nil {
				return err
			}

			logrus.Debugf("Slack message created in channel %s at %s", channelID, timestamp)
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultSlackNotificationRetry):
		}
	}

	return fmt.Errorf("failed to obtain Slack notification state for key %s", stateKey)
}

func updateExistingSlackNotification(ctx context.Context, rdb *redis.Client, api *slack.Client, owner, channel, appName, version string, blocks []slack.Block) error {
	stateKey := buildSlackNotificationStateKey(owner, channel, appName, version)
	state, err := getSlackNotificationState(ctx, rdb, owner, channel, appName, version)
	if err == redis.Nil {
		logrus.Debugf("Slack notification state not found for key %s, skipping update", stateKey)
		return nil
	}
	if err != nil {
		return err
	}

	return updateSlackNotification(ctx, api, state, blocks)
}

func getSlackNotificationState(ctx context.Context, rdb *redis.Client, owner, channel, appName, version string) (*slackNotificationState, error) {
	var (
		payload  string
		err      error
		stateKey string
	)

	for _, candidateKey := range buildSlackNotificationStateKeys(owner, channel, appName, version) {
		payload, err = rdb.Get(ctx, candidateKey).Result()
		if err == redis.Nil {
			continue
		}
		if err != nil {
			return nil, err
		}

		stateKey = candidateKey
		break
	}
	if stateKey == "" {
		return nil, redis.Nil
	}

	resetInvalidState := func(reason string, cause error) error {
		if err := rdb.Del(ctx, stateKey).Err(); err != nil {
			if cause != nil {
				return fmt.Errorf("failed to delete invalid Slack notification state for key %s after %s: %v: %w", stateKey, reason, cause, err)
			}
			return fmt.Errorf("failed to delete invalid Slack notification state for key %s: %w", stateKey, err)
		}

		entry := logrus.WithField("state_key", stateKey)
		if cause != nil {
			entry = entry.WithError(cause)
		}
		entry.Warnf("Deleted invalid Slack notification state: %s", reason)

		return redis.Nil
	}

	var state slackNotificationState
	if err := json.Unmarshal([]byte(payload), &state); err != nil {
		return nil, resetInvalidState("failed to decode payload", err)
	}
	if state.Channel == "" || state.TS == "" {
		return nil, resetInvalidState("payload is incomplete", nil)
	}

	return &state, nil
}

func updateSlackNotification(ctx context.Context, api *slack.Client, state *slackNotificationState, blocks []slack.Block) error {
	_, _, _, err := api.UpdateMessageContext(
		ctx,
		state.Channel,
		state.TS,
		slack.MsgOptionBlocks(blocks...),
	)
	if err != nil {
		return err
	}

	logrus.Debugf("Slack message updated in channel %s at %s", state.Channel, state.TS)
	return nil
}

func postSlackNotification(ctx context.Context, api *slack.Client, channelID string, blocks []slack.Block) error {
	_, timestamp, err := api.PostMessageContext(
		ctx,
		channelID,
		slack.MsgOptionBlocks(blocks...),
	)
	if err != nil {
		return err
	}

	logrus.Debugf("Slack message sent to channel %s at %s", channelID, timestamp)
	return nil
}
