package utils

import (
	"context"
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
	maxSlackNotificationRetries   = 5
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

func SendSlackNotification(appName, channel, version string, platforms, arches, artifacts, changelog, extensions []string, env *viper.Viper, rdb *redis.Client, publish, critical bool) {
	token := env.GetString("SLACK_BOT_TOKEN")
	channelID := env.GetString("SLACK_CHANNEL")
	if token == "" || channelID == "" {
		logrus.Warn("Slack notification skipped because SLACK_BOT_TOKEN or SLACK_CHANNEL is empty")
		return
	}

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
		if err := postSlackNotification(api, channelID, blocks); err != nil {
			logrus.Errorf("Error sending Slack message: %s", err)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stateKey := fmt.Sprintf("slack_notification:%s:%s", appName, version)
	ttl := getSlackNotificationTTL(env)

	if err := upsertSlackNotification(ctx, rdb, api, stateKey, channelID, blocks, ttl); err != nil {
		logrus.Errorf("Error upserting Slack message: %s", err)
	}
}

func UpdateSlackNotificationIfExists(appName, channel, version string, platforms, arches, artifacts, changelog, extensions []string, env *viper.Viper, rdb *redis.Client, publish, critical bool) {
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

	stateKey := fmt.Sprintf("slack_notification:%s:%s", appName, version)
	if err := updateExistingSlackNotification(ctx, rdb, api, stateKey, blocks); err != nil {
		logrus.Errorf("Error updating existing Slack message: %s", err)
	}
}

func DeleteSlackNotificationState(appName, version string, rdb *redis.Client) error {
	if rdb == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stateKey := fmt.Sprintf("slack_notification:%s:%s", appName, version)
	if err := rdb.Del(ctx, stateKey).Err(); err != nil {
		return fmt.Errorf("failed to delete Slack notification state for key %s: %w", stateKey, err)
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
		logrus.Debugf("Adding artifact #%d: %s", i+1, artifact.Link)

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

func upsertSlackNotification(ctx context.Context, rdb *redis.Client, api *slack.Client, stateKey, fallbackChannel string, blocks []slack.Block, ttl time.Duration) error {
	lockKey := stateKey + ":lock"

	for attempt := 0; attempt < maxSlackNotificationRetries; attempt++ {
		state, err := getSlackNotificationState(ctx, rdb, stateKey)
		if err == nil {
			return updateSlackNotification(api, state, blocks)
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

			state, err = getSlackNotificationState(ctx, rdb, stateKey)
			if err == nil {
				return updateSlackNotification(api, state, blocks)
			}
			if err != redis.Nil {
				return err
			}

			channelID, timestamp, err := api.PostMessage(
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

func updateExistingSlackNotification(ctx context.Context, rdb *redis.Client, api *slack.Client, stateKey string, blocks []slack.Block) error {
	state, err := getSlackNotificationState(ctx, rdb, stateKey)
	if err == redis.Nil {
		logrus.Debugf("Slack notification state not found for key %s, skipping update", stateKey)
		return nil
	}
	if err != nil {
		return err
	}

	return updateSlackNotification(api, state, blocks)
}

func getSlackNotificationState(ctx context.Context, rdb *redis.Client, stateKey string) (*slackNotificationState, error) {
	payload, err := rdb.Get(ctx, stateKey).Result()
	if err != nil {
		return nil, err
	}

	var state slackNotificationState
	if err := json.Unmarshal([]byte(payload), &state); err != nil {
		return nil, fmt.Errorf("failed to decode Slack notification state: %w", err)
	}
	if state.Channel == "" || state.TS == "" {
		return nil, fmt.Errorf("Slack notification state is incomplete for key %s", stateKey)
	}

	return &state, nil
}

func updateSlackNotification(api *slack.Client, state *slackNotificationState, blocks []slack.Block) error {
	_, _, _, err := api.UpdateMessage(
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

func postSlackNotification(api *slack.Client, channelID string, blocks []slack.Block) error {
	_, timestamp, err := api.PostMessage(
		channelID,
		slack.MsgOptionBlocks(blocks...),
	)
	if err != nil {
		return err
	}

	logrus.Debugf("Slack message sent to channel %s at %s", channelID, timestamp)
	return nil
}
