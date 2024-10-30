package utils

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/spf13/viper"
)

func SendSlackNotification(appName, channel, version, platform, arch string, artifacts []string, changelog []string, extensions []string, env *viper.Viper) {
	token := env.GetString("SLACK_BOT_TOKEN")
	channelID := env.GetString("SLACK_CHANNEL")
	api := slack.New(token)

	logrus.Debug("Preparing Slack message with the following details:")
	logrus.Debugf("App Name: %s", appName)
	logrus.Debugf("Channel: %s", channel)
	logrus.Debugf("Version: %s", version)
	logrus.Debugf("Platform: %s", platform)
	logrus.Debugf("Arch: %s", arch)
	logrus.Debugf("Number of Artifacts: %d", len(artifacts))
	logrus.Debugf("Changelog Entries: %d", len(changelog))

	// Create blocks for Slack message
	blocks := []slack.Block{
		slack.NewHeaderBlock(&slack.TextBlockObject{
			Type:  slack.PlainTextType,
			Text:  "New version of application is uploaded",
			Emoji: true,
		}),
		slack.NewSectionBlock(nil, []*slack.TextBlockObject{
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf(":package: *App name:*\n%s", appName), false, false),
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf(":bubbles: *Channel name:*\n%s", channel), false, false),
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf(":vs: *Version:*\n%s", version), false, false),
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf(":gear: *Platform:*\n%s", platform), false, false),
		}, nil),
		slack.NewDividerBlock(),
		slack.NewHeaderBlock(&slack.TextBlockObject{
			Type:  slack.PlainTextType,
			Text:  fmt.Sprintf(":link: Artifacts for `%s` architecture:", arch),
			Emoji: true,
		}),
	}

	// Add artifact buttons
	for i, artifact := range artifacts {
		// A hack for forming URLs for notifications for MinIO on localhost, since MinIO is currently used only for development and the main S3 is only used from AWS, so there is no point in digging into it. Uncomment this for local development.
		// Also, if this code is uncommented, Slack notifications will be sent from Go tests.
		// if !strings.HasPrefix(artifact, "http://") && !strings.HasPrefix(artifact, "https://") {
		// 	artifact = "http://" + artifact
		// }
		logrus.Debugf("Adding artifact #%d: %s", i+1, artifact)

		var extension string
		if i < len(extensions) && extensions[i] != "" {
			extension = strings.TrimPrefix(extensions[i], ".")
		} else {
			extension = "no-ext"
		}
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", "*Download:*", false, false),
			nil,
			slack.NewAccessory(slack.NewButtonBlockElement(
				"button-action",
				"click_me_123",
				slack.NewTextBlockObject("plain_text", extension, true, false),
			).WithURL(artifact)),
		))
	}

	// Add changelog section if available
	if len(changelog) > 0 {
		blocks = append(blocks, slack.NewDividerBlock(), slack.NewHeaderBlock(&slack.TextBlockObject{
			Type: slack.PlainTextType,
			Text: ":memo: Changelog:",
		}))

		changelogText := strings.Join(changelog, "\n- ")

		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("```%s```", changelogText), false, false),
			nil,
			nil,
		))
	}

	// Debug output of blocks before sending (make sense for using only on localhost)
	// for i, block := range blocks {
	// 	blockJSON, err := json.MarshalIndent(block, "", "  ")
	// 	if err != nil {
	// 		logrus.Errorf("Error marshaling block #%d: %s", i+1, err)
	// 		continue
	// 	}
	// 	logrus.Infof("Block #%d JSON: %s", i+1, string(blockJSON))
	// }

	_, timestamp, err := api.PostMessage(
		channelID,
		slack.MsgOptionBlocks(blocks...),
	)
	if err != nil {
		logrus.Errorf("Error sending Slack message: %s", err)
		return
	}
	logrus.Debugf("Message successfully sent to channel %s at %s", channelID, timestamp)
}
