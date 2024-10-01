package utils

import (
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/spf13/viper"
)

type SlackPayload struct {
	Text string `json:"text"`
}

func SendSlackNotification(message string, env *viper.Viper) {
	token := env.GetString("SLACK_BOT_TOKEN")
	channelID := env.GetString("SLACK_CHANNEL")
	api := slack.New(token)

	channelID, timestamp, err := api.PostMessage(
		channelID,
		slack.MsgOptionText(message, false),
		// slack.MsgOptionAttachments(attachment),
		// slack.MsgOptionAsUser(true),
	)
	if err != nil {
		logrus.Errorf("%s\n", err)
		return
	}
	logrus.Debugf("Message successfully sent to channel %s at %s", channelID, timestamp)
}
