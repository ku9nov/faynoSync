package artifacts

import (
	"context"
	"time"

	"faynoSync/server/model"
	"faynoSync/server/tuf/tasks"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
)

func PublishTUFArtifacts(
	mongoArtifact model.Artifact,
	checkAppVisibility bool,
	env *viper.Viper,
	redisClient *redis.Client,
	mongoDatabase *mongo.Database,
	owner string,
	appName string,
	publish bool,
) {
	if !publish || redisClient == nil || mongoDatabase == nil || owner == "" {
		return
	}

	logrus.Debugf("Starting adding artifacts to TUF")

	tufArtifact, err := ConvertMongoArtifactToTUF(mongoArtifact, checkAppVisibility, env)

	if err != nil {
		logrus.Errorf("Failed to convert artifact to TUF format: %v", err)
		return
	}

	go func() {
		taskID := uuid.New().String()
		ctx := context.Background()
		logrus.Debugf("Adding artifacts to TUF: %v", tufArtifact)
		if err := AddArtifacts(ctx, redisClient, mongoDatabase, owner, appName, []Artifact{*tufArtifact}, publish, taskID); err != nil {
			logrus.Errorf("Failed to add artifacts to TUF: %v", err)
			errorMsg := err.Error()
			taskName := tasks.TaskNameAddArtifacts
			result := &tasks.TaskResult{
				Message: func() *string { s := "Adding artifact(s) Failed"; return &s }(),
				Error:   &errorMsg,
				Status:  func() *bool { b := false; return &b }(),
				Task:    &taskName,
			}
			now := time.Now()
			result.LastUpdate = &now
			if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, result); err != nil {
				logrus.Errorf("Failed to save error task status: %v", err)
			}
		}
	}()
}
