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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	appID primitive.ObjectID,
	version string,
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
			// Update artifact in MongoDB with failure status
			updateArtifactTUFStatus(ctx, mongoDatabase, appID, version, owner, mongoArtifact, false, &taskID)
		} else {
			// Update artifact in MongoDB with success status
			updateArtifactTUFStatus(ctx, mongoDatabase, appID, version, owner, mongoArtifact, true, &taskID)
		}
	}()
}

// updateArtifactTUFStatus updates the TUF signing status of an artifact in MongoDB
func updateArtifactTUFStatus(
	ctx context.Context,
	mongoDatabase *mongo.Database,
	appID primitive.ObjectID,
	version string,
	owner string,
	artifact model.Artifact,
	signed bool,
	taskID *string,
) {
	collection := mongoDatabase.Collection("apps")
	filter := bson.D{
		{Key: "app_id", Value: appID},
		{Key: "version", Value: version},
		{Key: "owner", Value: owner},
		{Key: "artifacts.link", Value: artifact.Link},
		{Key: "artifacts.platform", Value: artifact.Platform},
		{Key: "artifacts.arch", Value: artifact.Arch},
		{Key: "artifacts.package", Value: artifact.Package},
	}

	update := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "artifacts.$.tuf_signed", Value: signed},
			{Key: "artifacts.$.tuf_task_id", Value: taskID},
			{Key: "updated_at", Value: time.Now()},
		}},
	}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		logrus.Errorf("Failed to update artifact TUF status in MongoDB: %v", err)
		return
	}

	if result.MatchedCount == 0 {
		logrus.Warnf("No artifact found to update TUF status: app_id=%s, version=%s, link=%s", appID.Hex(), version, artifact.Link)
		return
	}

	logrus.Debugf("Successfully updated artifact TUF status: signed=%t, task_id=%v", signed, taskID)
}
