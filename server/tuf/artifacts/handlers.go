package artifacts

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"faynoSync/server/model"
	"faynoSync/server/tuf/tasks"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type PublishArtifactsPayload struct {
	AppID   string `json:"app_id" binding:"required"`
	Version string `json:"version" binding:"required"`
}

func PostPublishArtifacts(c *gin.Context, redisClient *redis.Client, mongoDatabase *mongo.Database) {
	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get username from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var payload PublishArtifactsPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		logrus.Errorf("Failed to parse publish artifacts payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid payload format: %v", err),
		})
		return
	}

	ctx := context.Background()

	appID, err := primitive.ObjectIDFromHex(payload.AppID)
	if err != nil {
		logrus.Errorf("Invalid app_id format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid app_id format: %v", err),
		})
		return
	}

	collection := mongoDatabase.Collection("apps")
	var appDoc model.SpecificApp
	filter := bson.D{
		{Key: "app_id", Value: appID},
		{Key: "version", Value: payload.Version},
		{Key: "owner", Value: owner},
	}

	err = collection.FindOne(ctx, filter).Decode(&appDoc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			logrus.Errorf("App version not found: app_id=%s, version=%s, owner=%s", payload.AppID, payload.Version, owner)
			c.JSON(http.StatusNotFound, gin.H{
				"error": fmt.Sprintf("App version not found: app_id=%s, version=%s", payload.AppID, payload.Version),
			})
			return
		}
		logrus.Errorf("Failed to find app document: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to find app document",
		})
		return
	}

	metaCollection := mongoDatabase.Collection("apps_meta")
	var appMeta struct {
		ID      primitive.ObjectID `bson:"_id"`
		AppName string             `bson:"app_name"`
	}
	err = metaCollection.FindOne(ctx, bson.D{
		{Key: "_id", Value: appID},
		{Key: "owner", Value: owner},
	}).Decode(&appMeta)
	if err != nil {
		logrus.Errorf("Failed to find app meta: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to find app metadata",
		})
		return
	}

	// Filter artifacts that don't have tuf_signed: true
	unsignedArtifacts := make([]model.Artifact, 0)
	for _, artifact := range appDoc.Artifacts {
		if !artifact.TufSigned {
			unsignedArtifacts = append(unsignedArtifacts, artifact)
		}
	}

	if len(unsignedArtifacts) == 0 {
		logrus.Debugf("No unsigned artifacts found for app_id=%s, version=%s", payload.AppID, payload.Version)
		c.JSON(http.StatusOK, gin.H{
			"message": "All artifacts are already signed",
			"data": gin.H{
				"app_id":    payload.AppID,
				"version":   payload.Version,
				"artifacts": []string{},
			},
		})
		return
	}

	logrus.Debugf("Found %d unsigned artifacts for app_id=%s, version=%s", len(unsignedArtifacts), payload.AppID, payload.Version)

	env := viper.GetViper()

	tufArtifacts := make([]Artifact, 0, len(unsignedArtifacts))

	successfullyConvertedArtifacts := make([]model.Artifact, 0, len(unsignedArtifacts))

	for _, mongoArtifact := range unsignedArtifacts {

		checkAppVisibility := strings.Contains(mongoArtifact.Link, "/download?key=")
		logrus.Debugf("Determined checkAppVisibility=%v for link: %s", checkAppVisibility, mongoArtifact.Link)

		tufArtifact, err := ConvertMongoArtifactToTUF(mongoArtifact, checkAppVisibility, env)
		if err != nil {
			logrus.Errorf("Failed to convert artifact to TUF format: %v", err)
			// Continue with other artifacts instead of failing completely
			continue
		}
		tufArtifacts = append(tufArtifacts, *tufArtifact)
		successfullyConvertedArtifacts = append(successfullyConvertedArtifacts, mongoArtifact)
	}

	if len(tufArtifacts) == 0 {
		logrus.Errorf("No valid artifacts to publish after conversion")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No valid artifacts to publish",
		})
		return
	}

	taskID := uuid.New().String()
	logrus.Debugf("Generated task_id for publish artifacts: %s", taskID)

	taskName := tasks.TaskNameAddArtifacts
	if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStatePending, &tasks.TaskResult{
		Task: &taskName,
	}); err != nil {
		logrus.Warnf("Failed to save initial task status: %v", err)
	}

	if err := tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateStarted); err != nil {
		logrus.Warnf("Failed to update task state to STARTED: %v", err)
	}

	if err := tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateRunning); err != nil {
		logrus.Warnf("Failed to update task state to RUNNING: %v", err)
	}

	go func() {
		ctx := context.Background()
		if err := AddArtifacts(
			ctx,
			redisClient,
			mongoDatabase,
			owner,
			appMeta.AppName,
			tufArtifacts,
			true,
			taskID,
		); err != nil {
			logrus.Errorf("Failed to add artifacts to TUF: %v", err)
			errorMsg := err.Error()
			taskName := tasks.TaskNameAddArtifacts
			result := &tasks.TaskResult{
				Message: func() *string { s := "Publishing artifact(s) Failed"; return &s }(),
				Error:   &errorMsg,
				Status:  func() *bool { b := false; return &b }(),
				Task:    &taskName,
			}
			now := time.Now()
			result.LastUpdate = &now
			if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, result); err != nil {
				logrus.Errorf("Failed to save error task status: %v", err)
			}
			// Update only successfully converted artifacts with failure status
			updateAllArtifactsTUFStatus(ctx, mongoDatabase, appID, payload.Version, owner, successfullyConvertedArtifacts, false, &taskID)
		} else {
			// Update only successfully converted artifacts with success status
			updateAllArtifactsTUFStatus(ctx, mongoDatabase, appID, payload.Version, owner, successfullyConvertedArtifacts, true, &taskID)
		}
	}()

	artifactPaths := make([]string, len(tufArtifacts))
	for i, artifact := range tufArtifacts {
		artifactPaths[i] = artifact.Path
	}

	response := gin.H{
		"message": "Artifact(s) publishing started",
		"data": gin.H{
			"app_id":      payload.AppID,
			"version":     payload.Version,
			"artifacts":   artifactPaths,
			"task_id":     taskID,
			"last_update": time.Now(),
		},
	}

	c.JSON(http.StatusAccepted, response)
}

// updateAllArtifactsTUFStatus updates the TUF signing status for all artifacts in MongoDB for specific app version
func updateAllArtifactsTUFStatus(
	ctx context.Context,
	mongoDatabase *mongo.Database,
	appID primitive.ObjectID,
	version string,
	owner string,
	artifacts []model.Artifact,
	signed bool,
	taskID *string,
) {
	collection := mongoDatabase.Collection("apps")

	for _, artifact := range artifacts {

		filter := bson.D{
			{Key: "app_id", Value: appID},
			{Key: "version", Value: version},
			{Key: "owner", Value: owner},
			{Key: "artifacts", Value: bson.D{
				{Key: "$elemMatch", Value: bson.D{
					{Key: "link", Value: artifact.Link},
					{Key: "platform", Value: artifact.Platform},
					{Key: "arch", Value: artifact.Arch},
					{Key: "package", Value: artifact.Package},
				}},
			}},
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
			continue
		}

		if result.MatchedCount == 0 {
			logrus.Warnf("No artifact found to update TUF status: app_id=%s, version=%s, link=%s, platform=%s, arch=%s, package=%s",
				appID.Hex(), version, artifact.Link, artifact.Platform.Hex(), artifact.Arch.Hex(), artifact.Package)
		} else if result.ModifiedCount == 0 {
			logrus.Warnf("Artifact found but not modified (may already have same values): app_id=%s, version=%s, link=%s",
				appID.Hex(), version, artifact.Link)
		} else {
			logrus.Debugf("Successfully updated artifact TUF status: signed=%t, task_id=%v, link=%s", signed, taskID, artifact.Link)
		}
	}
}
