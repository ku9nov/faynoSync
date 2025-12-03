package artifacts

import (
	"context"
	"faynoSync/server/tuf/tasks"
	"faynoSync/server/utils"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

func PostAddArtifacts(c *gin.Context, redisClient *redis.Client, mongoDatabase *mongo.Database) {
	adminName, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get admin name from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var payload AddArtifactsPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		logrus.Errorf("Failed to parse artifacts payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid payload format: %v", err),
		})
		return
	}

	if payload.AppName == "" {
		logrus.Error("Missing required field: appName")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required field: appName",
		})
		return
	}

	if len(payload.Artifacts) == 0 {
		logrus.Error("No artifacts provided in payload")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No artifacts provided",
		})
		return
	}

	taskID := uuid.New().String()
	logrus.Debugf("Generated task_id for add artifacts: %s", taskID)

	if payload.AddTaskIDToCustom != nil && *payload.AddTaskIDToCustom {
		for i := range payload.Artifacts {
			if payload.Artifacts[i].Info.Custom == nil {
				payload.Artifacts[i].Info.Custom = make(map[string]interface{})
			}
			payload.Artifacts[i].Info.Custom["added_by_task_id"] = taskID
		}
	}
	publishArtifacts := true
	if payload.PublishArtifacts != nil {
		publishArtifacts = *payload.PublishArtifacts
	}

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
			adminName,
			payload.AppName,
			payload.Artifacts,
			publishArtifacts,
			taskID,
		); err != nil {
			logrus.Errorf("Failed to add artifacts: %v", err)
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

	artifactPaths := make([]string, len(payload.Artifacts))
	for i, artifact := range payload.Artifacts {
		artifactPaths[i] = artifact.Path
	}

	message := "New Artifact(s) successfully submitted."
	if !publishArtifacts {
		message += " Publishing will be skipped."
	}

	response := ArtifactsResponse{
		Data: struct {
			Artifacts  []string  `json:"artifacts"`
			TaskID     string    `json:"task_id"`
			LastUpdate time.Time `json:"last_update"`
		}{
			Artifacts:  artifactPaths,
			TaskID:     taskID,
			LastUpdate: time.Now(),
		},
		Message: message,
	}

	c.JSON(http.StatusAccepted, response)
}
