package metadata

import (
	"context"
	"faynoSync/server/tuf/models"
	"faynoSync/server/tuf/tasks"
	"faynoSync/server/utils"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func PostMetadataSignDelete(c *gin.Context, redisClient *redis.Client) {
	adminName, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get admin name from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	appName := c.Query("appName")
	if appName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "appName query parameter is required",
		})
		return
	}

	if redisClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Redis client is not available",
		})
		return
	}

	var payload models.MetadataSignDeletePayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		logrus.Errorf("Failed to parse metadata sign delete payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid payload format: %v", err),
		})
		return
	}

	ctx := context.Background()
	keySuffix := adminName + "_" + appName
	roleUpper := strings.ToUpper(payload.Role)

	signingKey := fmt.Sprintf("%s_SIGNING_%s", roleUpper, keySuffix)
	signingStatus, err := redisClient.Get(ctx, signingKey).Result()
	if err == redis.Nil || signingStatus == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"message": fmt.Sprintf("No signing process for %s.", payload.Role),
			"error":   fmt.Sprintf("The %s role is not in a signing process.", payload.Role),
		})
		return
	}

	taskID := uuid.New().String()
	taskName := tasks.TaskNameDeleteSignMetadata
	if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStatePending, &tasks.TaskResult{
		Task: &taskName,
	}); err != nil {
		logrus.Warnf("Failed to save initial task status: %v", err)
	}

	go func() {
		ctx := context.Background()
		if err := tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateStarted); err != nil {
			logrus.Warnf("Failed to update task state to STARTED: %v", err)
		}

		if err := tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateRunning); err != nil {
			logrus.Warnf("Failed to update task state to RUNNING: %v", err)
		}

		if err := redisClient.Del(ctx, signingKey).Err(); err != nil {
			logrus.Errorf("Failed to delete signing key from Redis: %v", err)
			errorMsg := err.Error()
			result := &tasks.TaskResult{
				Message: func() *string { s := "Deletion of metadata pending signatures failed"; return &s }(),
				Error:   &errorMsg,
				Status:  func() *bool { b := false; return &b }(),
				Task:    &taskName,
			}
			now := time.Now()
			result.LastUpdate = &now
			if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, result); err != nil {
				logrus.Errorf("Failed to save error task status: %v", err)
			}
			return
		}

		if payload.Role == "root" {
			bootstrapKey := "BOOTSTRAP_" + keySuffix
			bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
			if err == nil && strings.HasPrefix(bootstrapValue, "signing-") {
				if err := redisClient.Del(ctx, bootstrapKey).Err(); err != nil {
					logrus.Warnf("Failed to delete bootstrap key: %v", err)
				}
				message := fmt.Sprintf("Deletion of %s metadata successful, signing process stopped", payload.Role)
				result := &tasks.TaskResult{
					Message: &message,
					Status:  func() *bool { b := true; return &b }(),
					Task:    &taskName,
					Details: map[string]interface{}{
						"bootstrap": "Bootstrap process has been stopped",
					},
				}
				now := time.Now()
				result.LastUpdate = &now
				if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateSuccess, result); err != nil {
					logrus.Errorf("Failed to save success task status: %v", err)
				}
				return
			}
		}

		message := fmt.Sprintf("Deletion of %s metadata successful, signing process stopped", payload.Role)
		result := &tasks.TaskResult{
			Message: &message,
			Status:  func() *bool { b := true; return &b }(),
			Task:    &taskName,
		}
		now := time.Now()
		result.LastUpdate = &now
		if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateSuccess, result); err != nil {
			logrus.Errorf("Failed to save success task status: %v", err)
		}
	}()

	response := models.MetadataSignDeleteResponse{
		Data: models.MetadataSignData{
			TaskID:     taskID,
			LastUpdate: time.Now(),
		},
		Message: "Metadata sign delete accepted.",
	}

	c.JSON(http.StatusAccepted, response)
}
