package config

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"faynoSync/server/tuf/models"
	"faynoSync/server/tuf/tasks"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func GetConfig(c *gin.Context, redisClient *redis.Client) {
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

	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	ctx := context.Background()
	bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
	if err == redis.Nil || bootstrapValue == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "No Repository Settings/Config found.",
			"error":   fmt.Sprintf("It requires bootstrap. State: %s", bootstrapValue),
		})
		return
	}

	keySuffix := adminName + "_" + appName

	// List of all possible settings keys
	settingsKeys := []string{
		"BOOTSTRAP",
		"ROOT_EXPIRATION",
		"ROOT_THRESHOLD",
		"ROOT_NUM_KEYS",
		"TARGETS_EXPIRATION",
		"TARGETS_THRESHOLD",
		"TARGETS_NUM_KEYS",
		"TARGETS_ONLINE_KEY",
		"SNAPSHOT_EXPIRATION",
		"SNAPSHOT_THRESHOLD",
		"SNAPSHOT_NUM_KEYS",
		"TIMESTAMP_EXPIRATION",
		"TIMESTAMP_THRESHOLD",
		"TIMESTAMP_NUM_KEYS",
		// "BINS_EXPIRATION",
		// "BINS_THRESHOLD",
		// "BINS_NUM_KEYS",
		"NUMBER_OF_DELEGATED_BINS",
	}

	settings := make(map[string]interface{})

	if bootstrapValue != "" {
		settings["bootstrap"] = bootstrapValue
	}

	for _, key := range settingsKeys {
		if key == "BOOTSTRAP" {
			continue
		}

		fullKey := key + "_" + keySuffix
		value, err := redisClient.Get(ctx, fullKey).Result()
		if err == nil && value != "" {

			lowerKey := strings.ToLower(key)

			if intVal, err := strconv.Atoi(value); err == nil {
				settings[lowerKey] = intVal
			} else if value == "true" || value == "false" {

				settings[lowerKey] = value == "true"
			} else {

				settings[lowerKey] = value
			}
		}
	}

	expirationPattern := "*_EXPIRATION_" + keySuffix
	var cursor uint64 = 0
	for {
		var keys []string
		var err error
		keys, cursor, err = redisClient.Scan(ctx, cursor, expirationPattern, 100).Result()
		if err != nil {
			logrus.Warnf("Error scanning Redis for custom roles: %v", err)
			break
		}

		for _, fullKey := range keys {

			alreadyProcessed := false
			for _, standardKey := range settingsKeys {
				if standardKey != "BOOTSTRAP" && fullKey == standardKey+"_"+keySuffix {
					alreadyProcessed = true
					break
				}
			}
			if alreadyProcessed {
				continue
			}

			keyWithoutSuffix := strings.TrimSuffix(fullKey, "_EXPIRATION_"+keySuffix)
			if keyWithoutSuffix == fullKey {
				continue
			}

			value, err := redisClient.Get(ctx, fullKey).Result()
			if err == nil && value != "" {
				if intVal, err := strconv.Atoi(value); err == nil {
					settings["role_expiration"] = intVal
					break
				}
			}
		}

		if _, found := settings["role_expiration"]; found {
			break
		}

		if cursor == 0 {
			break
		}
	}

	c.JSON(http.StatusOK, models.GetConfigResponse{
		Data:    settings,
		Message: "Current Settings",
	})
}

func PutConfig(c *gin.Context, redisClient *redis.Client) {
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

	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	ctx := context.Background()
	bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
	if err == redis.Nil || bootstrapValue == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "No Repository Settings/Config found.",
			"error":   fmt.Sprintf("It requires bootstrap. State: %s", bootstrapValue),
		})
		return
	}

	var payload models.PutConfigPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		logrus.Errorf("Failed to parse config payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid payload format: %v", err),
		})
		return
	}

	if len(payload.Settings.Expiration) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No role provided for expiration policy change",
		})
		return
	}

	keySuffix := adminName + "_" + appName

	validOnlineRoles := map[string]bool{
		"targets":   true,
		"snapshot":  true,
		"timestamp": true,
		// "bins":      true,
	}

	updatedRoles := []string{}
	invalidRoles := []string{}

	for role, expiration := range payload.Settings.Expiration {
		roleLower := strings.ToLower(role)

		if !validOnlineRoles[roleLower] {
			invalidRoles = append(invalidRoles, role)
			continue
		}

		expirationKey := strings.ToUpper(role) + "_EXPIRATION_" + keySuffix
		existingValue, err := redisClient.Get(ctx, expirationKey).Result()
		if err == redis.Nil || existingValue == "" {
			invalidRoles = append(invalidRoles, role)
			continue
		}

		if err := redisClient.Set(ctx, expirationKey, expiration, 0).Err(); err != nil {
			logrus.Errorf("Failed to update %s expiration: %v", expirationKey, err)
			invalidRoles = append(invalidRoles, role)
			continue
		}

		updatedRoles = append(updatedRoles, role)
		logrus.Infof("Updated %s expiration to %d days", role, expiration)
	}

	taskID := uuid.New().String()
	taskName := tasks.TaskNameUpdateSettings

	details := map[string]interface{}{
		"updated_roles": updatedRoles,
		"invalid_roles": invalidRoles,
	}

	message := "Update Settings Succeeded"
	if len(updatedRoles) == 0 {
		message = "Update Settings Failed"
	}

	result := &tasks.TaskResult{
		Message: &message,
		Task:    &taskName,
		Details: details,
	}

	if len(updatedRoles) == 0 && len(invalidRoles) > 0 {
		errorMsg := "No valid roles were updated"
		result.Error = &errorMsg
		status := false
		result.Status = &status
	} else if len(invalidRoles) > 0 {
		status := true
		result.Status = &status
	} else {
		status := true
		result.Status = &status
	}

	if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateSuccess, result); err != nil {
		logrus.Warnf("Failed to save task status: %v", err)
	}

	response := models.PutConfigResponse{
		Data: models.PutConfigData{
			TaskID:     taskID,
			LastUpdate: time.Now(),
		},
		Message: "Settings successfully submitted.",
	}

	c.JSON(http.StatusAccepted, response)
}
