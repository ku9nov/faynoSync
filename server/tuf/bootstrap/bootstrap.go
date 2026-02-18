package bootstrap

import (
	"context"
	"encoding/json"
	"faynoSync/server/tuf/metadata"
	"faynoSync/server/tuf/models"
	tuf_storage "faynoSync/server/tuf/storage"
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

var listMetadataForBootstrap = tuf_storage.ListMetadataFromS3

func hasPersistedRootMetadata(ctx context.Context, adminName, appName string) (bool, error) {
	filenames, err := listMetadataForBootstrap(ctx, adminName, appName, "")
	if err != nil {
		return false, fmt.Errorf("failed to list metadata from storage: %w", err)
	}

	for _, filename := range filenames {
		if filename == "root.json" || strings.HasSuffix(filename, ".root.json") {
			return true, nil
		}
	}

	return false, nil
}

func GetBootstrapStatus(c *gin.Context, redisClient *redis.Client) {

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

	isInitialized, err := hasPersistedRootMetadata(context.Background(), adminName, appName)
	if err != nil {
		logrus.Errorf("Failed to determine bootstrap state from persistent metadata for admin %s, app %s: %v", adminName, appName, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Failed to determine bootstrap state from persistent metadata",
		})
		return
	}

	// Check Redis locks
	var bootstrapLock string
	var bootstrapCompleted bool
	var preLocks []string
	if redisClient != nil {
		ctx := context.Background()

		bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
		bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
		if err == nil && bootstrapValue != "" {
			bootstrapLock = bootstrapValue
			// Only mark as completed if bootstrapValue doesn't start with "pre-"
			if !strings.HasPrefix(bootstrapValue, "pre-") {
				bootstrapCompleted = true
			}
			logrus.Debugf("Found BOOTSTRAP lock for admin %s, app %s: %s", adminName, appName, bootstrapLock)
		} else {
			logrus.Debugf("No BOOTSTRAP lock found in Redis for admin %s, app %s", adminName, appName)
		}

		// Check pre-locks (keys starting with "pre-")
		keys, err := redisClient.Keys(ctx, "pre-*").Result()
		if err == nil {
			preLocks = keys
			logrus.Debugf("Found %d pre-locks in Redis", len(preLocks))
		} else {
			logrus.Debugf("Error searching for pre-locks: %v", err)
		}
	}

	// Determine if bootstrap is completed (either by metadata or Redis lock)
	bootstrapIsCompleted := isInitialized || bootstrapCompleted

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"bootstrap": bootstrapIsCompleted,
			"state":     nil,
			"id":        bootstrapLock,
			"redis_locks": gin.H{
				"bootstrap_lock": bootstrapLock,
				"pre_locks":      preLocks,
			},
		},
		"message": func() string {
			if bootstrapIsCompleted {
				return "Bootstrap already completed for this admin."
			}
			return "System available for bootstrap."
		}(),
	})
}

// Seems like only for testing purposes (?)
func GetBootstrapLocks(c *gin.Context, redisClient *redis.Client) {
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

	ctx := context.Background()
	locks := make(map[string]interface{})

	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
	if err == nil {
		locks["BOOTSTRAP"] = gin.H{
			"key":    bootstrapKey,
			"value":  bootstrapValue,
			"exists": true,
		}
		logrus.Debugf("Found BOOTSTRAP lock for admin %s, app %s: %s", adminName, appName, bootstrapValue)
	} else {
		locks["BOOTSTRAP"] = gin.H{
			"key":    bootstrapKey,
			"value":  nil,
			"exists": false,
		}
		logrus.Debugf("No BOOTSTRAP lock found for admin %s, app %s", adminName, appName)
	}

	preLockKeys, err := redisClient.Keys(ctx, "pre-*").Result()
	if err == nil {
		preLocks := make([]map[string]interface{}, 0)
		for _, key := range preLockKeys {
			value, err := redisClient.Get(ctx, key).Result()
			if err == nil {
				preLocks = append(preLocks, map[string]interface{}{
					"key":    key,
					"value":  value,
					"exists": true,
				})
				logrus.Debugf("Found pre-lock: %s = %s", key, value)
			}
		}
		locks["pre_locks"] = preLocks
		logrus.Debugf("Found %d pre-locks", len(preLocks))
	} else {
		locks["pre_locks"] = []map[string]interface{}{}
		logrus.Debugf("Error searching for pre-locks: %v", err)
	}

	settingsKeys, err := redisClient.Keys(ctx, "bootstrap:settings:*").Result()
	if err == nil {
		settings := make([]map[string]interface{}, 0)
		for _, key := range settingsKeys {
			value, err := redisClient.Get(ctx, key).Result()
			if err == nil {
				settings = append(settings, map[string]interface{}{
					"key":    key,
					"value":  value,
					"exists": true,
				})
				logrus.Debugf("Found bootstrap setting: %s = %s", key, value)
			}
		}
		locks["settings"] = settings
		logrus.Debugf("Found %d bootstrap settings", len(settings))
	} else {
		locks["settings"] = []map[string]interface{}{}
		logrus.Debugf("Error searching for bootstrap settings: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"data":    locks,
		"message": "Bootstrap locks status retrieved successfully",
	})
}

func PostBootstrap(c *gin.Context, redisClient *redis.Client) {
	adminName, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get admin name from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	logrus.Debugf("Starting bootstrap process for admin: %s", adminName)

	// Parse payload first to get appName
	var payload models.BootstrapPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		logrus.Errorf("Failed to parse bootstrap payload: %v", err)
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

	if redisClient == nil {
		logrus.Errorf("Redis client is nil, refusing bootstrap for admin %s, app %s", adminName, payload.AppName)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Redis client is not available",
		})
		return
	}

	if redisClient != nil {
		ctx := context.Background()
		bootstrapKey := "BOOTSTRAP_" + adminName + "_" + payload.AppName
		bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
		logrus.Debugf("Bootstrap key: %s, value: %s", bootstrapKey, bootstrapValue)
		if err == nil && bootstrapValue != "" {
			// Check if temporary keys still exist (bootstrap is in progress)
			preLockKey := bootstrapValue
			settingsKey := "bootstrap:settings:" + bootstrapValue

			preLockExists, err := redisClient.Exists(ctx, preLockKey).Result()
			if err != nil {
				logrus.Warnf("Error checking pre-lock key existence: %v", err)
			}

			settingsExists, err := redisClient.Exists(ctx, settingsKey).Result()
			if err != nil {
				logrus.Warnf("Error checking settings key existence: %v", err)
			}

			if preLockExists > 0 || settingsExists > 0 {
				logrus.Warnf("Bootstrap already in progress for admin %s, app %s. Task ID: %s", adminName, payload.AppName, bootstrapValue)
				c.JSON(http.StatusConflict, gin.H{
					"error": "Bootstrap already in progress for this admin and app",
					"data": gin.H{
						"task_id": bootstrapValue,
						"admin":   adminName,
						"app":     payload.AppName,
						"status":  "in_progress",
					},
				})
				return
			}

			if preLockExists == 0 && settingsExists == 0 {

				if strings.HasPrefix(bootstrapValue, "pre-") {
					taskIDFromValue := bootstrapValue[4:]
					taskState := getTaskStatusFromRedis(redisClient, taskIDFromValue)

					// If task is in FAILURE, ERRORED, REVOKED state, or not found (PENDING but locks are gone),
					// clean up the stale lock and allow new bootstrap
					switch taskState {
					case tasks.TaskStateFailure, tasks.TaskStateErrored, tasks.TaskStateRevoked, tasks.TaskStatePending:
						logrus.Warnf("Found stale bootstrap lock from task %s (state: %s), cleaning up", taskIDFromValue, taskState)
						releaseBootstrapLock(redisClient, taskIDFromValue, adminName, payload.AppName)
						// Continue with bootstrap after cleanup
					case tasks.TaskStateSuccess:
						// Task succeeded but locks are missing - this shouldn't happen, but treat as completed
						logrus.Warnf("Bootstrap task %s succeeded but locks are missing, treating as completed", taskIDFromValue)
						c.JSON(http.StatusConflict, gin.H{
							"error": "Bootstrap already completed for this admin and app",
							"data": gin.H{
								"task_id": bootstrapValue,
								"admin":   adminName,
								"app":     payload.AppName,
								"status":  "completed",
							},
						})
						return
					default:
						// Task is in progress (STARTED, RUNNING, etc.) but locks are missing - treat as in progress
						logrus.Warnf("Bootstrap task %s is in state %s but locks are missing, treating as in progress", taskIDFromValue, taskState)
						c.JSON(http.StatusConflict, gin.H{
							"error": "Bootstrap already in progress for this admin and app",
							"data": gin.H{
								"task_id": taskIDFromValue,
								"admin":   adminName,
								"app":     payload.AppName,
								"status":  "in_progress",
							},
						})
						return
					}
				} else {
					// bootstrapValue is a taskID (not pre-taskID), meaning bootstrap was completed
					logrus.Warnf("Bootstrap already completed for admin %s, app %s. Task ID: %s", adminName, payload.AppName, bootstrapValue)
					c.JSON(http.StatusConflict, gin.H{
						"error": "Bootstrap already completed for this admin and app",
						"data": gin.H{
							"task_id": bootstrapValue,
							"admin":   adminName,
							"app":     payload.AppName,
							"status":  "completed",
						},
					})
					return
				}
			}
		}

		preLockKeys, err := redisClient.Keys(ctx, "pre-*").Result()
		if err == nil {
			for _, preKey := range preLockKeys {

				taskIDFromPre := preKey[4:] // Remove "pre-" prefix

				settingsKey := "bootstrap:settings:" + taskIDFromPre
				settingsExists, err := redisClient.Exists(ctx, settingsKey).Result()
				if err == nil && settingsExists > 0 {

					bootstrapKey := "BOOTSTRAP_" + adminName + "_" + payload.AppName
					bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
					if err == nil && bootstrapValue == taskIDFromPre {
						logrus.Warnf("Bootstrap already in progress for admin %s, app %s. Task ID: %s (found via pre-lock)", adminName, payload.AppName, taskIDFromPre)
						c.JSON(http.StatusConflict, gin.H{
							"error": "Bootstrap already in progress for this admin and app",
							"data": gin.H{
								"task_id": taskIDFromPre,
								"admin":   adminName,
								"app":     payload.AppName,
								"status":  "in_progress",
							},
						})
						return
					}
				}
			}
		}
		logrus.Debugf("No existing bootstrap lock or in-progress bootstrap found for admin %s, app %s", adminName, payload.AppName)
	}

	logrus.Debug("Checking bootstrap state using persistent metadata")
	isInitialized, err := hasPersistedRootMetadata(context.Background(), adminName, payload.AppName)
	if err != nil {
		logrus.Errorf("Failed to determine bootstrap state from persistent metadata for admin %s, app %s: %v", adminName, payload.AppName, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Failed to determine bootstrap state from persistent metadata",
		})
		return
	}
	if isInitialized {
		logrus.Warnf("Persistent root metadata already exists for admin %s, app %s. Bootstrap already completed", adminName, payload.AppName)
		c.JSON(http.StatusConflict, gin.H{
			"error": "System already has root metadata. Bootstrap already completed.",
		})
		return
	}
	logrus.Debug("Bootstrap state check passed - system is available for bootstrap")

	// Validate required fields
	if payload.Settings.Roles.Root.Expiration == 0 {
		logrus.Error("Missing required field: settings.roles.root.expiration")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required field: settings.roles.root.expiration",
		})
		return
	}

	if len(payload.Metadata) == 0 {
		logrus.Error("Missing required field: metadata")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required field: metadata",
		})
		return
	}

	// Check if root metadata exists in payload
	if _, exists := payload.Metadata["root"]; !exists {
		logrus.Error("Missing required field: metadata.root")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required field: metadata.root",
		})
		return
	}

	// Set default timeout if not provided
	timeout := 300
	if payload.Timeout != nil {
		timeout = *payload.Timeout
	}
	logrus.Debugf("Bootstrap timeout set to: %d seconds", timeout)

	taskID := uuid.New().String()
	logrus.Debugf("Generated task_id: %s", taskID)

	logrus.Debug("Calling pre_lock_bootstrap")
	lockAcquired, existingBootstrapValue := preLockBootstrap(redisClient, taskID, adminName, payload.AppName)
	if !lockAcquired {
		status := "in_progress"
		errMsg := "Bootstrap already in progress for this admin and app"
		taskIDForResponse := existingBootstrapValue
		if existingBootstrapValue != "" && !strings.HasPrefix(existingBootstrapValue, "pre-") {
			status = "completed"
			errMsg = "Bootstrap already completed for this admin and app"
		}

		logrus.Warnf("Bootstrap lock acquisition failed for admin %s, app %s. Existing value: %s", adminName, payload.AppName, existingBootstrapValue)
		c.JSON(http.StatusConflict, gin.H{
			"error": errMsg,
			"data": gin.H{
				"task_id": taskIDForResponse,
				"admin":   adminName,
				"app":     payload.AppName,
				"status":  status,
			},
		})
		return
	}

	taskName := tasks.TaskNameBootstrap
	tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStatePending, &tasks.TaskResult{
		Task: &taskName,
	})

	logrus.Debugf("Starting bootstrap function in background for app: %s", payload.AppName)
	go func() {
		bootstrap(redisClient, taskID, adminName, payload.AppName, &payload)
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"data": gin.H{
			"task_id":     taskID,
			"last_update": time.Now().Format(time.RFC3339),
		},
		"message": "Bootstrap accepted and started in background",
	})
}

func preLockBootstrap(
	redisClient *redis.Client,
	taskID string,
	adminName string,
	appName string,
) (bool, string) {
	logrus.Debugf("Setting pre-lock and BOOTSTRAP lock in Redis for admin: %s, app: %s, task_id: %s", adminName, appName, taskID)
	if redisClient == nil {
		logrus.Errorf("Redis client is nil, failed to acquire pre-lock and BOOTSTRAP lock for admin: %s, app: %s", adminName, appName)
		return false, ""
	}

	ctx := context.Background()
	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	bootstrapValue := "pre-" + taskID

	wasSet, err := redisClient.SetNX(ctx, bootstrapKey, bootstrapValue, 0).Result()
	if err != nil {
		logrus.Errorf("Failed to atomically acquire BOOTSTRAP lock in Redis for admin %s, app %s: %v", adminName, appName, err)
		return false, ""
	}
	if !wasSet {
		existingBootstrapValue, getErr := redisClient.Get(ctx, bootstrapKey).Result()
		if getErr != nil && getErr != redis.Nil {
			logrus.Warnf("Failed to read existing BOOTSTRAP lock in Redis for admin %s, app %s: %v", adminName, appName, getErr)
		}
		return false, existingBootstrapValue
	}

	preLockKey := "pre-" + taskID
	err = redisClient.Set(ctx, preLockKey, taskID, 0).Err()
	if err != nil {
		logrus.Errorf("Failed to set pre-lock in Redis: %v", err)
		if delErr := redisClient.Del(ctx, bootstrapKey).Err(); delErr != nil {
			logrus.Warnf("Failed to rollback BOOTSTRAP lock %s after pre-lock set failure: %v", bootstrapKey, delErr)
		}
		return false, ""
	}

	logrus.Debugf("Successfully set pre-lock in Redis: %s", preLockKey)
	logrus.Debugf("Successfully acquired BOOTSTRAP lock in Redis for admin %s, app %s: %s (key: %s)", adminName, appName, bootstrapValue, bootstrapKey)

	return true, ""
}

func bootstrap(
	redisClient *redis.Client,
	taskID string,
	adminName string,
	appName string,
	payload *models.BootstrapPayload,
) {
	logrus.Debugf("Starting bootstrap function for admin: %s, app: %s, task_id: %s", adminName, appName, taskID)

	// Update task state to STARTED
	tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateStarted)

	// Update task state to RUNNING
	tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateRunning)

	logrus.Debug("Saving bootstrap settings")
	saveSettings(redisClient, adminName, appName, payload)

	logrus.Debug("Finalizing bootstrap")
	success := bootstrapFinalize(redisClient, taskID, adminName, appName, payload)

	if success {
		// Update task state to SUCCESS
		taskName := tasks.TaskNameBootstrap
		successStatus := true
		message := "Bootstrap completed successfully"
		tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateSuccess, &tasks.TaskResult{
			Task:    &taskName,
			Status:  &successStatus,
			Message: &message,
		})
		logrus.Debugf("Bootstrap function completed successfully for admin: %s, task_id: %s", adminName, taskID)
	} else {
		// Update task state to FAILURE
		taskName := tasks.TaskNameBootstrap
		successStatus := false
		errorMsg := "Bootstrap failed"
		tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, &tasks.TaskResult{
			Task:   &taskName,
			Status: &successStatus,
			Error:  &errorMsg,
		})
		logrus.Errorf("Bootstrap function failed for admin: %s, task_id: %s", adminName, taskID)

		// Clean up bootstrap locks on failure (similar to Python API's release_bootstrap_lock)
		logrus.Debugf("Cleaning up bootstrap locks after failure for admin: %s, task_id: %s", adminName, taskID)
		releaseBootstrapLock(redisClient, taskID, adminName, appName)
	}
}

func bootstrapFinalize(
	redisClient *redis.Client,
	taskID string,
	adminName string,
	appName string,
	payload *models.BootstrapPayload,
) bool {
	logrus.Debugf("Starting bootstrap finalization for admin: %s, app: %s", adminName, appName)

	logrus.Debug("Calling bootstrap_online_roles")
	if err := metadata.BootstrapOnlineRoles(redisClient, taskID, adminName, appName, payload); err != nil {
		logrus.Errorf("Bootstrap online roles failed: %v", err)
		return false
	}

	logrus.Debug("Cleaning up temporary bootstrap keys and finalizing state")
	if redisClient != nil {
		ctx := context.Background()

		preLockKey := "pre-" + taskID
		err := redisClient.Del(ctx, preLockKey).Err()
		if err != nil {
			logrus.Warnf("Failed to delete pre-lock key %s: %v", preLockKey, err)
		} else {
			logrus.Debugf("Successfully deleted pre-lock key: %s", preLockKey)
		}

		rootSigningKey := "ROOT_SIGNING_" + adminName + "_" + appName
		if err := redisClient.Set(ctx, rootSigningKey, "", 0).Err(); err != nil {
			logrus.Warnf("Failed to clear ROOT_SIGNING for admin %s, app %s: %v", adminName, appName, err)
		} else {
			logrus.Debugf("Successfully cleared ROOT_SIGNING for admin %s, app %s", adminName, appName)
		}

		bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
		if err := redisClient.Set(ctx, bootstrapKey, taskID, 0).Err(); err != nil {
			logrus.Errorf("Failed to set final BOOTSTRAP state for admin %s, app %s: %v", adminName, appName, err)
			return false
		} else {
			logrus.Debugf("Successfully set final BOOTSTRAP state for admin %s, app %s: %s", adminName, appName, taskID)
		}
	} else {
		logrus.Warn("Redis client is nil, skipping cleanup")
	}

	logrus.Debug("Bootstrap finalization completed")
	return true
}

func releaseBootstrapLock(
	redisClient *redis.Client,
	taskID string,
	adminName string,
	appName string,
) {
	if redisClient == nil {
		logrus.Warn("Redis client is nil, skipping bootstrap lock cleanup")
		return
	}

	ctx := context.Background()

	preLockKey := "pre-" + taskID
	err := redisClient.Del(ctx, preLockKey).Err()
	if err != nil {
		logrus.Warnf("Failed to delete pre-lock key %s: %v", preLockKey, err)
	} else {
		logrus.Debugf("Successfully deleted pre-lock key: %s", preLockKey)
	}

	settingsKeyWithPre := "bootstrap:settings:pre-" + taskID
	settingsKeyWithoutPre := "bootstrap:settings:" + taskID

	err = redisClient.Del(ctx, settingsKeyWithPre).Err()
	if err != nil {
		logrus.Debugf("Settings key %s not found or already deleted", settingsKeyWithPre)
	} else {
		logrus.Debugf("Successfully deleted settings key: %s", settingsKeyWithPre)
	}

	err = redisClient.Del(ctx, settingsKeyWithoutPre).Err()
	if err != nil {
		logrus.Debugf("Settings key %s not found or already deleted", settingsKeyWithoutPre)
	} else {
		logrus.Debugf("Successfully deleted settings key: %s", settingsKeyWithoutPre)
	}

	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	err = redisClient.Del(ctx, bootstrapKey).Err()
	if err != nil {
		logrus.Warnf("Failed to delete BOOTSTRAP key %s: %v", bootstrapKey, err)
	} else {
		logrus.Debugf("Successfully deleted BOOTSTRAP key: %s", bootstrapKey)
	}

	logrus.Debugf("Bootstrap lock cleanup completed for admin: %s, app: %s, task_id: %s", adminName, appName, taskID)
}

func getTaskStatusFromRedis(
	redisClient *redis.Client,
	taskID string,
) tasks.TaskState {
	if redisClient == nil {
		return tasks.TaskStatePending
	}

	ctx := context.Background()
	taskKey := "task:" + taskID

	taskData, err := redisClient.Get(ctx, taskKey).Result()
	if err == redis.Nil {

		return tasks.TaskStatePending
	} else if err != nil {
		logrus.Warnf("Failed to get task status from Redis for task_id %s: %v", taskID, err)
		return tasks.TaskStatePending
	}

	var taskStatus tasks.TaskStatus
	if err := json.Unmarshal([]byte(taskData), &taskStatus); err != nil {
		logrus.Warnf("Failed to unmarshal task status for task_id %s: %v", taskID, err)
		return tasks.TaskStatePending
	}

	return taskStatus.State
}
