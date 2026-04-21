package bootstrap

import (
	"context"
	"encoding/json"
	tuf_metadata "faynoSync/server/tuf/metadata"
	"faynoSync/server/tuf/models"
	tuf_storage "faynoSync/server/tuf/storage"
	"faynoSync/server/tuf/tasks"
	"faynoSync/server/utils"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	gotufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

var (
	listMetadataForBootstrap        = tuf_storage.ListMetadataFromS3
	findLatestMetadataBootstrap     = tuf_storage.FindLatestMetadataVersion
	downloadMetadataForBootstrap    = tuf_storage.DownloadMetadataFromS3
	getAllDelegatedRolesForRecovery = tuf_storage.GetAllDelegatedRoles
	recoverSettingsFromStorageFn    = recoverSettingsFromStorage
)

func scanKeys(ctx context.Context, redisClient *redis.Client, pattern string) ([]string, error) {
	if redisClient == nil {
		return nil, fmt.Errorf("redis client is nil")
	}

	const scanCount int64 = 100
	var (
		cursor uint64
		keys   []string
	)
	for {
		batch, nextCursor, err := redisClient.Scan(ctx, cursor, pattern, scanCount).Result()
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return keys, nil
}

func abortBootstrapIfContextDone(
	ctx context.Context,
	redisClient *redis.Client,
	taskID string,
	adminName string,
	appName string,
	stage string,
) bool {
	if err := ctx.Err(); err != nil {
		taskName := tasks.TaskNameBootstrap
		successStatus := false
		errorMsg := fmt.Sprintf("Bootstrap aborted: %v", err)
		tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, &tasks.TaskResult{
			Task:   &taskName,
			Status: &successStatus,
			Error:  &errorMsg,
		})
		logrus.Errorf("Bootstrap aborted %s for admin: %s, task_id: %s, err: %v", stage, adminName, taskID, err)
		releaseBootstrapLock(redisClient, taskID, adminName, appName)
		return true
	}
	return false
}

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
		keys, err := scanKeys(ctx, redisClient, "pre-*")
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

	preLockKeys, err := scanKeys(ctx, redisClient, "pre-*")
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

	settingsKeys, err := scanKeys(ctx, redisClient, "bootstrap:settings:*")
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

		preLockKeys, err := scanKeys(ctx, redisClient, "pre-*")
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
	if payload.Timeout != nil && *payload.Timeout > 0 {
		timeout = *payload.Timeout
	} else if payload.Timeout != nil {
		logrus.Warnf("Invalid bootstrap timeout %d seconds for admin %s, app %s. Falling back to default %d seconds", *payload.Timeout, adminName, payload.AppName, timeout)
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
		bootstrapCtx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()
		bootstrapWithContext(bootstrapCtx, redisClient, taskID, adminName, payload.AppName, &payload)
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
	bootstrapWithContext(context.Background(), redisClient, taskID, adminName, appName, payload)
}

func bootstrapWithContext(
	ctx context.Context,
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

	if abortBootstrapIfContextDone(ctx, redisClient, taskID, adminName, appName, "before settings save") {
		return
	}

	logrus.Debug("Saving bootstrap settings")
	saveSettings(redisClient, adminName, appName, payload)

	if abortBootstrapIfContextDone(ctx, redisClient, taskID, adminName, appName, "after settings save") {
		return
	}

	logrus.Debug("Finalizing bootstrap")
	success := bootstrapFinalizeWithContext(ctx, redisClient, taskID, adminName, appName, payload)

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
	return bootstrapFinalizeWithContext(context.Background(), redisClient, taskID, adminName, appName, payload)
}

func bootstrapFinalizeWithContext(
	ctx context.Context,
	redisClient *redis.Client,
	taskID string,
	adminName string,
	appName string,
	payload *models.BootstrapPayload,
) bool {
	if err := ctx.Err(); err != nil {
		logrus.Errorf("Bootstrap finalize aborted for admin: %s, app: %s, err: %v", adminName, appName, err)
		return false
	}

	logrus.Debugf("Starting bootstrap finalization for admin: %s, app: %s", adminName, appName)

	logrus.Debug("Calling bootstrap_online_roles")
	if err := tuf_metadata.BootstrapOnlineRolesWithContext(ctx, redisClient, taskID, adminName, appName, payload); err != nil {
		logrus.Errorf("Bootstrap online roles failed: %v", err)
		return false
	}

	logrus.Debug("Cleaning up temporary bootstrap keys and finalizing state")
	if redisClient != nil {
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

type bootstrapRecoveryPayload struct {
	AppName string `json:"appName" binding:"required"`
	Timeout *int   `json:"timeout,omitempty"`
}

type minimalTargetsMetadata struct {
	Signed struct {
		Expires     string `json:"expires"`
		Delegations struct {
			Roles []struct {
				Name string `json:"name"`
			} `json:"roles"`
		} `json:"delegations"`
	} `json:"signed"`
}

func PostBootstrapRecovery(c *gin.Context, redisClient *redis.Client) {
	adminName, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get admin name from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if redisClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Redis client is not available",
		})
		return
	}

	var payload bootstrapRecoveryPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid payload format: %v", err),
		})
		return
	}
	if payload.AppName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required field: appName",
		})
		return
	}

	timeoutSeconds := resolveBootstrapRecoveryTimeoutSeconds(payload.Timeout, adminName, payload.AppName)
	timeout := time.Duration(timeoutSeconds) * time.Second
	lockTTL := calculateBootstrapRecoveryLockTTL(timeout)

	isInitialized, err := hasPersistedRootMetadata(context.Background(), adminName, payload.AppName)
	if err != nil {
		logrus.Errorf("Failed to determine bootstrap state from persistent metadata for admin %s, app %s: %v", adminName, payload.AppName, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Failed to determine bootstrap state from persistent metadata",
		})
		return
	}
	if !isInitialized {
		c.JSON(http.StatusConflict, gin.H{
			"error": "No persisted root metadata found. Bootstrap must be completed before recovery.",
		})
		return
	}

	taskID := uuid.New().String()
	lockKey := "RECOVERY_LOCK_" + adminName + "_" + payload.AppName
	lockAcquired, err := redisClient.SetNX(context.Background(), lockKey, taskID, lockTTL).Result()
	if err != nil {
		logrus.Errorf("Failed to acquire bootstrap recovery lock: admin=%s app=%s err=%v", adminName, payload.AppName, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to acquire recovery lock",
		})
		return
	}
	if !lockAcquired {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Recovery already in progress for this admin and app",
		})
		return
	}

	required, reason, err := isRecoveryRequired(context.Background(), redisClient, adminName, payload.AppName)
	if err != nil {
		releaseRecoveryLock(context.Background(), redisClient, lockKey, taskID)
		logrus.Errorf("Failed to evaluate recovery precheck: admin=%s app=%s err=%v", adminName, payload.AppName, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Failed to evaluate recovery precheck",
		})
		return
	}
	if !required {
		releaseRecoveryLock(context.Background(), redisClient, lockKey, taskID)
		c.JSON(http.StatusConflict, gin.H{
			"error": reason,
		})
		return
	}

	taskName := tasks.TaskNameBootstrapRecovery
	_ = tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStatePending, &tasks.TaskResult{
		Task: &taskName,
	})
	go func() {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		runBootstrapRecovery(recoveryCtx, redisClient, taskID, adminName, payload.AppName, lockKey, lockTTL)
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"data": gin.H{
			"task_id":     taskID,
			"last_update": time.Now().Format(time.RFC3339),
		},
		"message": "Bootstrap recovery accepted and started in background",
	})
}

func runBootstrapRecovery(ctx context.Context, redisClient *redis.Client, taskID, adminName, appName, lockKey string, lockTTL time.Duration) {
	logrus.Infof("Starting bootstrap recovery: admin=%s app=%s task_id=%s", adminName, appName, taskID)
	defer releaseRecoveryLock(ctx, redisClient, lockKey, taskID)
	if err := redisClient.Expire(ctx, lockKey, lockTTL).Err(); err != nil {
		logrus.Warnf("Failed to extend bootstrap recovery lock TTL: admin=%s app=%s task_id=%s ttl=%s err=%v", adminName, appName, taskID, lockTTL, err)
	}
	_ = tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateStarted)
	_ = tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateRunning)
	recovered, err := recoverSettingsFromStorageFn(ctx, adminName, appName)
	if err != nil {
		logrus.Errorf("Bootstrap recovery failed during metadata reconstruction: admin=%s app=%s task_id=%s err=%v", adminName, appName, taskID, err)
		taskName := tasks.TaskNameBootstrapRecovery
		success := false
		errMsg := fmt.Sprintf("Bootstrap recovery failed: %v", err)
		_ = tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, &tasks.TaskResult{
			Task:   &taskName,
			Status: &success,
			Error:  &errMsg,
		})
		return
	}

	if err := saveRecoveredSettings(redisClient, adminName, appName, recovered); err != nil {
		logrus.Errorf("Bootstrap recovery failed during Redis write: admin=%s app=%s task_id=%s err=%v", adminName, appName, taskID, err)
		taskName := tasks.TaskNameBootstrapRecovery
		success := false
		errMsg := fmt.Sprintf("Bootstrap recovery failed to save Redis keys: %v", err)
		_ = tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, &tasks.TaskResult{
			Task:   &taskName,
			Status: &success,
			Error:  &errMsg,
		})
		return
	}

	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	if err := redisClient.Set(ctx, bootstrapKey, taskID, 0).Err(); err != nil {
		logrus.Errorf("Bootstrap recovery failed while setting BOOTSTRAP key: admin=%s app=%s task_id=%s key=%s err=%v", adminName, appName, taskID, bootstrapKey, err)
		taskName := tasks.TaskNameBootstrapRecovery
		success := false
		errMsg := fmt.Sprintf("Bootstrap recovery failed to set BOOTSTRAP key: %v", err)
		_ = tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, &tasks.TaskResult{
			Task:   &taskName,
			Status: &success,
			Error:  &errMsg,
		})
		return
	}

	taskName := tasks.TaskNameBootstrapRecovery
	success := true
	msg := "Bootstrap recovery completed successfully"
	_ = tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateSuccess, &tasks.TaskResult{
		Task:    &taskName,
		Status:  &success,
		Message: &msg,
	})
	logrus.Infof(
		"Bootstrap recovery completed: admin=%s app=%s task_id=%s delegated_roles=%d root_exp=%d targets_exp=%d snapshot_exp=%d timestamp_exp=%d",
		adminName,
		appName,
		taskID,
		len(recovered.DelegatedExpiration),
		recovered.RootExpiration,
		recovered.TargetsExpiration,
		recovered.SnapshotExpiration,
		recovered.TimestampExpiration,
	)
}

func releaseRecoveryLock(ctx context.Context, redisClient *redis.Client, lockKey, taskID string) {
	if redisClient == nil {
		return
	}

	current, err := redisClient.Get(ctx, lockKey).Result()
	if err == redis.Nil {
		return
	}
	if err != nil {
		logrus.Warnf("Failed to read recovery lock %s: %v", lockKey, err)
		return
	}

	if current != taskID {
		return
	}

	if err := redisClient.Del(ctx, lockKey).Err(); err != nil {
		logrus.Warnf("Failed to release recovery lock %s: %v", lockKey, err)
	}
}

func isRecoveryRequired(ctx context.Context, redisClient *redis.Client, adminName, appName string) (bool, string, error) {
	if redisClient == nil {
		return true, "", fmt.Errorf("redis client is nil")
	}

	delegatedRoles, err := getAllDelegatedRolesForRecovery(ctx, adminName, appName)
	if err != nil {
		return false, "", err
	}

	keySuffix := adminName + "_" + appName
	requiredKeys := []string{
		"BOOTSTRAP_" + keySuffix,
		"ROOT_EXPIRATION_" + keySuffix,
		"ROOT_THRESHOLD_" + keySuffix,
		"ROOT_NUM_KEYS_" + keySuffix,
		"TARGETS_EXPIRATION_" + keySuffix,
		"TARGETS_THRESHOLD_" + keySuffix,
		"TARGETS_NUM_KEYS_" + keySuffix,
		"TARGETS_ONLINE_KEY_" + keySuffix,
		"SNAPSHOT_EXPIRATION_" + keySuffix,
		"SNAPSHOT_THRESHOLD_" + keySuffix,
		"SNAPSHOT_NUM_KEYS_" + keySuffix,
		"TIMESTAMP_EXPIRATION_" + keySuffix,
		"TIMESTAMP_THRESHOLD_" + keySuffix,
		"TIMESTAMP_NUM_KEYS_" + keySuffix,
		"ROOT_SIGNING_" + keySuffix,
	}
	for _, roleName := range delegatedRoles {
		requiredKeys = append(requiredKeys, roleName+"_EXPIRATION_"+keySuffix)
	}

	for _, key := range requiredKeys {
		val, err := redisClient.Get(ctx, key).Result()
		if err == redis.Nil {
			return true, "", nil
		}
		if err != nil {
			return false, "", fmt.Errorf("failed to read key %s: %w", key, err)
		}
		if key != "ROOT_SIGNING_"+keySuffix && strings.TrimSpace(val) == "" {
			return true, "", nil
		}
	}

	bootstrapValue, _ := redisClient.Get(ctx, "BOOTSTRAP_"+keySuffix).Result()
	if strings.HasPrefix(bootstrapValue, "pre-") {
		return true, "", nil
	}
	rootSigningValue, _ := redisClient.Get(ctx, "ROOT_SIGNING_"+keySuffix).Result()
	if strings.TrimSpace(rootSigningValue) != "" {
		return true, "", nil
	}
	targetsOnlineValue, _ := redisClient.Get(ctx, "TARGETS_ONLINE_KEY_"+keySuffix).Result()
	if targetsOnlineValue != "1" && strings.ToLower(targetsOnlineValue) != "true" {
		return true, "", nil
	}

	return false, "Recovery not required: Redis state is already complete and consistent", nil
}

func recoverSettingsFromStorage(ctx context.Context, adminName, appName string) (recoveredBootstrapSettings, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to get current working directory: %w", err)
	}
	tmpDir, err := os.MkdirTemp(cwd, "tmp-recovery-*")
	if err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	now := time.Now().UTC()
	repo := repository.New()

	rootPath, rootFilename, err := downloadLatestRoleMetadata(ctx, adminName, appName, "root", tmpDir)
	if err != nil {
		return recoveredBootstrapSettings{}, err
	}
	targetsPath, targetsFilename, err := downloadLatestRoleMetadata(ctx, adminName, appName, "targets", tmpDir)
	if err != nil {
		return recoveredBootstrapSettings{}, err
	}
	snapshotPath, _, err := downloadLatestRoleMetadata(ctx, adminName, appName, "snapshot", tmpDir)
	if err != nil {
		return recoveredBootstrapSettings{}, err
	}
	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	if err := downloadMetadataForBootstrap(ctx, adminName, appName, "timestamp.json", timestampPath); err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to download timestamp metadata: %w", err)
	}

	root := gotufmetadata.Root(now.Add(365 * 24 * time.Hour))
	repo.SetRoot(root)
	if _, err := repo.Root().FromFile(rootPath); err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to load root metadata: %w", err)
	}
	if err := repo.Root().VerifyDelegate("root", repo.Root()); err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to verify root metadata signatures: %w", err)
	}
	if !repo.Root().Signed.Expires.After(now) {
		return recoveredBootstrapSettings{}, fmt.Errorf("root metadata is expired at %s", repo.Root().Signed.Expires.UTC().Format(time.RFC3339))
	}

	targets := gotufmetadata.Targets(now.Add(365 * 24 * time.Hour))
	repo.SetTargets("targets", targets)
	if _, err := repo.Targets("targets").FromFile(targetsPath); err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to load targets metadata: %w", err)
	}
	if err := repo.Root().VerifyDelegate("targets", repo.Targets("targets")); err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to verify targets metadata signatures: %w", err)
	}
	if !repo.Targets("targets").Signed.Expires.After(now) {
		return recoveredBootstrapSettings{}, fmt.Errorf("targets metadata is expired at %s", repo.Targets("targets").Signed.Expires.UTC().Format(time.RFC3339))
	}

	snapshot := gotufmetadata.Snapshot(now.Add(365 * 24 * time.Hour))
	repo.SetSnapshot(snapshot)
	if _, err := repo.Snapshot().FromFile(snapshotPath); err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to load snapshot metadata: %w", err)
	}
	if err := repo.Root().VerifyDelegate("snapshot", repo.Snapshot()); err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to verify snapshot metadata signatures: %w", err)
	}
	if !repo.Snapshot().Signed.Expires.After(now) {
		return recoveredBootstrapSettings{}, fmt.Errorf("snapshot metadata is expired at %s", repo.Snapshot().Signed.Expires.UTC().Format(time.RFC3339))
	}

	timestamp := gotufmetadata.Timestamp(now.Add(365 * 24 * time.Hour))
	repo.SetTimestamp(timestamp)
	if _, err := repo.Timestamp().FromFile(timestampPath); err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to load timestamp metadata: %w", err)
	}
	if err := repo.Root().VerifyDelegate("timestamp", repo.Timestamp()); err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to verify timestamp metadata signatures: %w", err)
	}
	if !repo.Timestamp().Signed.Expires.After(now) {
		return recoveredBootstrapSettings{}, fmt.Errorf("timestamp metadata is expired at %s", repo.Timestamp().Signed.Expires.UTC().Format(time.RFC3339))
	}

	rootData, err := os.ReadFile(rootPath)
	if err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to read root metadata file %s: %w", rootFilename, err)
	}
	var rootMetadata models.RootMetadata
	if err := json.Unmarshal(rootData, &rootMetadata); err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to parse root metadata: %w", err)
	}

	targetsData, err := os.ReadFile(targetsPath)
	if err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to read targets metadata file %s: %w", targetsFilename, err)
	}
	var targetsMetadata minimalTargetsMetadata
	if err := json.Unmarshal(targetsData, &targetsMetadata); err != nil {
		return recoveredBootstrapSettings{}, fmt.Errorf("failed to parse targets metadata for delegations: %w", err)
	}

	rootExpirationDays, err := expirationDaysFromTime(repo.Root().Signed.Expires, now)
	if err != nil {
		return recoveredBootstrapSettings{}, err
	}
	targetsExpirationDays, err := expirationDaysFromTime(repo.Targets("targets").Signed.Expires, now)
	if err != nil {
		return recoveredBootstrapSettings{}, err
	}
	snapshotExpirationDays, err := expirationDaysFromTime(repo.Snapshot().Signed.Expires, now)
	if err != nil {
		return recoveredBootstrapSettings{}, err
	}
	timestampExpirationDays, err := expirationDaysFromTime(repo.Timestamp().Signed.Expires, now)
	if err != nil {
		return recoveredBootstrapSettings{}, err
	}

	roleThreshold := func(role string) int {
		r, ok := rootMetadata.Signed.Roles[role]
		if !ok || r.Threshold < 1 {
			return 1
		}
		return r.Threshold
	}
	roleNumKeys := func(role string) int {
		r, ok := rootMetadata.Signed.Roles[role]
		if !ok || len(r.KeyIDs) < 1 {
			return 1
		}
		return len(r.KeyIDs)
	}

	delegatedExpiration := map[string]int{}
	for _, delegated := range targetsMetadata.Signed.Delegations.Roles {
		roleName := strings.TrimSpace(delegated.Name)
		if roleName == "" {
			continue
		}

		delegatedPath, _, err := downloadLatestRoleMetadata(ctx, adminName, appName, roleName, tmpDir)
		if err != nil {
			logrus.Warnf("Skipping delegated role %s during recovery: %v", roleName, err)
			continue
		}

		roleTargets := gotufmetadata.Targets(now.Add(365 * 24 * time.Hour))
		repo.SetTargets(roleName, roleTargets)
		if _, err := repo.Targets(roleName).FromFile(delegatedPath); err != nil {
			logrus.Warnf("Skipping delegated role %s due to parse error: %v", roleName, err)
			continue
		}
		if err := repo.Targets("targets").VerifyDelegate(roleName, repo.Targets(roleName)); err != nil {
			logrus.Warnf("Skipping delegated role %s due to signature verification error: %v", roleName, err)
			continue
		}
		if !repo.Targets(roleName).Signed.Expires.After(now) {
			logrus.Warnf("Skipping delegated role %s because metadata is expired", roleName)
			continue
		}

		days, err := expirationDaysFromTime(repo.Targets(roleName).Signed.Expires, now)
		if err != nil {
			logrus.Warnf("Skipping delegated role %s due to expiration conversion error: %v", roleName, err)
			continue
		}
		delegatedExpiration[roleName] = days
	}

	return recoveredBootstrapSettings{
		RootExpiration:      rootExpirationDays,
		RootThreshold:       roleThreshold("root"),
		RootNumKeys:         roleNumKeys("root"),
		TargetsExpiration:   targetsExpirationDays,
		TargetsThreshold:    roleThreshold("targets"),
		TargetsNumKeys:      roleNumKeys("targets"),
		SnapshotExpiration:  snapshotExpirationDays,
		SnapshotThreshold:   roleThreshold("snapshot"),
		SnapshotNumKeys:     roleNumKeys("snapshot"),
		TimestampExpiration: timestampExpirationDays,
		TimestampThreshold:  roleThreshold("timestamp"),
		TimestampNumKeys:    roleNumKeys("timestamp"),
		TargetsOnlineKey:    true,
		DelegatedExpiration: delegatedExpiration,
	}, nil
}

func downloadLatestRoleMetadata(ctx context.Context, adminName, appName, roleName, tmpDir string) (string, string, error) {
	_, filename, err := findLatestMetadataBootstrap(ctx, adminName, appName, roleName)
	if err != nil {
		if roleName == "root" {
			path := filepath.Join(tmpDir, "root.json")
			if err := downloadMetadataForBootstrap(ctx, adminName, appName, "root.json", path); err == nil {
				return path, "root.json", nil
			}

			path = filepath.Join(tmpDir, "1.root.json")
			if err := downloadMetadataForBootstrap(ctx, adminName, appName, "1.root.json", path); err == nil {
				return path, "1.root.json", nil
			}
		}
		return "", "", fmt.Errorf("failed to find latest %s metadata version: %w", roleName, err)
	}

	path := filepath.Join(tmpDir, filename)
	if err := downloadMetadataForBootstrap(ctx, adminName, appName, filename, path); err != nil {
		return "", "", fmt.Errorf("failed to download %s metadata %s: %w", roleName, filename, err)
	}
	return path, filename, nil
}

func expirationDaysFromTime(expiresAt, now time.Time) (int, error) {
	if !expiresAt.After(now) {
		return 0, fmt.Errorf("metadata is expired at %s", expiresAt.UTC().Format(time.RFC3339))
	}

	days := int(math.Ceil(expiresAt.Sub(now).Hours() / 24))
	if days < 1 {
		days = 1
	}
	return days, nil
}

const (
	bootstrapRecoveryLockTTL = 5 * time.Minute
	maxBootstrapTimeout      = 5 * time.Minute
	lockBuffer               = 30 * time.Second
)

func resolveBootstrapRecoveryTimeoutSeconds(payloadTimeout *int, adminName, appName string) int {
	timeout := 300
	if payloadTimeout != nil && *payloadTimeout > 0 {
		timeout = *payloadTimeout
		logrus.Debugf("Timeout: %d", timeout)
	} else if payloadTimeout != nil {
		logrus.Warnf("Invalid bootstrap recovery timeout %d seconds for admin %s, app %s. Falling back to default %d seconds", *payloadTimeout, adminName, appName, timeout)
	}

	maxTimeoutSeconds := int(maxBootstrapTimeout / time.Second)
	if timeout > maxTimeoutSeconds {
		logrus.Warnf(
			"Bootstrap recovery timeout %d seconds exceeds max %d seconds for admin %s, app %s. Capping timeout.",
			timeout,
			maxTimeoutSeconds,
			adminName,
			appName,
		)
		timeout = maxTimeoutSeconds
	}

	return timeout
}

func calculateBootstrapRecoveryLockTTL(timeout time.Duration) time.Duration {
	lockTTL := timeout + lockBuffer
	if lockTTL < bootstrapRecoveryLockTTL {
		return bootstrapRecoveryLockTTL
	}
	return lockTTL
}
