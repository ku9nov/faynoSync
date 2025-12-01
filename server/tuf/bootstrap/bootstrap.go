package bootstrap

import (
	"context"
	"faynoSync/server/tuf/metadata"
	"faynoSync/server/tuf/models"
	"faynoSync/server/tuf/tasks"
	"faynoSync/server/utils"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"go.mongodb.org/mongo-driver/mongo"
)

func GetBootstrapStatus(c *gin.Context, redisClient *redis.Client) {

	adminName, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get admin name from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	repo := repository.New()

	// Check if repository is initialized by checking if root metadata exists
	root := repo.Root()
	isInitialized := root != nil

	// Check Redis locks
	var bootstrapLock string
	var bootstrapCompleted bool
	var preLocks []string
	if redisClient != nil {
		ctx := context.Background()

		bootstrapKey := "BOOTSTRAP_" + adminName
		bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
		if err == nil && bootstrapValue != "" {
			bootstrapLock = bootstrapValue
			bootstrapCompleted = true
			logrus.Debugf("Found BOOTSTRAP lock for admin %s: %s", adminName, bootstrapLock)
		} else {
			logrus.Debugf("No BOOTSTRAP lock found in Redis for admin %s", adminName)
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

	if redisClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Redis client is not available",
		})
		return
	}

	ctx := context.Background()
	locks := make(map[string]interface{})

	bootstrapKey := "BOOTSTRAP_" + adminName
	bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
	if err == nil {
		locks["BOOTSTRAP"] = gin.H{
			"key":    bootstrapKey,
			"value":  bootstrapValue,
			"exists": true,
		}
		logrus.Debugf("Found BOOTSTRAP lock for admin %s: %s", adminName, bootstrapValue)
	} else {
		locks["BOOTSTRAP"] = gin.H{
			"key":    bootstrapKey,
			"value":  nil,
			"exists": false,
		}
		logrus.Debugf("No BOOTSTRAP lock found for admin %s", adminName)
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

func PostBootstrap(c *gin.Context, redisClient *redis.Client, mongoDatabase *mongo.Database) {
	adminName, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get admin name from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	logrus.Debugf("Starting bootstrap process for admin: %s", adminName)

	// Check if bootstrap is already in progress or completed for this admin
	if redisClient != nil {
		ctx := context.Background()
		bootstrapKey := "BOOTSTRAP_" + adminName
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
				logrus.Warnf("Bootstrap already in progress for admin %s. Task ID: %s", adminName, bootstrapValue)
				c.JSON(http.StatusConflict, gin.H{
					"error": "Bootstrap already in progress for this admin",
					"data": gin.H{
						"task_id": bootstrapValue,
						"admin":   adminName,
						"status":  "in_progress",
					},
				})
				return
			}

			if preLockExists == 0 && settingsExists == 0 {
				logrus.Warnf("Bootstrap already completed for admin %s. Task ID: %s", adminName, bootstrapValue)
				c.JSON(http.StatusConflict, gin.H{
					"error": "Bootstrap already completed for this admin",
					"data": gin.H{
						"task_id": bootstrapValue,
						"admin":   adminName,
						"status":  "completed",
					},
				})
				return
			}
		}

		preLockKeys, err := redisClient.Keys(ctx, "pre-*").Result()
		if err == nil {
			for _, preKey := range preLockKeys {

				taskIDFromPre := preKey[4:] // Remove "pre-" prefix

				settingsKey := "bootstrap:settings:" + taskIDFromPre
				settingsExists, err := redisClient.Exists(ctx, settingsKey).Result()
				if err == nil && settingsExists > 0 {

					bootstrapKey := "BOOTSTRAP_" + adminName
					bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
					if err == nil && bootstrapValue == taskIDFromPre {
						logrus.Warnf("Bootstrap already in progress for admin %s. Task ID: %s (found via pre-lock)", adminName, taskIDFromPre)
						c.JSON(http.StatusConflict, gin.H{
							"error": "Bootstrap already in progress for this admin",
							"data": gin.H{
								"task_id": taskIDFromPre,
								"admin":   adminName,
								"status":  "in_progress",
							},
						})
						return
					}
				}
			}
		}
		logrus.Debugf("No existing bootstrap lock or in-progress bootstrap found for admin %s", adminName)
	}

	logrus.Debug("Checking bootstrap state")
	repo := repository.New()
	root := repo.Root()
	if root != nil {
		logrus.Warn("System already has metadata. Bootstrap already completed")
		c.JSON(http.StatusNotFound, gin.H{
			"error": "System already has a Metadata. Bootstrap already completed.",
		})
		return
	}
	logrus.Debug("Bootstrap state check passed - system is available for bootstrap")

	var payload models.BootstrapPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		logrus.Errorf("Failed to parse bootstrap payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid payload format: %v", err),
		})
		return
	}

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

	// Initialize task status as PENDING
	taskName := tasks.TaskNameBootstrap
	tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStatePending, &tasks.TaskResult{
		Task: &taskName,
	})

	logrus.Debug("Calling pre_lock_bootstrap")
	preLockBootstrap(redisClient, taskID, adminName)

	logrus.Debug("Starting bootstrap function in background")
	go func() {
		bootstrap(c.Request.Context(), redisClient, mongoDatabase, taskID, adminName, &payload)
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"data": gin.H{
			"task_id":     taskID,
			"last_update": time.Now().Format(time.RFC3339),
		},
		"message": "Bootstrap accepted and started in background",
	})
}

func preLockBootstrap(redisClient *redis.Client, taskID string, adminName string) {
	logrus.Debugf("Setting pre-lock and BOOTSTRAP lock in Redis for admin: %s, task_id: %s", adminName, taskID)
	if redisClient != nil {
		ctx := context.Background()

		preLockKey := "pre-" + taskID
		err := redisClient.Set(ctx, preLockKey, taskID, 0).Err()
		if err != nil {
			logrus.Errorf("Failed to set pre-lock in Redis: %v", err)
		} else {
			logrus.Debugf("Successfully set pre-lock in Redis: %s", preLockKey)
		}

		bootstrapKey := "BOOTSTRAP_" + adminName
		bootstrapValue := "pre-" + taskID
		err = redisClient.Set(ctx, bootstrapKey, bootstrapValue, 0).Err()
		if err != nil {
			logrus.Errorf("Failed to set BOOTSTRAP lock in Redis for admin %s: %v", adminName, err)
		} else {
			logrus.Debugf("Successfully set BOOTSTRAP lock in Redis for admin %s: %s (key: %s)", adminName, bootstrapValue, bootstrapKey)
		}
	} else {
		logrus.Warn("Redis client is nil, skipping pre-lock and BOOTSTRAP lock")
	}
}

func bootstrap(ctx context.Context, redisClient *redis.Client, mongoDatabase *mongo.Database, taskID string, adminName string, payload *models.BootstrapPayload) {
	logrus.Debugf("Starting bootstrap function for admin: %s, task_id: %s", adminName, taskID)

	// Update task state to STARTED
	tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateStarted)

	// Update task state to RUNNING
	tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateRunning)

	logrus.Debug("Saving bootstrap settings")
	saveSettings(redisClient, taskID, adminName, payload)

	logrus.Debug("Finalizing bootstrap")
	success := bootstrapFinalize(redisClient, mongoDatabase, taskID, adminName, payload)

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
	}
}

func bootstrapFinalize(redisClient *redis.Client, mongoDatabase *mongo.Database, taskID string, adminName string, payload *models.BootstrapPayload) bool {
	logrus.Debugf("Starting bootstrap finalization for admin: %s", adminName)

	logrus.Debug("Calling bootstrap_online_roles")
	metadata.BootstrapOnlineRoles(redisClient, mongoDatabase, taskID, adminName, payload)

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

		rootSigningKey := "ROOT_SIGNING_" + adminName
		if err := redisClient.Set(ctx, rootSigningKey, "", 0).Err(); err != nil {
			logrus.Warnf("Failed to clear ROOT_SIGNING for admin %s: %v", adminName, err)
		} else {
			logrus.Debugf("Successfully cleared ROOT_SIGNING for admin %s", adminName)
		}

		bootstrapKey := "BOOTSTRAP_" + adminName
		if err := redisClient.Set(ctx, bootstrapKey, taskID, 0).Err(); err != nil {
			logrus.Errorf("Failed to set final BOOTSTRAP state for admin %s: %v", adminName, err)
			return false
		} else {
			logrus.Debugf("Successfully set final BOOTSTRAP state for admin %s: %s", adminName, taskID)
		}
	} else {
		logrus.Warn("Redis client is nil, skipping cleanup")
	}

	logrus.Debug("Bootstrap finalization completed")
	return true
}
