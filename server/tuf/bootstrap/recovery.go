package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"faynoSync/server/tuf/models"
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

func finalizeRecoveredBootstrapMarker(
	ctx context.Context,
	redisClient *redis.Client,
	bootstrapKey string,
	expectedBootstrapMarker string,
	recoveryTaskID string,
) (bool, error) {
	result, err := bootstrapRecoveryFinalizeScript.Run(ctx, redisClient, []string{bootstrapKey}, expectedBootstrapMarker, recoveryTaskID).Int()
	if err != nil {
		return false, err
	}
	return result == 1, nil
}

func rollbackRecoveredBootstrapMarker(
	ctx context.Context,
	redisClient *redis.Client,
	bootstrapKey string,
	recoveryMarker string,
	restoreValue string,
) error {
	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := redisClient.Watch(ctx, func(tx *redis.Tx) error {
			current, err := tx.Get(ctx, bootstrapKey).Result()
			if err == redis.Nil {
				return nil
			}
			if err != nil {
				return err
			}
			if current != recoveryMarker {
				return nil
			}

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				if restoreValue == "" {
					pipe.Del(ctx, bootstrapKey)
				} else {
					pipe.Set(ctx, bootstrapKey, restoreValue, 0)
				}
				return nil
			})
			return err
		}, bootstrapKey)
		if err == redis.TxFailedErr {
			continue
		}
		return err
	}
	return fmt.Errorf("failed to rollback BOOTSTRAP marker %s after %d retries", bootstrapKey, maxRetries)
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

	required, reason, expectedBootstrapMarker, err := isRecoveryRequired(context.Background(), redisClient, adminName, payload.AppName)
	if err != nil {
		releaseRecoveryLock(context.Background(), redisClient, lockKey, taskID)
		if errors.Is(err, errBootstrapInProgress) {
			c.JSON(http.StatusConflict, gin.H{
				"error": reason,
			})
			return
		}
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
		runBootstrapRecovery(recoveryCtx, redisClient, taskID, adminName, payload.AppName, lockKey, lockTTL, expectedBootstrapMarker)
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"data": gin.H{
			"task_id":     taskID,
			"last_update": time.Now().Format(time.RFC3339),
		},
		"message": "Bootstrap recovery accepted and started in background",
	})
}

func runBootstrapRecovery(
	ctx context.Context,
	redisClient *redis.Client,
	taskID,
	adminName,
	appName,
	lockKey string,
	lockTTL time.Duration,
	expectedBootstrapMarker string,
) {
	logrus.Infof("Starting bootstrap recovery: admin=%s app=%s task_id=%s", adminName, appName, taskID)
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), recoveryLockReleaseTimeout)
		releaseRecoveryLock(releaseCtx, redisClient, lockKey, taskID)
		cancel()
	}()
	if err := redisClient.Expire(ctx, lockKey, lockTTL).Err(); err != nil {
		logrus.Warnf("Failed to extend bootstrap recovery lock TTL: admin=%s app=%s task_id=%s ttl=%s err=%v", adminName, appName, taskID, lockTTL, err)
	}
	_ = tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateStarted)
	_ = tasks.UpdateTaskState(redisClient, taskID, tasks.TaskStateRunning)
	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	recoveryMarker := "RECOVERING_" + taskID
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

	claimed, err := finalizeRecoveredBootstrapMarker(ctx, redisClient, bootstrapKey, expectedBootstrapMarker, recoveryMarker)
	if err != nil {
		logrus.Errorf("Bootstrap recovery failed while claiming BOOTSTRAP key: admin=%s app=%s task_id=%s key=%s err=%v", adminName, appName, taskID, bootstrapKey, err)
		taskName := tasks.TaskNameBootstrapRecovery
		success := false
		errMsg := fmt.Sprintf("Bootstrap recovery failed to claim BOOTSTRAP key: %v", err)
		_ = tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, &tasks.TaskResult{
			Task:   &taskName,
			Status: &success,
			Error:  &errMsg,
		})
		return
	}
	if !claimed {
		currentBootstrapMarker, readErr := redisClient.Get(ctx, bootstrapKey).Result()
		if readErr == redis.Nil {
			currentBootstrapMarker = "<missing>"
		} else if readErr != nil {
			currentBootstrapMarker = "<unreadable>"
		}
		logrus.Warnf(
			"Bootstrap recovery aborted due to BOOTSTRAP marker mismatch while claiming: admin=%s app=%s task_id=%s key=%s expected=%s current=%s",
			adminName,
			appName,
			taskID,
			bootstrapKey,
			expectedBootstrapMarker,
			currentBootstrapMarker,
		)
		taskName := tasks.TaskNameBootstrapRecovery
		success := false
		errMsg := fmt.Sprintf("Bootstrap recovery aborted: bootstrap marker changed before claiming (expected=%s current=%s)", expectedBootstrapMarker, currentBootstrapMarker)
		_ = tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, &tasks.TaskResult{
			Task:   &taskName,
			Status: &success,
			Error:  &errMsg,
		})
		return
	}

	if err := saveRecoveredSettings(redisClient, adminName, appName, recovered); err != nil {
		logrus.Errorf("Bootstrap recovery failed during Redis write: admin=%s app=%s task_id=%s err=%v", adminName, appName, taskID, err)
		if rollbackErr := rollbackRecoveredBootstrapMarker(ctx, redisClient, bootstrapKey, recoveryMarker, expectedBootstrapMarker); rollbackErr != nil {
			logrus.Warnf("Failed to rollback in-progress BOOTSTRAP marker after Redis write failure: admin=%s app=%s task_id=%s key=%s err=%v", adminName, appName, taskID, bootstrapKey, rollbackErr)
		}
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

	updated, err := finalizeRecoveredBootstrapMarker(ctx, redisClient, bootstrapKey, recoveryMarker, taskID)
	if err != nil {
		logrus.Errorf("Bootstrap recovery failed while setting BOOTSTRAP key: admin=%s app=%s task_id=%s key=%s err=%v", adminName, appName, taskID, bootstrapKey, err)
		if rollbackErr := rollbackRecoveredBootstrapMarker(ctx, redisClient, bootstrapKey, recoveryMarker, expectedBootstrapMarker); rollbackErr != nil {
			logrus.Warnf("Failed to rollback in-progress BOOTSTRAP marker after finalize error: admin=%s app=%s task_id=%s key=%s err=%v", adminName, appName, taskID, bootstrapKey, rollbackErr)
		}
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
	if !updated {
		currentBootstrapMarker, readErr := redisClient.Get(ctx, bootstrapKey).Result()
		if readErr == redis.Nil {
			currentBootstrapMarker = "<missing>"
		} else if readErr != nil {
			currentBootstrapMarker = "<unreadable>"
		}
		logrus.Warnf(
			"Bootstrap recovery aborted due to BOOTSTRAP marker mismatch: admin=%s app=%s task_id=%s key=%s expected=%s current=%s",
			adminName,
			appName,
			taskID,
			bootstrapKey,
			expectedBootstrapMarker,
			currentBootstrapMarker,
		)
		taskName := tasks.TaskNameBootstrapRecovery
		success := false
		errMsg := fmt.Sprintf("Bootstrap recovery aborted: bootstrap marker changed (expected=%s current=%s)", expectedBootstrapMarker, currentBootstrapMarker)
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

func isRecoveryRequired(ctx context.Context, redisClient *redis.Client, adminName, appName string) (bool, string, string, error) {
	if redisClient == nil {
		return true, "", "", fmt.Errorf("redis client is nil")
	}

	delegatedRoles, err := getAllDelegatedRolesForRecovery(ctx, adminName, appName)
	if err != nil {
		return false, "", "", err
	}

	keySuffix := adminName + "_" + appName
	expectedBootstrapMarker := ""
	bootstrapKey := "BOOTSTRAP_" + keySuffix
	bootstrapValue, bootstrapErr := redisClient.Get(ctx, bootstrapKey).Result()
	if bootstrapErr != nil && bootstrapErr != redis.Nil {
		return false, "", "", fmt.Errorf("failed to read key %s: %w", bootstrapKey, bootstrapErr)
	}
	if bootstrapErr == nil && strings.HasPrefix(bootstrapValue, "pre-") {
		expectedBootstrapMarker = bootstrapValue
		active, bootstrapTaskID, err := isBootstrapTaskActive(ctx, redisClient, bootstrapValue)
		if err != nil {
			return false, "", "", err
		}
		if active {
			reason := fmt.Sprintf("Bootstrap already in progress for this admin and app (task_id=%s)", bootstrapTaskID)
			return false, reason, expectedBootstrapMarker, errBootstrapInProgress
		}
	}

	requiredKeys := []string{
		bootstrapKey,
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
			return true, "", expectedBootstrapMarker, nil
		}
		if err != nil {
			return false, "", "", fmt.Errorf("failed to read key %s: %w", key, err)
		}
		if key != "ROOT_SIGNING_"+keySuffix && strings.TrimSpace(val) == "" {
			return true, "", expectedBootstrapMarker, nil
		}
	}

	rootSigningValue, _ := redisClient.Get(ctx, "ROOT_SIGNING_"+keySuffix).Result()
	if strings.TrimSpace(rootSigningValue) != "" {
		return true, "", expectedBootstrapMarker, nil
	}
	targetsOnlineValue, _ := redisClient.Get(ctx, "TARGETS_ONLINE_KEY_"+keySuffix).Result()
	if targetsOnlineValue != "1" && strings.ToLower(targetsOnlineValue) != "true" {
		return true, "", expectedBootstrapMarker, nil
	}

	return false, "Recovery not required: Redis state is already complete and consistent", expectedBootstrapMarker, nil
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
			return recoveredBootstrapSettings{}, fmt.Errorf("failed to download delegated role metadata for %s: %w", roleName, err)
		}

		roleTargets := gotufmetadata.Targets(now.Add(365 * 24 * time.Hour))
		repo.SetTargets(roleName, roleTargets)
		if _, err := repo.Targets(roleName).FromFile(delegatedPath); err != nil {
			return recoveredBootstrapSettings{}, fmt.Errorf("failed to load delegated role metadata for %s: %w", roleName, err)
		}
		if err := repo.Targets("targets").VerifyDelegate(roleName, repo.Targets(roleName)); err != nil {
			return recoveredBootstrapSettings{}, fmt.Errorf("failed to verify delegated role metadata signatures for %s: %w", roleName, err)
		}
		if !repo.Targets(roleName).Signed.Expires.After(now) {
			return recoveredBootstrapSettings{}, fmt.Errorf(
				"delegated role %s metadata is expired at %s",
				roleName,
				repo.Targets(roleName).Signed.Expires.UTC().Format(time.RFC3339),
			)
		}

		days, err := expirationDaysFromTime(repo.Targets(roleName).Signed.Expires, now)
		if err != nil {
			return recoveredBootstrapSettings{}, fmt.Errorf("failed to derive delegated role expiration days for %s: %w", roleName, err)
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
