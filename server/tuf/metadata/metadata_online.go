package metadata

import (
	"context"
	"crypto"
	"encoding/json"
	"faynoSync/server/tuf/models"
	"faynoSync/server/tuf/signing"
	tuf_storage "faynoSync/server/tuf/storage"
	"faynoSync/server/tuf/tasks"
	tuf_utils "faynoSync/server/tuf/utils"
	"faynoSync/server/utils"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func PostMetadataOnline(c *gin.Context, redisClient *redis.Client) {
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

	var payload models.MetadataOnlinePostPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		logrus.Errorf("Failed to parse metadata online payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid payload format: %v", err),
		})
		return
	}
	logrus.Debugf("payload: %+v", payload)

	if contains(payload.Roles, "root") {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Root role cannot be updated via this endpoint",
		})
		return
	}

	ctx := context.Background()
	keySuffix := adminName + "_" + appName

	bootstrapKey := "BOOTSTRAP_" + keySuffix
	bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
	switch {
	case err == redis.Nil, bootstrapValue == "":
		c.JSON(http.StatusNotFound, gin.H{
			"message": "Task not accepted.",
			"error":   fmt.Sprintf("Requires bootstrap finished. State: %s", bootstrapValue),
		})
		return
	case err != nil:
		logrus.Errorf("Redis error reading bootstrap key %q: %v", bootstrapKey, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Storage temporarily unavailable",
		})
		return
	}

	targetsOnlineRedisKey := "TARGETS_ONLINE_KEY_" + keySuffix
	targetsOnlineVal, err := redisClient.Get(ctx, targetsOnlineRedisKey).Result()
	var targetsOnline bool
	switch {
	case err == redis.Nil:
		targetsOnline = true
	case err != nil:
		logrus.Errorf("Redis error reading targets online key %q: %v", targetsOnlineRedisKey, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Storage temporarily unavailable",
		})
		return
	default:
		switch {
		case strings.EqualFold(targetsOnlineVal, "true"), targetsOnlineVal == "1":
			targetsOnline = true
		default:
			targetsOnline = false
		}
	}

	if contains(payload.Roles, "targets") && !targetsOnline {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "Task not accepted.",
			"error":   "Targets is an offline role - use other endpoint to update",
		})
		return
	}

	if len(payload.Roles) == 0 {
		payload.Roles = []string{"snapshot", "timestamp"}

		if targetsOnline {
			payload.Roles = append(payload.Roles, "targets")
		}
	}

	taskID := uuid.New().String()
	logrus.Debugf("Generated task_id for force online metadata update: %s", taskID)

	taskName := tasks.TaskNameForceOnlineMetadataUpdate
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
		updatedRoles, err := forceOnlineMetadataUpdate(
			ctx,
			redisClient,
			adminName,
			appName,
			payload.Roles,
		)
		if err != nil {
			logrus.Errorf("Failed to force online metadata update: %v", err)
			errorMsg := err.Error()
			taskName := tasks.TaskNameForceOnlineMetadataUpdate
			result := &tasks.TaskResult{
				Message: func() *string { s := "Force new online metadata update failed"; return &s }(),
				Error:   &errorMsg,
				Status:  func() *bool { b := false; return &b }(),
				Task:    &taskName,
			}
			now := time.Now()
			result.LastUpdate = &now
			if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, result); err != nil {
				logrus.Errorf("Failed to save error task status: %v", err)
			}
		} else {
			taskName := tasks.TaskNameForceOnlineMetadataUpdate
			result := &tasks.TaskResult{
				Message: func() *string { s := "Force new online metadata update succeeded"; return &s }(),
				Error:   nil,
				Status:  func() *bool { b := true; return &b }(),
				Task:    &taskName,
				Details: map[string]interface{}{
					"updated_roles": updatedRoles,
				},
			}
			now := time.Now()
			result.LastUpdate = &now
			if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateSuccess, result); err != nil {
				logrus.Errorf("Failed to save success task status: %v", err)
			}
		}
	}()

	response := models.MetadataOnlinePostResponse{
		Data: models.MetadataOnlinePostData{
			TaskID:     taskID,
			LastUpdate: time.Now(),
		},
		Message: "Force online metadata update accepted.",
	}

	c.JSON(http.StatusAccepted, response)
}

func forceOnlineMetadataUpdate(
	ctx context.Context,
	redisClient *redis.Client,
	adminName string,
	appName string,
	roles []string,
) ([]string, error) {
	keySuffix := adminName + "_" + appName

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}
	tmpDir, err := os.MkdirTemp(cwd, "tmp-tuf-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	repo := repository.New()

	rootPath := filepath.Join(tmpDir, "root.json")
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "1.root.json", rootPath); err != nil {
		if err2 := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "root.json", rootPath); err2 != nil {
			return nil, fmt.Errorf(
				"failed to download root metadata: primary error: %v, fallback error: %w",
				err, err2,
			)
		}
	}

	tempRoot := metadata.Root(time.Now().Add(365 * 24 * time.Hour))
	repo.SetRoot(tempRoot)
	if _, err := repo.Root().FromFile(rootPath); err != nil {
		return nil, fmt.Errorf("failed to load root metadata: %w", err)
	}

	rootData, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read root metadata: %w", err)
	}

	var rootMetadata models.RootMetadata
	if err := json.Unmarshal(rootData, &rootMetadata); err != nil {
		return nil, fmt.Errorf("failed to parse root metadata: %w", err)
	}

	// Load signers for online roles (timestamp, snapshot, targets)
	timestampRole, ok := rootMetadata.Signed.Roles["timestamp"]
	if !ok || len(timestampRole.KeyIDs) == 0 {
		return nil, fmt.Errorf("timestamp role not found in root metadata")
	}
	timestampSigners, err := buildOnlineRoleSigners(timestampRole.KeyIDs, timestampRole.Threshold, "timestamp")
	if err != nil {
		return nil, err
	}

	snapshotRole, ok := rootMetadata.Signed.Roles["snapshot"]
	if !ok || len(snapshotRole.KeyIDs) == 0 {
		return nil, fmt.Errorf("snapshot role not found in root metadata")
	}
	snapshotSigners, err := buildOnlineRoleSigners(snapshotRole.KeyIDs, snapshotRole.Threshold, "snapshot")
	if err != nil {
		return nil, err
	}

	targetsRole, ok := rootMetadata.Signed.Roles["targets"]
	if !ok || len(targetsRole.KeyIDs) == 0 {
		return nil, fmt.Errorf("targets role not found in root metadata")
	}
	targetsSigners, err := buildOnlineRoleSigners(targetsRole.KeyIDs, targetsRole.Threshold, "targets")
	if err != nil {
		return nil, err
	}

	updatedRoles := []string{}

	hasTargetsOrDelegations := false
	for _, role := range roles {
		if role == "targets" || (!isStandardRole(role) && role != "snapshot" && role != "timestamp") {
			hasTargetsOrDelegations = true
			break
		}
	}

	if contains(roles, "targets") {
		if err := bumpTargetsRole(ctx, repo, adminName, appName, redisClient, targetsSigners, tmpDir, keySuffix); err != nil {
			return nil, fmt.Errorf("failed to bump targets role: %w", err)
		}
		updatedRoles = append(updatedRoles, "targets")
		hasTargetsOrDelegations = true
	}

	delegatedRoles := []string{}
	for _, role := range roles {
		if !isStandardRole(role) {
			delegatedRoles = append(delegatedRoles, role)
		}
	}

	if len(delegatedRoles) > 0 {
		updatedDelegated, err := bumpDelegatedRoles(ctx, repo, adminName, appName, redisClient, tmpDir, keySuffix, delegatedRoles)
		if err != nil {
			return nil, fmt.Errorf("failed to bump delegated roles: %w", err)
		}
		updatedRoles = append(updatedRoles, updatedDelegated...)
		if len(updatedDelegated) > 0 {
			hasTargetsOrDelegations = true
		}
	}

	if contains(roles, "snapshot") || hasTargetsOrDelegations {
		if err := bumpSnapshotRole(ctx, repo, adminName, appName, redisClient, snapshotSigners, tmpDir, keySuffix); err != nil {
			return nil, fmt.Errorf("failed to bump snapshot role: %w", err)
		}
		if !contains(updatedRoles, "snapshot") {
			updatedRoles = append(updatedRoles, "snapshot")
		}
	}

	if contains(roles, "timestamp") || hasTargetsOrDelegations || contains(roles, "snapshot") {
		if err := bumpTimestampRole(ctx, repo, adminName, appName, redisClient, timestampSigners, tmpDir, keySuffix); err != nil {
			return nil, fmt.Errorf("failed to bump timestamp role: %w", err)
		}
		if !contains(updatedRoles, "timestamp") {
			updatedRoles = append(updatedRoles, "timestamp")
		}
	}

	return updatedRoles, nil
}

func bumpTargetsRole(
	ctx context.Context,
	repo *repository.Type,
	adminName string,
	appName string,
	redisClient *redis.Client,
	signers []signature.Signer,
	tmpDir string,
	keySuffix string,
) error {
	_, targetsFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "targets")
	if err != nil {
		return fmt.Errorf("failed to find latest targets version: %w", err)
	}

	targetsPath := filepath.Join(tmpDir, targetsFilename)
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, targetsFilename, targetsPath); err != nil {
		return fmt.Errorf("failed to download targets metadata: %w", err)
	}

	targetsExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TARGETS_EXPIRATION_"+keySuffix, 365)
	targets := metadata.Targets(tuf_utils.HelperExpireIn(targetsExpiration))
	repo.SetTargets("targets", targets)
	if _, err := repo.Targets("targets").FromFile(targetsPath); err != nil {
		return fmt.Errorf("failed to load targets metadata: %w", err)
	}

	repo.Targets("targets").Signed.Version++
	repo.Targets("targets").Signed.Expires = tuf_utils.HelperExpireIn(targetsExpiration)
	repo.Targets("targets").ClearSignatures()

	for i, s := range signers {
		if _, err := repo.Targets("targets").Sign(s); err != nil {
			return fmt.Errorf("failed to sign targets metadata with key %d: %w", i+1, err)
		}
	}

	newTargetsFilename := fmt.Sprintf("%d.targets.json", repo.Targets("targets").Signed.Version)
	newTargetsPath := filepath.Join(tmpDir, newTargetsFilename)
	if err := repo.Targets("targets").ToFile(newTargetsPath, true); err != nil {
		return fmt.Errorf("failed to save targets metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, newTargetsFilename, newTargetsPath); err != nil {
		return fmt.Errorf("failed to upload targets metadata to S3: %w", err)
	}

	logrus.Infof("Successfully bumped targets role to version %d", repo.Targets("targets").Signed.Version)
	return nil
}

func bumpDelegatedRoles(
	ctx context.Context,
	repo *repository.Type,
	adminName string,
	appName string,
	redisClient *redis.Client,
	tmpDir string,
	keySuffix string,
	roleNames []string,
) (updatedDelegatedRoles []string, err error) {

	_, targetsFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "targets")
	if err != nil {
		return nil, fmt.Errorf("failed to find latest targets version: %w", err)
	}

	targetsPath := filepath.Join(tmpDir, targetsFilename)
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, targetsFilename, targetsPath); err != nil {
		return nil, fmt.Errorf("failed to download targets metadata: %w", err)
	}

	targetsExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TARGETS_EXPIRATION_"+keySuffix, 365)
	targets := metadata.Targets(tuf_utils.HelperExpireIn(targetsExpiration))
	repo.SetTargets("targets", targets)
	if _, err := repo.Targets("targets").FromFile(targetsPath); err != nil {
		return nil, fmt.Errorf("failed to load targets metadata: %w", err)
	}

	var updated []string
	for _, roleName := range roleNames {
		rolesExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, roleName+"_EXPIRATION_"+keySuffix, 365)

		_, delegationFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, roleName)
		if err != nil {
			logrus.Warnf("Failed to find delegation %s, skipping: %v", roleName, err)
			continue
		}

		delegationPath := filepath.Join(tmpDir, delegationFilename)
		if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, delegationFilename, delegationPath); err != nil {
			logrus.Warnf("Failed to download delegation %s, skipping: %v", roleName, err)
			continue
		}

		delegation := metadata.Targets(tuf_utils.HelperExpireIn(rolesExpiration))
		repo.SetTargets(roleName, delegation)
		if _, err := repo.Targets(roleName).FromFile(delegationPath); err != nil {
			logrus.Warnf("Failed to load delegation %s, skipping: %v", roleName, err)
			continue
		}

		targets := repo.Targets("targets")
		if targets == nil || targets.Signed.Delegations == nil {
			return nil, fmt.Errorf("failed to get delegations from targets metadata for role %s", roleName)
		}

		var roleKeyIDs []string
		var roleThreshold int
		for _, role := range targets.Signed.Delegations.Roles {
			if role.Name == roleName {
				roleKeyIDs = role.KeyIDs
				roleThreshold = role.Threshold
				break
			}
		}

		if len(roleKeyIDs) == 0 {
			return nil, fmt.Errorf("no key IDs found for delegated role %s", roleName)
		}
		if roleThreshold < 1 {
			roleThreshold = 1
		}

		seenKeyID := make(map[string]bool)
		keysToSign := make([]string, 0, roleThreshold)
		for _, keyID := range roleKeyIDs {
			if seenKeyID[keyID] {
				continue
			}
			seenKeyID[keyID] = true
			keysToSign = append(keysToSign, keyID)
			if len(keysToSign) == roleThreshold {
				break
			}
		}
		if len(keysToSign) < roleThreshold {
			return nil, fmt.Errorf("not enough distinct keys for delegated role %s: need %d, got %d", roleName, roleThreshold, len(keysToSign))
		}

		repo.Targets(roleName).Signed.Version++
		repo.Targets(roleName).Signed.Expires = tuf_utils.HelperExpireIn(rolesExpiration)
		repo.Targets(roleName).ClearSignatures()

		for _, delegationKeyID := range keysToSign {
			delegationPrivateKey, err := signing.LoadPrivateKeyFromFilesystem(delegationKeyID, delegationKeyID)
			if err != nil {
				return nil, fmt.Errorf("failed to load delegation private key %s for role %s: %w", delegationKeyID, roleName, err)
			}

			delegationSigner, err := signature.LoadSigner(delegationPrivateKey, crypto.Hash(0))
			if err != nil {
				return nil, fmt.Errorf("failed to create delegation signer for role %s: %w", roleName, err)
			}

			if _, err := repo.Targets(roleName).Sign(delegationSigner); err != nil {
				return nil, fmt.Errorf("failed to sign delegation %s with key %s: %w", roleName, delegationKeyID, err)
			}
		}

		newDelegationFilename := fmt.Sprintf("%d.%s.json", repo.Targets(roleName).Signed.Version, roleName)
		newDelegationPath := filepath.Join(tmpDir, newDelegationFilename)
		if err := repo.Targets(roleName).ToFile(newDelegationPath, true); err != nil {
			return nil, fmt.Errorf("failed to save delegation %s: %w", roleName, err)
		}

		if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, newDelegationFilename, newDelegationPath); err != nil {
			return nil, fmt.Errorf("failed to upload delegation %s to S3: %w", roleName, err)
		}

		logrus.Infof("Successfully bumped delegation %s to version %d", roleName, repo.Targets(roleName).Signed.Version)
		updated = append(updated, roleName)
	}

	return updated, nil
}

func bumpSnapshotRole(
	ctx context.Context,
	repo *repository.Type,
	adminName string,
	appName string,
	redisClient *redis.Client,
	signers []signature.Signer,
	tmpDir string,
	keySuffix string,
) error {
	lockKey := fmt.Sprintf("LOCK_SNAPSHOT_%s_%s", adminName, appName)
	lockTTL := 300 * time.Second

	acquired, err := redisClient.SetNX(ctx, lockKey, "locked", lockTTL).Result()
	if err != nil {
		return fmt.Errorf("failed to acquire snapshot lock: %w", err)
	}
	if !acquired {
		return fmt.Errorf("failed to acquire snapshot lock: snapshot lock already held")
	}

	defer func() {
		if err := redisClient.Del(ctx, lockKey).Err(); err != nil {
			logrus.Warnf("Failed to release snapshot lock: %v", err)
		}
	}()

	_, snapshotFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "snapshot")
	if err != nil {
		return fmt.Errorf("failed to find latest snapshot version: %w", err)
	}

	snapshotPath := filepath.Join(tmpDir, snapshotFilename)
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, snapshotFilename, snapshotPath); err != nil {
		return fmt.Errorf("failed to download snapshot metadata: %w", err)
	}

	snapshotExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "SNAPSHOT_EXPIRATION_"+keySuffix, 7)
	snapshot := metadata.Snapshot(tuf_utils.HelperExpireIn(snapshotExpiration))
	repo.SetSnapshot(snapshot)
	if _, err := repo.Snapshot().FromFile(snapshotPath); err != nil {
		return fmt.Errorf("failed to load snapshot metadata: %w", err)
	}

	snapshotMeta := repo.Snapshot().Signed.Meta
	if snapshotMeta == nil {
		snapshotMeta = make(map[string]*metadata.MetaFiles)
		repo.Snapshot().Signed.Meta = snapshotMeta
	}

	targets := repo.Targets("targets")
	if targets != nil {
		snapshotMeta["targets.json"] = metadata.MetaFile(int64(targets.Signed.Version))
	}

	if targets != nil && targets.Signed.Delegations != nil {
		if targets.Signed.Delegations.Roles != nil {
			for _, role := range targets.Signed.Delegations.Roles {
				delegation := repo.Targets(role.Name)
				if delegation != nil {
					metaFilename := fmt.Sprintf("%s.json", role.Name)
					snapshotMeta[metaFilename] = metadata.MetaFile(int64(delegation.Signed.Version))
				}
			}
		}
	}

	repo.Snapshot().Signed.Version++
	repo.Snapshot().Signed.Expires = tuf_utils.HelperExpireIn(snapshotExpiration)
	repo.Snapshot().ClearSignatures()

	for i, s := range signers {
		if _, err := repo.Snapshot().Sign(s); err != nil {
			return fmt.Errorf("failed to sign snapshot metadata with key %d: %w", i+1, err)
		}
	}

	newSnapshotFilename := fmt.Sprintf("%d.snapshot.json", repo.Snapshot().Signed.Version)
	newSnapshotPath := filepath.Join(tmpDir, newSnapshotFilename)
	if err := repo.Snapshot().ToFile(newSnapshotPath, true); err != nil {
		return fmt.Errorf("failed to save snapshot metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, newSnapshotFilename, newSnapshotPath); err != nil {
		return fmt.Errorf("failed to upload snapshot metadata to S3: %w", err)
	}

	logrus.Infof("Successfully bumped snapshot role to version %d", repo.Snapshot().Signed.Version)
	return nil
}

func bumpTimestampRole(
	ctx context.Context,
	repo *repository.Type,
	adminName string,
	appName string,
	redisClient *redis.Client,
	signers []signature.Signer,
	tmpDir string,
	keySuffix string,
) error {

	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "timestamp.json", timestampPath); err != nil {
		logrus.Debug("Timestamp metadata not found, creating new one")
	}

	timestampExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TIMESTAMP_EXPIRATION_"+keySuffix, 1)
	timestamp := metadata.Timestamp(tuf_utils.HelperExpireIn(timestampExpiration))
	repo.SetTimestamp(timestamp)
	loadedTimestamp := false
	if _, err := os.Stat(timestampPath); err == nil {
		if _, err := repo.Timestamp().FromFile(timestampPath); err != nil {
			logrus.Warnf("Failed to load timestamp metadata: %v, creating new one", err)
		} else {
			loadedTimestamp = true
		}
	}

	timestampMeta := repo.Timestamp().Signed.Meta
	if timestampMeta == nil {
		timestampMeta = make(map[string]*metadata.MetaFiles)
		repo.Timestamp().Signed.Meta = timestampMeta
	}

	snapshot := repo.Snapshot()
	if snapshot != nil {
		snapshotMetaFile := metadata.MetaFile(int64(snapshot.Signed.Version))
		timestampMeta["snapshot.json"] = snapshotMetaFile
	}
	if loadedTimestamp {
		repo.Timestamp().Signed.Version++
	}

	repo.Timestamp().Signed.Expires = tuf_utils.HelperExpireIn(timestampExpiration)
	repo.Timestamp().ClearSignatures()

	for i, s := range signers {
		if _, err := repo.Timestamp().Sign(s); err != nil {
			return fmt.Errorf("failed to sign timestamp metadata with key %d: %w", i+1, err)
		}
	}

	timestampPath = filepath.Join(tmpDir, "timestamp.json")
	if err := repo.Timestamp().ToFile(timestampPath, true); err != nil {
		return fmt.Errorf("failed to save timestamp metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, "timestamp.json", timestampPath); err != nil {
		return fmt.Errorf("failed to upload timestamp metadata to S3: %w", err)
	}

	logrus.Infof("Successfully updated timestamp role with expiration %s", repo.Timestamp().Signed.Expires.Format(time.RFC3339))
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func buildOnlineRoleSigners(keyIDs []string, threshold int, roleName string) ([]signature.Signer, error) {
	if threshold < 1 {
		threshold = 1
	}
	seen := make(map[string]bool)
	keysToSign := make([]string, 0, threshold)
	for _, keyID := range keyIDs {
		if seen[keyID] {
			continue
		}
		seen[keyID] = true
		keysToSign = append(keysToSign, keyID)
		if len(keysToSign) == threshold {
			break
		}
	}
	if len(keysToSign) < threshold {
		return nil, fmt.Errorf("not enough distinct keys for %s role: need %d, got %d", roleName, threshold, len(keysToSign))
	}
	signers := make([]signature.Signer, 0, len(keysToSign))
	for _, keyID := range keysToSign {
		priv, err := signing.LoadPrivateKeyFromFilesystem(keyID, keyID)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s private key %s: %w", roleName, keyID, err)
		}
		sig, err := signature.LoadSigner(priv, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("failed to create %s signer for key %s: %w", roleName, keyID, err)
		}
		signers = append(signers, sig)
	}
	return signers, nil
}

func isStandardRole(role string) bool {
	standardRoles := []string{"root", "targets", "snapshot", "timestamp"}
	for _, r := range standardRoles {
		if r == role {
			return true
		}
	}
	return false
}
