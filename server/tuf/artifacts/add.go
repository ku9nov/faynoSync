package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"go.mongodb.org/mongo-driver/mongo"

	"faynoSync/server/tuf/delegations"
	"faynoSync/server/tuf/signing"
	tuf_storage "faynoSync/server/tuf/storage"
	"faynoSync/server/tuf/tasks"
	tuf_utils "faynoSync/server/tuf/utils"
)

func AddArtifacts(
	ctx context.Context,
	redisClient *redis.Client,
	mongoDatabase *mongo.Database,
	adminName string,
	appName string,
	artifacts []Artifact,
	publishArtifacts bool,
	taskID string,
) error {
	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
	if err == redis.Nil || bootstrapValue == "" {
		return fmt.Errorf("bootstrap not completed for admin %s, app %s", adminName, appName)
	}

	keySuffix := adminName + "_" + appName

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}
	tmpDir, err := os.MkdirTemp(cwd, "tmp-tuf-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	repo := repository.New()

	rootPath := filepath.Join(tmpDir, "root.json")
	_, latestRootFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "root")
	if err != nil {
		if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "root.json", rootPath); err != nil {
			if err2 := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "1.root.json", rootPath); err2 != nil {
				return fmt.Errorf("failed to download root metadata (tried root.json and 1.root.json): %w", err)
			}
		}
	} else {
		if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, latestRootFilename, rootPath); err != nil {
			return fmt.Errorf("failed to download latest root metadata: %w", err)
		}
	}

	tempRoot := metadata.Root(time.Now().Add(365 * 24 * time.Hour))
	repo.SetRoot(tempRoot)
	if _, err := repo.Root().FromFile(rootPath); err != nil {
		return fmt.Errorf("failed to load root metadata: %w", err)
	}

	rootData, err := os.ReadFile(rootPath)
	if err != nil {
		return fmt.Errorf("failed to read root metadata: %w", err)
	}

	var rootJSON map[string]interface{}
	if err := json.Unmarshal(rootData, &rootJSON); err != nil {
		return fmt.Errorf("failed to parse root metadata: %w", err)
	}

	signed, ok := rootJSON["signed"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid root metadata structure")
	}

	roles, ok := signed["roles"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid root metadata: no roles")
	}

	timestampRole, ok := roles["timestamp"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid root metadata: no timestamp role")
	}

	timestampSigners, err := buildSignersFromRoleMap(timestampRole, "timestamp")
	if err != nil {
		return err
	}

	targetsRole, ok := roles["targets"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid root metadata: no targets role")
	}

	targetsSigners, err := buildSignersFromRoleMap(targetsRole, "targets")
	if err != nil {
		return err
	}

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

	rolesArtifacts := make(map[string][]Artifact)
	invalidPaths := []string{}

	for _, artifact := range artifacts {
		roleName, err := getRoleForArtifactPath(repo, artifact.Path)
		if err != nil {
			logrus.Warnf("Failed to determine role for artifact path %s: %v", artifact.Path, err)
			invalidPaths = append(invalidPaths, artifact.Path)
			continue
		}

		rolesArtifacts[roleName] = append(rolesArtifacts[roleName], artifact)
	}

	if len(invalidPaths) > 0 {
		logrus.Warnf("Skipped %d artifacts with invalid paths", len(invalidPaths))
	}

	if len(rolesArtifacts) == 0 {
		return fmt.Errorf("no valid artifacts to add")
	}

	updatedRoles := []string{}
	targetsPathsUpdated := false

	// First, update delegation paths for all roles before saving targets.json
	// This ensures that updated paths are included in the saved targets.json
	for roleName, roleArtifacts := range rolesArtifacts {
		artifactPaths := make([]string, 0, len(roleArtifacts))
		for _, artifact := range roleArtifacts {
			artifactPaths = append(artifactPaths, artifact.Path)
		}
		pathsUpdated, err := delegations.UpdateDelegationPaths(
			ctx, repo, roleName, artifactPaths, adminName,
		)
		if err != nil {
			logrus.Warnf("Failed to update delegation paths for role %s: %v", roleName, err)
			// Don't fail the entire operation if path update fails
		} else if pathsUpdated {
			targetsPathsUpdated = true
			logrus.Debugf("Delegation paths updated for role %s", roleName)
		}
	}

	// If delegation paths were updated, save targets.json before processing artifacts
	if targetsPathsUpdated {
		logrus.Debugf("Delegation paths were updated, saving targets metadata before processing artifacts")
		// Update expiration and increment version when delegation paths are updated
		repo.Targets("targets").Signed.Expires = tuf_utils.HelperExpireIn(targetsExpiration)
		repo.Targets("targets").Signed.Version++
		repo.Targets("targets").ClearSignatures()
		for i, s := range targetsSigners {
			if _, err := repo.Targets("targets").Sign(s); err != nil {
				return fmt.Errorf("failed to re-sign targets metadata with key %d: %w", i+1, err)
			}
		}

		targetsVersion := repo.Targets("targets").Signed.Version
		correctTargetsFilename := fmt.Sprintf("%d.targets.json", targetsVersion)
		correctTargetsPath := filepath.Join(tmpDir, correctTargetsFilename)
		if err := repo.Targets("targets").ToFile(correctTargetsPath, true); err != nil {
			return fmt.Errorf("failed to save targets metadata after path update: %w", err)
		}

		if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, correctTargetsFilename, correctTargetsPath); err != nil {
			return fmt.Errorf("failed to upload targets metadata to S3 after path update: %w", err)
		}
		logrus.Debugf("Successfully updated and saved targets metadata with new delegation paths")
	}

	// Now process artifacts for each role
	for roleName, roleArtifacts := range rolesArtifacts {
		_, err := updateDelegatedRoleWithArtifacts(
			ctx, repo, roleName, roleArtifacts, adminName, appName, redisClient, tmpDir,
		)
		if err != nil {
			return fmt.Errorf("failed to update role %s: %w", roleName, err)
		}
		updatedRoles = append(updatedRoles, roleName)
	}

	if publishArtifacts {
		root := repo.Root()
		snapshotRole, ok := root.Signed.Roles["snapshot"]
		if !ok || len(snapshotRole.KeyIDs) == 0 {
			return fmt.Errorf("failed to find snapshot key in root metadata")
		}
		snapshotSigners, err := buildSignersFromKeyIDsAndThreshold(snapshotRole.KeyIDs, snapshotRole.Threshold, "snapshot")
		if err != nil {
			return fmt.Errorf("failed to build snapshot signers: %w", err)
		}

		if err := updateSnapshotAndTimestamp(
			ctx, repo, updatedRoles, adminName, appName, redisClient, timestampSigners, snapshotSigners, tmpDir,
		); err != nil {
			return fmt.Errorf("failed to update snapshot and timestamp: %w", err)
		}
	}

	message := "Artifact(s) Added"
	if len(invalidPaths) > 0 {
		message += fmt.Sprintf(". %d invalid paths skipped", len(invalidPaths))
	}

	details := map[string]interface{}{
		"added_artifacts": getArtifactPaths(artifacts),
		"invalid_paths":   invalidPaths,
		"target_roles":    updatedRoles,
	}

	result := &tasks.TaskResult{
		Message: &message,
		Status:  func() *bool { b := true; return &b }(),
		Task:    func() *tasks.TaskName { t := tasks.TaskNameAddArtifacts; return &t }(),
		Details: details,
	}

	now := time.Now()
	result.LastUpdate = &now

	if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateSuccess, result); err != nil {
		logrus.Warnf("Failed to save task status: %v", err)
	}

	return nil
}

func getRoleForArtifactPath(repo *repository.Type, artifactPath string) (string, error) {
	targets := repo.Targets("targets")
	if targets == nil {
		return "", fmt.Errorf("targets metadata not loaded")
	}

	delegations := targets.Signed.Delegations
	if delegations == nil {
		return "", fmt.Errorf("no delegations found in targets metadata")
	}

	if delegations.Roles != nil {

		for _, role := range delegations.Roles {
			if matchesRole(artifactPath, &role) {
				return role.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no delegated role found for path: %s", artifactPath)
}

func matchesRole(artifactPath string, role *metadata.DelegatedRole) bool {
	if role == nil {
		return false
	}

	if len(role.Paths) > 0 {
		for _, pattern := range role.Paths {
			matched, err := matchDelegatedPathPattern(pattern, artifactPath)
			if err != nil {
				logrus.WithError(err).Warnf("Invalid delegation path pattern %q for artifact %q", pattern, artifactPath)
				continue
			}
			if matched {
				return true
			}
		}
	}

	if len(role.PathHashPrefixes) > 0 {
		digest := sha256.Sum256([]byte(artifactPath))
		hashHex := hex.EncodeToString(digest[:])
		for _, prefix := range role.PathHashPrefixes {
			if strings.HasPrefix(hashHex, prefix) {
				return true
			}
		}
	}

	return false
}

func matchDelegatedPathPattern(pattern string, artifactPath string) (bool, error) {
	matched, err := path.Match(pattern, artifactPath)
	if err != nil {
		return false, err
	}
	if matched {
		return true, nil
	}

	// Preserve legacy delegation semantics where "prefix/*" is used as recursive prefix.
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(artifactPath, prefix) {
			return true, nil
		}
	}

	return false, nil
}

func updateDelegatedRoleWithArtifacts(
	ctx context.Context,
	repo *repository.Type,
	roleName string,
	artifacts []Artifact,
	adminName string,
	appName string,
	redisClient *redis.Client,
	tmpDir string,
) (bool, error) {

	_, delegationFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, roleName)
	isNewDelegation := err != nil

	roleExpirationKey := roleName + "_EXPIRATION_" + adminName + "_" + appName
	roleExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, roleExpirationKey, 90)
	delegationTargets := metadata.Targets(tuf_utils.HelperExpireIn(roleExpiration))
	repo.SetTargets(roleName, delegationTargets)

	if !isNewDelegation {
		logrus.Debugf("Loading existing delegation metadata for role %s from %s", roleName, delegationFilename)
		delegationPath := filepath.Join(tmpDir, delegationFilename)
		if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, delegationFilename, delegationPath); err != nil {
			return false, fmt.Errorf("failed to download %s metadata: %w", roleName, err)
		}

		if _, err := repo.Targets(roleName).FromFile(delegationPath); err != nil {
			return false, fmt.Errorf("failed to load %s metadata: %w", roleName, err)
		}
	} else {
		logrus.Debugf("Delegation metadata for role %s not found, creating new. Error: %v", roleName, err)
		delegation := repo.Targets(roleName)
		delegation.Signed.Version = 1
		logrus.Debugf("Created new delegation metadata for role %s with version 1", roleName)
	}

	delegation := repo.Targets(roleName)
	if delegation.Signed.Targets == nil {
		delegation.Signed.Targets = make(map[string]*metadata.TargetFiles)
	}

	for _, artifact := range artifacts {

		hashes := make(metadata.Hashes)
		for alg, hashStr := range artifact.Info.Hashes {
			hashBytes, err := hex.DecodeString(hashStr)
			if err != nil {
				logrus.Warnf("Failed to decode hash %s for algorithm %s: %v", hashStr, alg, err)
				hashBytes = []byte(hashStr)
			}
			hashes[alg] = metadata.HexBytes(hashBytes)
		}

		var custom *json.RawMessage
		if len(artifact.Info.Custom) > 0 {
			customBytes, err := json.Marshal(artifact.Info.Custom)
			if err != nil {
				logrus.Warnf("Failed to marshal custom data for artifact %s: %v", artifact.Path, err)
			} else {
				rawMsg := json.RawMessage(customBytes)
				custom = &rawMsg
			}
		}

		targetFile := &metadata.TargetFiles{
			Length: artifact.Info.Length,
			Hashes: hashes,
			Custom: custom,
		}

		delegation.Signed.Targets[artifact.Path] = targetFile
	}

	delegation.Signed.Version++

	delegation.Signed.Expires = tuf_utils.HelperExpireIn(roleExpiration)

	delegation.ClearSignatures()

	targets := repo.Targets("targets")
	if targets == nil || targets.Signed.Delegations == nil {
		return false, fmt.Errorf("failed to get delegations from targets metadata")
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
		return false, fmt.Errorf("no key IDs found for delegated role %s", roleName)
	}
	usedKeyIDs, err := signing.LoadAndSignDelegation(
		roleName,
		roleKeyIDs,
		roleThreshold,
		func(s signature.Signer, _ string) error {
			_, signErr := repo.Targets(roleName).Sign(s)
			return signErr
		},
	)
	if err != nil {
		return false, err
	}
	for _, keyID := range usedKeyIDs {
		logrus.Debugf("Successfully signed delegated role metadata %s with key %s", roleName, keyID)
	}
	newDelegationFilename := fmt.Sprintf("%d.%s.json", delegation.Signed.Version, roleName)
	delegationPath := filepath.Join(tmpDir, newDelegationFilename)
	if err := repo.Targets(roleName).ToFile(delegationPath, true); err != nil {
		return false, fmt.Errorf("failed to save %s metadata: %w", roleName, err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, newDelegationFilename, delegationPath); err != nil {
		return false, fmt.Errorf("failed to upload %s metadata to S3: %w", roleName, err)
	}

	logrus.Debugf("Successfully updated role %s with %d artifacts", roleName, len(artifacts))
	return false, nil
}

func updateSnapshotAndTimestamp(
	ctx context.Context,
	repo *repository.Type,
	updatedRoles []string,
	adminName string,
	appName string,
	redisClient *redis.Client,
	timestampSigners []signature.Signer,
	snapshotSigners []signature.Signer,
	tmpDir string,
) error {
	lockKey := fmt.Sprintf("LOCK_SNAPSHOT_%s", adminName)
	lockTTL := 300 * time.Second
	maxWaitTime := 500 * time.Second

	lockCtx, cancel := context.WithTimeout(ctx, maxWaitTime)
	defer cancel()

	lockAcquired := false
	initialDelay := 50 * time.Millisecond
	maxDelay := 2 * time.Second
	currentDelay := initialDelay
	startTime := time.Now()

	for !lockAcquired {

		select {
		case <-lockCtx.Done():
			return fmt.Errorf("failed to acquire snapshot lock: timeout after %v (another process is updating snapshot)", maxWaitTime)
		default:
		}

		acquired, err := redisClient.SetNX(lockCtx, lockKey, "locked", lockTTL).Result()
		if err != nil {

			if lockCtx.Err() != nil {
				return fmt.Errorf("failed to acquire snapshot lock: timeout after %v (another process is updating snapshot)", maxWaitTime)
			}
			return fmt.Errorf("failed to acquire snapshot lock: %w", err)
		}

		if acquired {
			lockAcquired = true
			elapsed := time.Since(startTime)
			if elapsed > 100*time.Millisecond {
				logrus.Debugf("Acquired snapshot lock after %v (retries with exponential backoff)", elapsed)
			}
			break
		}

		logrus.Debugf("Snapshot lock is held by another process, waiting %v before retry...", currentDelay)
		select {
		case <-lockCtx.Done():
			return fmt.Errorf("failed to acquire snapshot lock: timeout after %v (another process is updating snapshot)", maxWaitTime)
		case <-time.After(currentDelay):

			currentDelay *= 2
			if currentDelay > maxDelay {
				currentDelay = maxDelay
			}
		}
	}

	// Ensure lock is released when function exits
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

	snapshotExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "SNAPSHOT_EXPIRATION_"+adminName+"_"+appName, 7)
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

	// Update snapshot meta only for updated roles
	// The existing roles in snapshot are preserved automatically since we loaded snapshot from S3
	for _, roleName := range updatedRoles {
		// Role should already be loaded in repo from updateDelegatedRoleWithArtifacts
		delegation := repo.Targets(roleName)
		if delegation != nil && delegation.Signed.Version > 0 {
			metaFilename := fmt.Sprintf("%s.json", roleName)
			snapshotMeta[metaFilename] = metadata.MetaFile(int64(delegation.Signed.Version))
			logrus.Debugf("Updated snapshot meta for role %s (version %d)", roleName, delegation.Signed.Version)
		} else {
			logrus.Warnf("Role %s not found in repo or has invalid version, skipping snapshot update", roleName)
		}
	}

	// Always update targets.json in snapshot
	targets := repo.Targets("targets")
	if targets != nil {
		snapshotMeta["targets.json"] = metadata.MetaFile(int64(targets.Signed.Version))
	}

	repo.Snapshot().Signed.Version++

	repo.Snapshot().Signed.Expires = tuf_utils.HelperExpireIn(snapshotExpiration)

	repo.Snapshot().ClearSignatures()

	for i, s := range snapshotSigners {
		if _, err := repo.Snapshot().Sign(s); err != nil {
			return fmt.Errorf("failed to sign snapshot metadata with key %d: %w", i+1, err)
		}
	}

	snapshotFilename = fmt.Sprintf("%d.snapshot.json", repo.Snapshot().Signed.Version)
	snapshotPath = filepath.Join(tmpDir, snapshotFilename)
	if err := repo.Snapshot().ToFile(snapshotPath, true); err != nil {
		return fmt.Errorf("failed to save snapshot metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, snapshotFilename, snapshotPath); err != nil {
		return fmt.Errorf("failed to upload snapshot metadata to S3: %w", err)
	}

	if err := updateTimestamp(ctx, repo, adminName, appName, redisClient, timestampSigners, tmpDir); err != nil {
		return fmt.Errorf("failed to update timestamp: %w", err)
	}

	return nil
}

func updateTimestamp(
	ctx context.Context,
	repo *repository.Type,
	adminName string,
	appName string,
	redisClient *redis.Client,
	signers []signature.Signer,
	tmpDir string,
) error {
	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "timestamp.json", timestampPath); err != nil {
		logrus.Debug("Timestamp metadata not found, creating new one")
	}

	timestampExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TIMESTAMP_EXPIRATION_"+adminName+"_"+appName, 1)
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

	return nil
}

func buildSignersFromRoleMap(roleMap map[string]interface{}, roleName string) ([]signature.Signer, error) {
	keyIDsRaw, ok := roleMap["keyids"].([]interface{})
	if !ok || len(keyIDsRaw) == 0 {
		return nil, fmt.Errorf("invalid root metadata: no %s keyids", roleName)
	}
	threshold := 1
	if t, ok := roleMap["threshold"].(float64); ok && int(t) >= 1 {
		threshold = int(t)
	}
	keyIDs := make([]string, 0, len(keyIDsRaw))
	for _, v := range keyIDsRaw {
		if s, ok := v.(string); ok {
			keyIDs = append(keyIDs, s)
		}
	}
	return buildSignersFromKeyIDsAndThreshold(keyIDs, threshold, roleName)
}

func buildSignersFromKeyIDsAndThreshold(keyIDs []string, threshold int, roleName string) ([]signature.Signer, error) {
	signers := make([]signature.Signer, 0)
	_, err := signing.LoadAndSignDelegation(
		roleName,
		keyIDs,
		threshold,
		func(s signature.Signer, _ string) error {
			signers = append(signers, s)
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return signers, nil
}

func getArtifactPaths(artifacts []Artifact) []string {
	paths := make([]string, len(artifacts))
	for i, artifact := range artifacts {
		paths[i] = artifact.Path
	}
	return paths
}
