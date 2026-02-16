package artifacts

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

func RemoveArtifacts(
	ctx context.Context,
	redisClient *redis.Client,
	mongoDatabase *mongo.Database,
	adminName string,
	appName string,
	artifacts []Artifact,
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
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "1.root.json", rootPath); err != nil {
		if err2 := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "root.json", rootPath); err2 != nil {
			return fmt.Errorf("failed to download root metadata: %w", err)
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
		return fmt.Errorf("no valid artifacts to remove")
	}

	updatedRoles := []string{}
	targetsPathsUpdated := false

	for roleName, roleArtifacts := range rolesArtifacts {
		artifactPaths := make([]string, 0, len(roleArtifacts))
		for _, artifact := range roleArtifacts {
			artifactPaths = append(artifactPaths, artifact.Path)
		}
		pathsRemoved, err := delegations.RemoveDelegationPaths(
			ctx, repo, roleName, artifactPaths, adminName,
		)
		if err != nil {
			logrus.Warnf("Failed to remove delegation paths for role %s: %v", roleName, err)

		} else if pathsRemoved {
			targetsPathsUpdated = true
			logrus.Debugf("Delegation paths removed for role %s", roleName)
		}
	}

	if targetsPathsUpdated {
		logrus.Debugf("Delegation paths were removed, saving targets metadata before processing artifacts")
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
			return fmt.Errorf("failed to save targets metadata after path removal: %w", err)
		}

		if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, correctTargetsFilename, correctTargetsPath); err != nil {
			return fmt.Errorf("failed to upload targets metadata to S3 after path removal: %w", err)
		}
		logrus.Debugf("Successfully updated and saved targets metadata with removed delegation paths")
	}

	for roleName, roleArtifacts := range rolesArtifacts {
		removed, err := removeArtifactsFromDelegatedRole(
			ctx,
			repo,
			roleName,
			roleArtifacts,
			adminName,
			appName,
			redisClient,
			tmpDir,
		)
		if err != nil {
			logrus.Errorf("Failed to remove artifacts from role %s: %v", roleName, err)
			return fmt.Errorf("failed to remove artifacts from role %s: %w", roleName, err)
		}
		if removed {
			updatedRoles = append(updatedRoles, roleName)
		}
	}

	if len(updatedRoles) == 0 {
		logrus.Warnf("No artifacts were removed from any delegated roles")
		return nil
	}

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
		ctx,
		repo,
		updatedRoles,
		adminName,
		appName,
		redisClient,
		timestampSigners,
		snapshotSigners,
		tmpDir,
	); err != nil {
		return fmt.Errorf("failed to update snapshot and timestamp: %w", err)
	}

	result := &tasks.TaskResult{
		Status: func() *bool { b := true; return &b }(),
		Message: func() *string {
			s := fmt.Sprintf("Successfully removed %d artifacts from TUF metadata", len(artifacts))
			return &s
		}(),
		Task: func() *tasks.TaskName { t := tasks.TaskNameRemoveArtifacts; return &t }(),
	}

	now := time.Now()
	result.LastUpdate = &now

	if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateSuccess, result); err != nil {
		logrus.Warnf("Failed to save task status: %v", err)
	}

	return nil
}

func removeArtifactsFromDelegatedRole(
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
	if err != nil {
		return false, fmt.Errorf("failed to find latest delegation metadata for role %s: %w", roleName, err)
	}

	roleExpirationKey := roleName + "_EXPIRATION_" + adminName + "_" + appName
	roleExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, roleExpirationKey, 90)
	delegationTargets := metadata.Targets(tuf_utils.HelperExpireIn(roleExpiration))
	repo.SetTargets(roleName, delegationTargets)

	logrus.Debugf("Loading existing delegation metadata for role %s from %s", roleName, delegationFilename)
	delegationPath := filepath.Join(tmpDir, delegationFilename)
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, delegationFilename, delegationPath); err != nil {
		return false, fmt.Errorf("failed to download %s metadata: %w", roleName, err)
	}

	if _, err := repo.Targets(roleName).FromFile(delegationPath); err != nil {
		return false, fmt.Errorf("failed to load %s metadata: %w", roleName, err)
	}

	delegation := repo.Targets(roleName)
	if delegation.Signed.Targets == nil {
		logrus.Warnf("Delegation %s has no targets, nothing to remove", roleName)
		return false, nil
	}

	removedCount := 0
	for _, artifact := range artifacts {
		if _, exists := delegation.Signed.Targets[artifact.Path]; exists {
			delete(delegation.Signed.Targets, artifact.Path)
			removedCount++
			logrus.Debugf("Removed artifact %s from role %s", artifact.Path, roleName)
		} else {
			logrus.Warnf("Artifact %s not found in role %s metadata", artifact.Path, roleName)
		}
	}

	if removedCount == 0 {
		logrus.Warnf("No artifacts were removed from role %s (they may not have existed)", roleName)
		return false, nil
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
		return false, fmt.Errorf("not enough distinct keys for delegated role %s: need %d, got %d", roleName, roleThreshold, len(keysToSign))
	}

	for _, delegationKeyID := range keysToSign {
		delegationPrivateKey, err := signing.LoadPrivateKeyFromFilesystem(delegationKeyID, delegationKeyID)
		if err != nil {
			return false, fmt.Errorf("failed to load delegation private key %s for role %s: %w", delegationKeyID, roleName, err)
		}

		delegationSigner, err := signature.LoadSigner(delegationPrivateKey, crypto.Hash(0))
		if err != nil {
			return false, fmt.Errorf("failed to create delegation signer for role %s: %w", roleName, err)
		}

		if _, err := repo.Targets(roleName).Sign(delegationSigner); err != nil {
			return false, fmt.Errorf("failed to sign %s metadata with key %s: %w", roleName, delegationKeyID, err)
		}
		logrus.Debugf("Successfully signed delegated role %s with key %s", roleName, delegationKeyID)
	}

	newDelegationFilename := fmt.Sprintf("%d.%s.json", delegation.Signed.Version, roleName)
	delegationPath = filepath.Join(tmpDir, newDelegationFilename)
	if err := repo.Targets(roleName).ToFile(delegationPath, true); err != nil {
		return false, fmt.Errorf("failed to save %s metadata: %w", roleName, err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, newDelegationFilename, delegationPath); err != nil {
		return false, fmt.Errorf("failed to upload %s metadata to S3: %w", roleName, err)
	}

	logrus.Debugf("Successfully removed %d artifacts from role %s", removedCount, roleName)
	return true, nil
}
