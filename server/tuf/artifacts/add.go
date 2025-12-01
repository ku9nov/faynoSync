package artifacts

import (
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"go.mongodb.org/mongo-driver/mongo"

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
	artifacts []Artifact,
	publishArtifacts bool,
	taskID string,
) error {
	bootstrapKey := "BOOTSTRAP_" + adminName
	bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
	if err == redis.Nil || bootstrapValue == "" {
		return fmt.Errorf("bootstrap not completed for admin %s", adminName)
	}

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
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, "1.root.json", rootPath); err != nil {
		if err2 := tuf_storage.DownloadMetadataFromS3(ctx, adminName, "root.json", rootPath); err2 != nil {
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

	timestampKeyIDs, ok := timestampRole["keyids"].([]interface{})
	if !ok || len(timestampKeyIDs) == 0 {
		return fmt.Errorf("invalid root metadata: no timestamp keyids")
	}

	timestampKeyID, ok := timestampKeyIDs[0].(string)
	if !ok {
		return fmt.Errorf("invalid root metadata: timestamp keyid is not a string")
	}

	targetsRole, ok := roles["targets"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid root metadata: no targets role")
	}

	targetsKeyIDs, ok := targetsRole["keyids"].([]interface{})
	if !ok || len(targetsKeyIDs) == 0 {
		return fmt.Errorf("invalid root metadata: no targets keyids")
	}

	targetsKeyID, ok := targetsKeyIDs[0].(string)
	if !ok {
		return fmt.Errorf("invalid root metadata: targets keyid is not a string")
	}

	timestampPrivateKey, err := signing.LoadPrivateKeyFromMongoDB(mongoDatabase, adminName, timestampKeyID, ctx)
	if err != nil {
		return fmt.Errorf("failed to load timestamp private key: %w", err)
	}

	timestampSigner, err := signature.LoadSigner(timestampPrivateKey, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("failed to create timestamp signer: %w", err)
	}

	targetsPrivateKey, err := signing.LoadPrivateKeyFromMongoDB(mongoDatabase, adminName, targetsKeyID, ctx)
	if err != nil {
		return fmt.Errorf("failed to load targets private key: %w", err)
	}

	targetsSigner, err := signature.LoadSigner(targetsPrivateKey, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("failed to create targets signer: %w", err)
	}

	signer := timestampSigner

	_, targetsFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, "targets")
	if err != nil {
		return fmt.Errorf("failed to find latest targets version: %w", err)
	}

	targetsPath := filepath.Join(tmpDir, targetsFilename)
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, targetsFilename, targetsPath); err != nil {
		return fmt.Errorf("failed to download targets metadata: %w", err)
	}

	targetsExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TARGETS_EXPIRATION_"+adminName, 365)
	targets := metadata.Targets(tuf_utils.HelperExpireIn(targetsExpiration))
	repo.SetTargets("targets", targets)
	if _, err := repo.Targets("targets").FromFile(targetsPath); err != nil {
		return fmt.Errorf("failed to load targets metadata: %w", err)
	}

	repo.Targets("targets").ClearSignatures()
	if _, err := repo.Targets("targets").Sign(targetsSigner); err != nil {
		return fmt.Errorf("failed to sign targets metadata: %w", err)
	}

	targetsVersion := repo.Targets("targets").Signed.Version
	correctTargetsFilename := fmt.Sprintf("%d.targets.json", targetsVersion)
	correctTargetsPath := filepath.Join(tmpDir, correctTargetsFilename)
	if err := repo.Targets("targets").ToFile(correctTargetsPath, true); err != nil {
		return fmt.Errorf("failed to save targets metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, correctTargetsFilename, correctTargetsPath); err != nil {
		return fmt.Errorf("failed to upload targets metadata to S3: %w", err)
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
	for roleName, roleArtifacts := range rolesArtifacts {
		if err := updateDelegatedRoleWithArtifacts(
			ctx, repo, roleName, roleArtifacts, adminName, redisClient, mongoDatabase, signer, tmpDir,
		); err != nil {
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
		snapshotKeyID := snapshotRole.KeyIDs[0]

		snapshotPrivateKey, err := signing.LoadPrivateKeyFromMongoDB(mongoDatabase, adminName, snapshotKeyID, ctx)
		if err != nil {
			return fmt.Errorf("failed to load snapshot private key: %w", err)
		}

		snapshotSigner, err := signature.LoadSigner(snapshotPrivateKey, crypto.Hash(0))
		if err != nil {
			return fmt.Errorf("failed to create snapshot signer: %w", err)
		}

		if err := updateSnapshotAndTimestamp(
			ctx, repo, updatedRoles, adminName, redisClient, mongoDatabase, signer, snapshotSigner, tmpDir,
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

	if delegations.SuccinctRoles != nil {

		roles := delegations.SuccinctRoles.GetRolesForTarget(artifactPath)
		if len(roles) == 0 {
			return "", fmt.Errorf("no role found for path: %s", artifactPath)
		}
		roleName := roles[0].Name
		logrus.Debugf("Calculated role for path %s using go-tuf GetRolesForTarget: %s", artifactPath, roleName)

		if strings.Contains(roleName, "--") {
			logrus.Warnf("Role name contains double minus (negative bin index): %s for path %s", roleName, artifactPath)
		}

		return roleName, nil
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
		for _, path := range role.Paths {
			if strings.HasPrefix(artifactPath, path) {
				return true
			}
		}
	}

	if len(role.PathHashPrefixes) > 0 {
		hash := fmt.Sprintf("%x", artifactPath)
		for _, prefix := range role.PathHashPrefixes {
			if strings.HasPrefix(hash, prefix) {
				return true
			}
		}
	}

	return false
}

func updateDelegatedRoleWithArtifacts(
	ctx context.Context,
	repo *repository.Type,
	roleName string,
	artifacts []Artifact,
	adminName string,
	redisClient *redis.Client,
	mongoDatabase *mongo.Database,
	signer signature.Signer,
	tmpDir string,
) error {

	_, delegationFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, roleName)
	isNewDelegation := err != nil

	binsExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "BINS_EXPIRATION_"+adminName, 90)
	delegationTargets := metadata.Targets(tuf_utils.HelperExpireIn(binsExpiration))
	repo.SetTargets(roleName, delegationTargets)

	if !isNewDelegation {
		logrus.Debugf("Loading existing delegation metadata for role %s from %s", roleName, delegationFilename)
		delegationPath := filepath.Join(tmpDir, delegationFilename)
		if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, delegationFilename, delegationPath); err != nil {
			return fmt.Errorf("failed to download %s metadata: %w", roleName, err)
		}

		if _, err := repo.Targets(roleName).FromFile(delegationPath); err != nil {
			return fmt.Errorf("failed to load %s metadata: %w", roleName, err)
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

	delegation.Signed.Expires = tuf_utils.HelperExpireIn(binsExpiration)

	delegation.ClearSignatures()

	if _, err := repo.Targets(roleName).Sign(signer); err != nil {
		return fmt.Errorf("failed to sign %s metadata: %w", roleName, err)
	}

	newDelegationFilename := fmt.Sprintf("%d.%s.json", delegation.Signed.Version, roleName)
	delegationPath := filepath.Join(tmpDir, newDelegationFilename)
	if err := repo.Targets(roleName).ToFile(delegationPath, true); err != nil {
		return fmt.Errorf("failed to save %s metadata: %w", roleName, err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, newDelegationFilename, delegationPath); err != nil {
		return fmt.Errorf("failed to upload %s metadata to S3: %w", roleName, err)
	}

	logrus.Debugf("Successfully updated role %s with %d artifacts", roleName, len(artifacts))
	return nil
}

func updateSnapshotAndTimestamp(
	ctx context.Context,
	repo *repository.Type,
	updatedRoles []string,
	adminName string,
	redisClient *redis.Client,
	mongoDatabase *mongo.Database,
	timestampSigner signature.Signer,
	snapshotSigner signature.Signer,
	tmpDir string,
) error {

	_, snapshotFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, "snapshot")
	if err != nil {
		return fmt.Errorf("failed to find latest snapshot version: %w", err)
	}

	snapshotPath := filepath.Join(tmpDir, snapshotFilename)
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, snapshotFilename, snapshotPath); err != nil {
		return fmt.Errorf("failed to download snapshot metadata: %w", err)
	}

	snapshotExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "SNAPSHOT_EXPIRATION_"+adminName, 7)
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

	for _, roleName := range updatedRoles {
		delegation := repo.Targets(roleName)
		metaFilename := fmt.Sprintf("%s.json", roleName)
		snapshotMeta[metaFilename] = metadata.MetaFile(int64(delegation.Signed.Version))
	}

	targets := repo.Targets("targets")
	if targets != nil {
		snapshotMeta["targets.json"] = metadata.MetaFile(int64(targets.Signed.Version))
	}

	repo.Snapshot().Signed.Version++

	repo.Snapshot().Signed.Expires = tuf_utils.HelperExpireIn(snapshotExpiration)

	repo.Snapshot().ClearSignatures()

	if _, err := repo.Snapshot().Sign(snapshotSigner); err != nil {
		return fmt.Errorf("failed to sign snapshot metadata: %w", err)
	}

	snapshotFilename = fmt.Sprintf("%d.snapshot.json", repo.Snapshot().Signed.Version)
	snapshotPath = filepath.Join(tmpDir, snapshotFilename)
	if err := repo.Snapshot().ToFile(snapshotPath, true); err != nil {
		return fmt.Errorf("failed to save snapshot metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, snapshotFilename, snapshotPath); err != nil {
		return fmt.Errorf("failed to upload snapshot metadata to S3: %w", err)
	}

	if err := updateTimestamp(ctx, repo, adminName, redisClient, timestampSigner, tmpDir); err != nil {
		return fmt.Errorf("failed to update timestamp: %w", err)
	}

	return nil
}

func updateTimestamp(
	ctx context.Context,
	repo *repository.Type,
	adminName string,
	redisClient *redis.Client,
	signer signature.Signer,
	tmpDir string,
) error {
	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, "timestamp.json", timestampPath); err != nil {
		logrus.Debug("Timestamp metadata not found, creating new one")
	}

	timestampExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TIMESTAMP_EXPIRATION_"+adminName, 1)
	timestamp := metadata.Timestamp(tuf_utils.HelperExpireIn(timestampExpiration))
	repo.SetTimestamp(timestamp)

	if _, err := os.Stat(timestampPath); err == nil {
		if _, err := repo.Timestamp().FromFile(timestampPath); err != nil {
			logrus.Warnf("Failed to load timestamp metadata: %v, creating new one", err)
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

	repo.Timestamp().Signed.Expires = tuf_utils.HelperExpireIn(timestampExpiration)

	repo.Timestamp().ClearSignatures()

	if _, err := repo.Timestamp().Sign(signer); err != nil {
		return fmt.Errorf("failed to sign timestamp metadata: %w", err)
	}

	timestampPath = filepath.Join(tmpDir, "timestamp.json")
	if err := repo.Timestamp().ToFile(timestampPath, true); err != nil {
		return fmt.Errorf("failed to save timestamp metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, "timestamp.json", timestampPath); err != nil {
		return fmt.Errorf("failed to upload timestamp metadata to S3: %w", err)
	}

	return nil
}

func getArtifactPaths(artifacts []Artifact) []string {
	paths := make([]string, len(artifacts))
	for i, artifact := range artifacts {
		paths[i] = artifact.Path
	}
	return paths
}
