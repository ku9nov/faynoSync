package metadata

import (
	"context"
	"encoding/json"
	"errors"
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

// bootstrapOnlineRoles creates online roles (targets, snapshot, timestamp) and delegations
func BootstrapOnlineRoles(
	redisClient *redis.Client,
	taskID string,
	adminName string,
	appName string,
	payload *models.BootstrapPayload,
) error {
	return BootstrapOnlineRolesWithContext(context.Background(), redisClient, taskID, adminName, appName, payload)
}

// BootstrapOnlineRolesWithContext creates online roles with caller-provided context.
func BootstrapOnlineRolesWithContext(
	ctx context.Context,
	redisClient *redis.Client,
	taskID string,
	adminName string,
	appName string,
	payload *models.BootstrapPayload,
) error {
	logrus.Debugf("Starting bootstrap online roles creation for admin: %s, app: %s", adminName, appName)

	// Create temporary directory for storing metadata
	tmpDir, err := os.MkdirTemp("", "tmp")
	if err != nil {
		logrus.Errorf("Failed to create temporary directory: %v", err)
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Initialize repository
	repo := repository.New()

	// Load root metadata from payload
	rootMetadata, exists := payload.Metadata["root"]
	if !exists {
		logrus.Error("Root metadata not found in payload")
		return fmt.Errorf("root metadata not found in payload")
	}

	// Save root metadata to temporary file first
	rootJSON, err := json.Marshal(rootMetadata)
	if err != nil {
		logrus.Errorf("Failed to marshal root metadata: %v", err)
		return fmt.Errorf("failed to marshal root metadata: %w", err)
	}
	logrus.Debugf("Tmp dir will be used to store metadata: %s", tmpDir)
	rootPath := filepath.Join(tmpDir, "1.root.json")
	if err := os.WriteFile(rootPath, rootJSON, 0644); err != nil {
		logrus.Errorf("Failed to write root metadata to file: %v", err)
		return fmt.Errorf("failed to write root metadata to file: %w", err)
	}

	expires, err := time.Parse(time.RFC3339Nano, rootMetadata.Signed.Expires)
	if err != nil {
		logrus.Errorf("Failed to parse root expiration: %v", err)
		return fmt.Errorf("invalid root expiration format: %w", err)
	}
	if !expires.After(time.Now().UTC()) {
		return fmt.Errorf("root expiration is in the past")
	}
	tempRoot := metadata.Root(expires)
	repo.SetRoot(tempRoot)

	_, err = repo.Root().FromFile(rootPath)
	if err != nil {
		logrus.Errorf("Failed to load root metadata from file: %v", err)
		return fmt.Errorf("failed to load root metadata from file: %w", err)
	}

	err = repo.Root().VerifyDelegate("root", repo.Root())
	if err != nil {
		logrus.Errorf("Failed to verify root metadata: %v", err)
		return fmt.Errorf("failed to verify root metadata: %w", err)
	} else {
		logrus.Debug("Successfully verified root metadata")
	}

	keySuffix := adminName + "_" + appName
	targetsExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TARGETS_EXPIRATION_"+keySuffix, payload.Settings.Roles.Targets.Expiration)
	snapshotExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "SNAPSHOT_EXPIRATION_"+keySuffix, payload.Settings.Roles.Snapshot.Expiration)
	timestampExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TIMESTAMP_EXPIRATION_"+keySuffix, payload.Settings.Roles.Timestamp.Expiration)

	targetsRole, ok := rootMetadata.Signed.Roles["targets"]
	if !ok || len(targetsRole.KeyIDs) == 0 {
		logrus.Error("Failed to find targets role keys in root metadata")
		return fmt.Errorf("failed to find targets role keys in root metadata")
	}
	for _, keyID := range targetsRole.KeyIDs {
		if _, keyExists := rootMetadata.Signed.Keys[keyID]; !keyExists {
			logrus.Errorf("Targets key %s not found in root metadata", keyID)
			return fmt.Errorf("targets key %s not found in root metadata", keyID)
		}
	}
	targetsSigners, err := buildOnlineRoleSigners(targetsRole.KeyIDs, targetsRole.Threshold, "targets")
	if err != nil {
		logrus.Errorf("Failed to build targets signers: %v", err)
		return fmt.Errorf("failed to build targets signers: %w", err)
	}
	logrus.Debugf("Using %d online key(s) for targets (threshold %d)", len(targetsSigners), targetsRole.Threshold)

	snapshotRole, ok := rootMetadata.Signed.Roles["snapshot"]
	if !ok || len(snapshotRole.KeyIDs) == 0 {
		logrus.Error("Failed to find snapshot role keys in root metadata")
		return fmt.Errorf("failed to find snapshot role keys in root metadata")
	}
	for _, keyID := range snapshotRole.KeyIDs {
		if _, keyExists := rootMetadata.Signed.Keys[keyID]; !keyExists {
			logrus.Errorf("Snapshot key %s not found in root metadata", keyID)
			return fmt.Errorf("snapshot key %s not found in root metadata", keyID)
		}
	}
	snapshotSigners, err := buildOnlineRoleSigners(snapshotRole.KeyIDs, snapshotRole.Threshold, "snapshot")
	if err != nil {
		logrus.Errorf("Failed to build snapshot signers: %v", err)
		return fmt.Errorf("failed to build snapshot signers: %w", err)
	}
	logrus.Debugf("Using %d online key(s) for snapshot (threshold %d)", len(snapshotSigners), snapshotRole.Threshold)

	timestampRole, ok := rootMetadata.Signed.Roles["timestamp"]
	if !ok || len(timestampRole.KeyIDs) == 0 {
		logrus.Error("Failed to find timestamp role keys in root metadata")
		return fmt.Errorf("failed to find timestamp role keys in root metadata")
	}
	for _, keyID := range timestampRole.KeyIDs {
		if _, keyExists := rootMetadata.Signed.Keys[keyID]; !keyExists {
			logrus.Errorf("Timestamp key %s not found in root metadata", keyID)
			return fmt.Errorf("timestamp key %s not found in root metadata", keyID)
		}
	}
	timestampSigners, err := buildOnlineRoleSigners(timestampRole.KeyIDs, timestampRole.Threshold, "timestamp")
	if err != nil {
		logrus.Errorf("Failed to build timestamp signers: %v", err)
		return fmt.Errorf("failed to build timestamp signers: %w", err)
	}
	logrus.Debugf("Using %d online key(s) for timestamp (threshold %d)", len(timestampSigners), timestampRole.Threshold)

	targets := metadata.Targets(tuf_utils.HelperExpireIn(targetsExpiration))
	repo.SetTargets("targets", targets)

	snapshot := metadata.Snapshot(tuf_utils.HelperExpireIn(snapshotExpiration))
	repo.SetSnapshot(snapshot)

	timestamp := metadata.Timestamp(tuf_utils.HelperExpireIn(timestampExpiration))
	repo.SetTimestamp(timestamp)

	if payload.Settings.Roles.Delegations != nil {
		logrus.Debug("Creating custom delegations")
		customDelegations := payload.Settings.Roles.Delegations

		delegationKeys := make(map[string]*metadata.Key)
		for keyID, tufKey := range customDelegations.Keys {
			delegationKey, err := decodeAndValidateMetadataKey(tufKey, keyID)
			if err != nil {
				logrus.Errorf("Invalid delegation key %s: %v", keyID, err)
				return fmt.Errorf("invalid delegation key %s: %w", keyID, err)
			}

			delegationKeys[keyID] = delegationKey
			logrus.Debugf("Added delegation key: %s", keyID)
		}

		delegatedRoles := make([]metadata.DelegatedRole, 0, len(customDelegations.Roles))
		for _, tufRole := range customDelegations.Roles {
			roleExpiration := 90

			// add role-specific expiration logic here?
			for _, roleKeyID := range tufRole.KeyIDs {
				if _, exists := delegationKeys[roleKeyID]; !exists {
					logrus.Errorf("Delegated role %s references missing key %s in delegations.keys", tufRole.Name, roleKeyID)
					return fmt.Errorf("delegated role %s references key %s that is not present in delegations.keys", tufRole.Name, roleKeyID)
				}
			}

			delegatedRole := metadata.DelegatedRole{
				Name:        tufRole.Name,
				Terminating: tufRole.Terminating,
				KeyIDs:      tufRole.KeyIDs,
				Threshold:   tufRole.Threshold,
				Paths:       tufRole.Paths,
			}

			delegatedRoles = append(delegatedRoles, delegatedRole)
			logrus.Debugf("Added delegated role: %s with paths: %v", tufRole.Name, tufRole.Paths)

			// Save role expiration to Redis (using default for now, can be extended)
			expirationKey := fmt.Sprintf("%s_EXPIRATION_%s_%s", tufRole.Name, adminName, appName)
			if err := redisClient.Set(ctx, expirationKey, roleExpiration, 0).Err(); err != nil {
				logrus.Warnf("Failed to save expiration for role %s: %v", tufRole.Name, err)
			}
		}

		targets.Signed.Delegations = &metadata.Delegations{
			Keys:  delegationKeys,
			Roles: delegatedRoles,
		}

		repo.SetTargets("targets", targets)

		// Create metadata files for each delegated role
		for i := range delegatedRoles {
			roleName := delegatedRoles[i].Name
			roleTargets := metadata.Targets(tuf_utils.HelperExpireIn(90)) // Default expiration, can be customized
			roleTargets.Signed.Version = 1

			repo.SetTargets(roleName, roleTargets)

			roleKeyIDs := delegatedRoles[i].KeyIDs
			if len(roleKeyIDs) == 0 {
				logrus.Errorf("No key IDs found for delegated role %s", roleName)
				return fmt.Errorf("no key IDs found for delegated role %s", roleName)
			}

			usedKeyIDs, err := signing.LoadAndSignDelegation(
				roleName,
				roleKeyIDs,
				delegatedRoles[i].Threshold,
				func(s signature.Signer, delegationKeyID string) error {
					_, signErr := repo.Targets(roleName).Sign(s)
					return signErr
				},
			)
			if err != nil {
				logrus.Errorf("Failed to sign delegated role metadata %s: %v", roleName, err)
				if strings.Contains(err.Error(), "failed to load "+roleName+" private key") {
					return fmt.Errorf("failed to load delegation private key for role %s: %w", roleName, err)
				}
				return fmt.Errorf("failed to sign delegated role metadata %s: %w", roleName, err)
			}
			for _, delegationKeyID := range usedKeyIDs {
				logrus.Debugf("Successfully signed delegated role metadata %s with key %s", roleName, delegationKeyID)
			}

			filename := fmt.Sprintf("1.%s.json", roleName)
			rolePath := filepath.Join(tmpDir, filename)
			if err := repo.Targets(roleName).ToFile(rolePath, true); err != nil {
				logrus.Errorf("Failed to persist delegated role metadata %s: %v", roleName, err)
				return fmt.Errorf("failed to persist delegated role metadata %s: %w", roleName, err)
			}
			roleMF, err := metaFileFromPath(rolePath, 1)
			if err != nil {
				return fmt.Errorf("failed to compute hash for delegated role %s: %w", roleName, err)
			}
			snapshot.Signed.Meta[fmt.Sprintf("%s.json", roleName)] = roleMF
			logrus.Debugf("Successfully persisted delegated role metadata: %s", filename)

			if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, filename, rolePath); err != nil {
				logrus.Errorf("Failed to upload delegated role metadata %s to S3: %v", roleName, err)
				return fmt.Errorf("failed to upload delegated role metadata %s to S3: %w", roleName, err)
			}
		}

		logrus.Debug("Custom delegations created successfully")
	}

	timestampMeta := repo.Timestamp().Signed.Meta
	if timestampMeta == nil {
		timestampMeta = make(map[string]*metadata.MetaFiles)
		repo.Timestamp().Signed.Meta = timestampMeta
	}

	for i, s := range targetsSigners {
		if _, err := repo.Targets("targets").Sign(s); err != nil {
			logrus.Errorf("Failed to sign targets metadata with key %d: %v", i+1, err)
			return fmt.Errorf("failed to sign targets metadata with key %d: %w", i+1, err)
		}
	}
	logrus.Debug("Successfully signed targets metadata")

	// Write signed targets now so we can compute its hash for snapshot.
	bootstrapTargetsFilename := fmt.Sprintf("%d.targets.json", targets.Signed.Version)
	bootstrapTargetsPath := filepath.Join(tmpDir, bootstrapTargetsFilename)
	if err := repo.Targets("targets").ToFile(bootstrapTargetsPath, true); err != nil {
		return fmt.Errorf("failed to write targets for hash computation: %w", err)
	}
	targetsMF, err := metaFileFromPath(bootstrapTargetsPath, int64(targets.Signed.Version))
	if err != nil {
		return fmt.Errorf("failed to compute targets hash: %w", err)
	}
	snapshot.Signed.Meta["targets.json"] = targetsMF

	for i, s := range snapshotSigners {
		if _, err := repo.Snapshot().Sign(s); err != nil {
			logrus.Errorf("Failed to sign snapshot metadata with key %d: %v", i+1, err)
			return fmt.Errorf("failed to sign snapshot metadata with key %d: %w", i+1, err)
		}
	}
	logrus.Debug("Successfully signed snapshot metadata")

	// Write signed snapshot now so we can compute its hash for timestamp.
	bootstrapSnapshotFilename := fmt.Sprintf("%d.snapshot.json", snapshot.Signed.Version)
	bootstrapSnapshotPath := filepath.Join(tmpDir, bootstrapSnapshotFilename)
	if err := repo.Snapshot().ToFile(bootstrapSnapshotPath, true); err != nil {
		return fmt.Errorf("failed to write snapshot for hash computation: %w", err)
	}
	snapshotMF, err := metaFileFromPath(bootstrapSnapshotPath, int64(snapshot.Signed.Version))
	if err != nil {
		return fmt.Errorf("failed to compute snapshot hash: %w", err)
	}
	timestampMeta["snapshot.json"] = snapshotMF
	logrus.Debugf("Timestamp metadata references snapshot version %d", snapshot.Signed.Version)

	for i, s := range timestampSigners {
		if _, err := repo.Timestamp().Sign(s); err != nil {
			logrus.Errorf("Failed to sign timestamp metadata with key %d: %v", i+1, err)
			return fmt.Errorf("failed to sign timestamp metadata with key %d: %w", i+1, err)
		}
	}
	logrus.Debug("Successfully signed timestamp metadata")

	if err := repo.Root().ToFile(rootPath, true); err != nil {
		logrus.Errorf("Failed to persist root metadata: %v", err)
		return fmt.Errorf("failed to persist root metadata: %w", err)
	}
	logrus.Debugf("Successfully persisted root metadata: 1.root.json")

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, "1.root.json", rootPath); err != nil {
		logrus.Errorf("Failed to upload root metadata to S3: %v", err)
		return fmt.Errorf("failed to upload root metadata to S3: %w", err)
	}

	targetsFilename := fmt.Sprintf("%d.targets.json", targets.Signed.Version)
	targetsPath := filepath.Join(tmpDir, targetsFilename)
	if err := repo.Targets("targets").ToFile(targetsPath, true); err != nil {
		logrus.Errorf("Failed to persist targets metadata: %v", err)
		return fmt.Errorf("failed to persist targets metadata: %w", err)
	}
	logrus.Debugf("Successfully persisted targets metadata: %s", targetsFilename)

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, targetsFilename, targetsPath); err != nil {
		logrus.Errorf("Failed to upload targets metadata to S3: %v", err)
		return fmt.Errorf("failed to upload targets metadata to S3: %w", err)
	}

	snapshotFilename := fmt.Sprintf("%d.snapshot.json", snapshot.Signed.Version)
	snapshotPath := filepath.Join(tmpDir, snapshotFilename)
	if err := repo.Snapshot().ToFile(snapshotPath, true); err != nil {
		logrus.Errorf("Failed to persist snapshot metadata: %v", err)
		return fmt.Errorf("failed to persist snapshot metadata: %w", err)
	}
	logrus.Debugf("Successfully persisted snapshot metadata: %s", snapshotFilename)

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, snapshotFilename, snapshotPath); err != nil {
		logrus.Errorf("Failed to upload snapshot metadata to S3: %v", err)
		return fmt.Errorf("failed to upload snapshot metadata to S3: %w", err)
	}

	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	if err := repo.Timestamp().ToFile(timestampPath, true); err != nil {
		logrus.Errorf("Failed to persist timestamp metadata: %v", err)
		return fmt.Errorf("failed to persist timestamp metadata: %w", err)
	}
	logrus.Debugf("Successfully persisted timestamp metadata: timestamp.json")

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, "timestamp.json", timestampPath); err != nil {
		logrus.Errorf("Failed to upload timestamp metadata to S3: %v", err)
		return fmt.Errorf("failed to upload timestamp metadata to S3: %w", err)
	}

	logrus.Debug("Bootstrap online roles creation completed")
	return nil
}

func PostMetadataRotate(c *gin.Context, redisClient *redis.Client) {
	updateCtx, ok := validateMetadataUpdatePreconditions(c, redisClient)
	if !ok {
		return
	}
	ctx := updateCtx.Ctx
	adminName := updateCtx.AdminName
	appName := updateCtx.AppName
	keySuffix := updateCtx.KeySuffix
	bootstrapValue := updateCtx.BootstrapValue

	var payload models.MetadataPostPayload
	var err error
	if err := c.ShouldBindJSON(&payload); err != nil {
		logrus.Errorf("Failed to parse metadata payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid payload format: %v", err),
		})
		return
	}

	rootMetadata, exists := payload.Metadata["root"]
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Root metadata is required",
		})
		return
	}

	tmpDir, err := os.MkdirTemp("", "tmp-metadata-*")
	if err != nil {
		logrus.Errorf("Failed to create temporary directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer os.RemoveAll(tmpDir)

	newRootJSON, err := json.Marshal(rootMetadata)
	if err != nil {
		logrus.Errorf("Failed to marshal new root metadata: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to process root metadata",
		})
		return
	}

	newRootPath := filepath.Join(tmpDir, "new_root.json")
	if err := os.WriteFile(newRootPath, newRootJSON, 0644); err != nil {
		logrus.Errorf("Failed to write new root metadata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	currentRootPath := filepath.Join(tmpDir, "current_root.json")
	_, currentRootFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "root")
	if err != nil {
		if err2 := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "root.json", currentRootPath); err2 != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Failed to load current root metadata from storage",
			})
			return
		}
	} else {
		if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, currentRootFilename, currentRootPath); err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Failed to load current root metadata from storage",
			})
			return
		}
	}

	repo := repository.New()
	currentRoot := metadata.Root(time.Now().Add(365 * 24 * time.Hour))
	repo.SetRoot(currentRoot)
	if _, err := repo.Root().FromFile(currentRootPath); err != nil {
		logrus.Errorf("Failed to load current root metadata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to load current root metadata",
		})
		return
	}

	newRoot := metadata.Root(time.Now().Add(365 * 24 * time.Hour))
	newRepo := repository.New()
	newRepo.SetRoot(newRoot)
	if _, err := newRepo.Root().FromFile(newRootPath); err != nil {
		logrus.Errorf("Failed to load new root metadata: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to load new root metadata",
		})
		return
	}

	currentRootMeta := repo.Root()
	newRootMeta := newRepo.Root()
	if err := verifyNewRootMetadata(currentRootMeta, newRootMeta); err != nil {

		if errors.Is(err, errRootSignaturesMissing) {
			taskID := uuid.New().String()
			logrus.Debugf("Generated task_id: %s", taskID)
			if err := stageMetadataForSigning(ctx, redisClient, keySuffix, "ROOT", newRootJSON, taskID); err != nil {
				logrus.Errorf("Failed to stage root metadata for signing: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to stage root metadata for signing",
				})
				return
			}
			logrus.Infof("Root metadata v%d saved for offline signing", newRepo.Root().Signed.Version)

			taskName := tasks.TaskNameMetadataUpdate
			tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStatePending, &tasks.TaskResult{
				Task: &taskName,
			})

			c.JSON(http.StatusOK, models.MetadataPostResponse{
				Data: models.MetadataPostData{
					TaskID:     taskID,
					LastUpdate: time.Now(),
				},
				Message: "Metadata Update Processed",
			})
			return
		}

		logrus.Errorf("Failed to verify new root metadata: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Metadata Update Failed",
			"error":   fmt.Sprintf("Failed to verify the trust: %v", err),
		})
		return
	}

	if err := finalizeRootMetadataUpdate(ctx, newRepo, adminName, appName, tmpDir, false, bootstrapValue, redisClient); err != nil {
		logrus.Errorf("Failed to finalize root metadata update: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Metadata Update Failed",
			"error":   fmt.Sprintf("Failed to finalize update: %v", err),
		})
		return
	}

	taskID := uuid.New().String()
	logrus.Debugf("Generated task_id: %s", taskID)

	taskName := tasks.TaskNameMetadataUpdate
	tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStatePending, &tasks.TaskResult{
		Task: &taskName,
	})

	successStatus := true
	message := "Metadata update completed successfully"
	tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateSuccess, &tasks.TaskResult{
		Task:    &taskName,
		Status:  &successStatus,
		Message: &message,
	})

	c.JSON(http.StatusOK, models.MetadataPostResponse{
		Data: models.MetadataPostData{
			TaskID:     taskID,
			LastUpdate: time.Now(),
		},
		Message: "Metadata Update Processed",
	})
}

func PostMetadataDelegatedRotate(c *gin.Context, redisClient *redis.Client) {
	updateCtx, ok := validateMetadataUpdatePreconditions(c, redisClient)
	if !ok {
		return
	}
	ctx := updateCtx.Ctx
	adminName := updateCtx.AdminName
	appName := updateCtx.AppName
	keySuffix := updateCtx.KeySuffix

	var payload models.MetadataDelegatedRotatePayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		logrus.Errorf("Failed to parse delegated rotate payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid payload format: %v", err),
		})
		return
	}

	roleName := strings.TrimSpace(payload.Role)
	if roleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is required"})
		return
	}
	if isTopLevelRole(roleName) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "delegated rotation endpoint supports delegated roles only",
		})
		return
	}

	delegatorRole := strings.TrimSpace(payload.Delegator)
	if delegatorRole == "" {
		delegatorRole = "targets"
	}
	if delegatorRole != "targets" && isTopLevelRole(delegatorRole) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "delegator must be targets or a delegated role",
		})
		return
	}

	targetsRaw, hasTargets := payload.Metadata["targets"]
	delegatedRaw, hasDelegated := payload.Metadata[roleName]
	if !hasTargets && !hasDelegated {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "metadata must contain at least one of: targets or delegated role metadata",
		})
		return
	}

	var targetsMetaForDelegatorCheck *metadata.Metadata[metadata.TargetsType]
	if hasTargets {
		targetsEnvelope, targetsMeta, err := validateTargetsMetadataForStaging(targetsRaw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Metadata Update Failed",
				"error":   fmt.Sprintf("Invalid targets metadata: %v", err),
			})
			return
		}

		version, err := getTargetsSignedVersion(targetsEnvelope)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Metadata Update Failed",
				"error":   fmt.Sprintf("Invalid targets metadata: %v", err),
			})
			return
		}

		trustedTargets, err := loadTrustedTargetsMetadataFromS3(ctx, adminName, appName, "targets")
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"message": "Metadata Update Failed",
				"error":   fmt.Sprintf("Failed to load trusted targets metadata: %v", err),
			})
			return
		}
		if version <= int64(trustedTargets.Signed.Version) {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Metadata Update Failed",
				"error":   fmt.Sprintf("targets version must be greater than trusted version %d", trustedTargets.Signed.Version),
			})
			return
		}

		targetsMetaForDelegatorCheck = targetsMeta
	}

	if hasDelegated {
		delegatedEnvelope, _, err := validateTargetsMetadataForStaging(delegatedRaw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Metadata Update Failed",
				"error":   fmt.Sprintf("Invalid delegated metadata for role %s: %v", roleName, err),
			})
			return
		}

		version, err := getTargetsSignedVersion(delegatedEnvelope)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Metadata Update Failed",
				"error":   fmt.Sprintf("Invalid delegated metadata for role %s: %v", roleName, err),
			})
			return
		}

		trustedDelegated, err := loadTrustedTargetsMetadataFromS3(ctx, adminName, appName, roleName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Metadata Update Failed",
				"error":   fmt.Sprintf("Delegated role lifecycle changes are deferred; failed to load trusted role %s: %v", roleName, err),
			})
			return
		}
		if version <= int64(trustedDelegated.Signed.Version) {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Metadata Update Failed",
				"error":   fmt.Sprintf("%s version must be greater than trusted version %d", roleName, trustedDelegated.Signed.Version),
			})
			return
		}

		delegatorMeta, err := loadTrustedTargetsMetadataFromS3(ctx, adminName, appName, delegatorRole)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Metadata Update Failed",
				"error":   fmt.Sprintf("Failed to load delegator metadata %s: %v", delegatorRole, err),
			})
			return
		}

		if err := ensureDelegatorAuthorizesRole(delegatorMeta, roleName); err != nil {
			// Allow one-request staging when the incoming targets metadata already updates delegations.
			if !(delegatorRole == "targets" && targetsMetaForDelegatorCheck != nil && ensureDelegatorAuthorizesRole(targetsMetaForDelegatorCheck, roleName) == nil) {
				c.JSON(http.StatusBadRequest, gin.H{
					"message": "Metadata Update Failed",
					"error":   fmt.Sprintf("Delegator %s does not authorize role %s: %v", delegatorRole, roleName, err),
				})
				return
			}
		}
	}

	taskID := uuid.New().String()
	taskName := tasks.TaskNameMetadataDelegation
	tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStatePending, &tasks.TaskResult{
		Task: &taskName,
	})
	cleanupRoles := make([]string, 0, 2)
	delegatedRoleUpper := strings.ToUpper(roleName)
	var stageErr error

	if hasTargets && hasDelegated {
		stageErr = stageMetadataBatchForSigning(ctx, redisClient, keySuffix, taskID, []stagedMetadataForSigning{
			{roleUpper: "TARGETS", metadataJSON: targetsRaw},
			{roleUpper: delegatedRoleUpper, metadataJSON: delegatedRaw},
		})
		cleanupRoles = append(cleanupRoles, "TARGETS", delegatedRoleUpper)
	} else {
		if hasTargets {
			if err := stageMetadataForSigning(ctx, redisClient, keySuffix, "TARGETS", targetsRaw, taskID); err != nil {
				stageErr = err
			}
			cleanupRoles = append(cleanupRoles, "TARGETS")
		}
		if stageErr == nil && hasDelegated {
			if err := stageMetadataForSigning(ctx, redisClient, keySuffix, delegatedRoleUpper, delegatedRaw, taskID); err != nil {
				stageErr = err
			}
			cleanupRoles = append(cleanupRoles, delegatedRoleUpper)
		}
	}

	if stageErr != nil {
		if err := cleanupStagedMetadataForSigning(ctx, redisClient, keySuffix, cleanupRoles); err != nil {
			logrus.Warnf("Failed to cleanup staged metadata for task %s: %v", taskID, err)
		}
		status := false
		stageErrMsg := stageErr.Error()
		tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, &tasks.TaskResult{
			Task:   &taskName,
			Status: &status,
			Error:  &stageErrMsg,
		})

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Metadata Update Failed",
			"error":   stageErrMsg,
		})
		return
	}

	c.JSON(http.StatusOK, models.MetadataPostResponse{
		Data: models.MetadataPostData{
			TaskID:     taskID,
			LastUpdate: time.Now(),
		},
		Message: "Metadata rotation staged for signing",
	})
}

func GetMetadataSign(c *gin.Context, redisClient *redis.Client) {
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
	if err := tuf_utils.ValidateAppName(appName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if redisClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Redis client is not available",
		})
		return
	}

	ctx := context.Background()
	keySuffix := adminName + "_" + appName

	bootstrapKey := "BOOTSTRAP_" + keySuffix
	bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
	if err == redis.Nil || bootstrapValue == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "No metadata pending signing available",
			"error":   fmt.Sprintf("Requires bootstrap started. State: %s", bootstrapValue),
		})
		return
	}

	isSigningState := strings.HasPrefix(bootstrapValue, "signing-")
	isCompleted := !strings.HasPrefix(bootstrapValue, "pre-") && !isSigningState

	if !isSigningState && !isCompleted {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "No metadata pending signing available",
			"error":   fmt.Sprintf("Requires bootstrap started. State: %s", bootstrapValue),
		})
		return
	}

	// Search for all signing keys: ROOT_SIGNING, TARGETS_SIGNING, etc.
	// Format: {ROLE}_SIGNING_{adminName}_{appName}
	// TODO: Add delegated roles (?)
	possibleRoles := []string{"ROOT", "TARGETS", "SNAPSHOT", "TIMESTAMP"}
	metadataResponse := make(map[string]interface{})

	for _, role := range possibleRoles {
		signingKey := fmt.Sprintf("%s_SIGNING_%s", role, keySuffix)
		signingValue, err := redisClient.Get(ctx, signingKey).Result()
		if err == nil && signingValue != "" {
			var metadataJSON map[string]interface{}
			if err := json.Unmarshal([]byte(signingValue), &metadataJSON); err != nil {
				logrus.Warnf("Failed to parse %s metadata from Redis: %v", role, err)
				continue
			}
			roleLower := strings.ToLower(role)
			metadataResponse[roleLower] = metadataJSON
			logrus.Debugf("Found %s metadata pending signing", role)
		}
	}

	// Also check for delegated roles (custom roles)
	// Search for keys matching pattern: *_SIGNING_{adminName}_{appName}
	pattern := "*_SIGNING_" + keySuffix
	var scanCursor uint64
	for {
		var batch []string
		var scanErr error
		batch, scanCursor, scanErr = redisClient.Scan(ctx, scanCursor, pattern, 100).Result()
		if scanErr != nil {
			logrus.Warnf("Failed to scan Redis for delegated signing keys: %v", scanErr)
			break
		}
		for _, key := range batch {
			parts := strings.Split(key, "_SIGNING_")
			if len(parts) == 2 {
				role := parts[0]
				roleUpper := strings.ToUpper(role)
				alreadyProcessed := false
				for _, pr := range possibleRoles {
					if roleUpper == pr {
						alreadyProcessed = true
						break
					}
				}
				if !alreadyProcessed {
					signingValue, err := redisClient.Get(ctx, key).Result()
					if err == nil && signingValue != "" {
						var metadataJSON map[string]interface{}
						if err := json.Unmarshal([]byte(signingValue), &metadataJSON); err != nil {
							logrus.Warnf("Failed to parse %s metadata from Redis: %v", role, err)
							continue
						}
						roleLower := strings.ToLower(role)
						metadataResponse[roleLower] = metadataJSON
						logrus.Debugf("Found delegated role %s metadata pending signing", role)
					}
				}
			}
		}
		if scanCursor == 0 {
			break
		}
	}

	if rootMetadata, hasRoot := metadataResponse["root"]; hasRoot {
		hasTargetsType := false
		if rootMap, ok := rootMetadata.(map[string]interface{}); ok {
			if signed, ok := rootMap["signed"].(map[string]interface{}); ok {
				if metadataType, ok := signed["_type"].(string); ok && metadataType == "targets" {
					hasTargetsType = true
				}
			}
		}

		trustedRoot, err := loadTrustedRootFromS3(ctx, adminName, appName)
		if err == nil && trustedRoot != nil {
			metadataResponse["trusted_root"] = trustedRoot
			logrus.Debug("Added trusted_root to response")
		} else {
			logrus.Debugf("Could not load trusted_root: %v", err)
		}
		if hasTargetsType {
			for _, meta := range metadataResponse {
				if metaMap, ok := meta.(map[string]interface{}); ok {
					if signed, ok := metaMap["signed"].(map[string]interface{}); ok {
						if metadataType, ok := signed["_type"].(string); ok && metadataType == "targets" {
							trustedTargets, err := loadTrustedTargetsFromS3(ctx, adminName, appName)
							if err == nil && trustedTargets != nil {
								metadataResponse["trusted_targets"] = trustedTargets
								logrus.Debug("Added trusted_targets to response")
							} else {
								logrus.Debugf("Could not load trusted_targets: %v", err)
							}
							break
						}
					}
				}
			}
		}
	}

	if len(metadataResponse) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"data":    nil,
			"message": "No metadata pending signing available",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"metadata": metadataResponse,
		},
		"message": "Metadata role(s) pending signing",
	})
}

func PostMetadataSign(c *gin.Context, redisClient *redis.Client) {
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
	if err := tuf_utils.ValidateAppName(appName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if redisClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Redis client is not available",
		})
		return
	}

	var payload models.MetadataSignPostPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		logrus.Errorf("Failed to parse metadata sign payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid payload format: %v", err),
		})
		return
	}

	ctx := context.Background()
	keySuffix := adminName + "_" + appName
	roleUpper := strings.ToUpper(payload.Role)

	bootstrapKey := "BOOTSTRAP_" + keySuffix
	bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
	if err == redis.Nil || bootstrapValue == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "No signing pending.",
			"error":   fmt.Sprintf("Requires bootstrap in signing state. State: %s", bootstrapValue),
		})
		return
	}

	isSigningState := strings.HasPrefix(bootstrapValue, "signing-")
	isCompleted := !strings.HasPrefix(bootstrapValue, "pre-") && !isSigningState

	if !isSigningState && !isCompleted {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "No signing pending.",
			"error":   fmt.Sprintf("Requires bootstrap in signing state. State: %s", bootstrapValue),
		})
		return
	}

	signingKey := fmt.Sprintf("%s_SIGNING_%s", roleUpper, keySuffix)
	metadataJSONStr, err := redisClient.Get(ctx, signingKey).Result()
	if err == redis.Nil || metadataJSONStr == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"message": fmt.Sprintf("No signatures pending for %s", payload.Role),
			"error":   fmt.Sprintf("No metadata found in signing process for role %s", payload.Role),
		})
		return
	}

	var metadataJSON map[string]interface{}
	if err := json.Unmarshal([]byte(metadataJSONStr), &metadataJSON); err != nil {
		logrus.Errorf("Failed to parse metadata from Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to parse metadata",
		})
		return
	}

	signedData, ok := metadataJSON["signed"].(map[string]interface{})
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid metadata format: missing 'signed' field",
		})
		return
	}

	metadataType, ok := signedData["_type"].(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid metadata format: missing '_type' field",
		})
		return
	}

	signatures, ok := metadataJSON["signatures"].([]interface{})
	if !ok {
		signatures = []interface{}{}
	}
	if err := ensureUniqueSignatureKeyIDs(signatures); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Signature Failed",
			"error":   err.Error(),
		})
		return
	}
	if metadataType != "root" && metadataType != "targets" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("signature validation not supported for metadata type %q", metadataType),
		})
		return
	}
	if err := ensureMetadataNotExpiredFromSigned(signedData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Signature Failed",
			"error":   err.Error(),
		})
		return
	}

	signatureExists := false
	for _, sig := range signatures {
		if sigMap, ok := sig.(map[string]interface{}); ok {
			if keyid, ok := sigMap["keyid"].(string); ok && keyid == payload.Signature.KeyID {
				signatureExists = true
				break
			}
		}
	}

	if !signatureExists {
		if err := validateIncomingMetadataSignature(ctx, adminName, appName, metadataType, payload.Role, payload.Signature.KeyID, payload.Signature.Sig, signedData, isSigningState); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Signature Failed",
				"error":   fmt.Sprintf("Invalid signature or unauthorized key: %v", err),
			})
			return
		}

		signatureMap := map[string]interface{}{
			"keyid": payload.Signature.KeyID,
			"sig":   payload.Signature.Sig,
		}
		signatures = append(signatures, signatureMap)
		metadataJSON["signatures"] = signatures
	}

	tmpDir, err := os.MkdirTemp("", "tmp-sign-*")
	if err != nil {
		logrus.Errorf("Failed to create temporary directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer os.RemoveAll(tmpDir)

	metadataPath := filepath.Join(tmpDir, fmt.Sprintf("%s.json", payload.Role))
	updatedMetadataJSON, err := json.Marshal(metadataJSON)
	if err != nil {
		logrus.Errorf("Failed to marshal updated metadata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process metadata"})
		return
	}
	if err := os.WriteFile(metadataPath, updatedMetadataJSON, 0644); err != nil {
		logrus.Errorf("Failed to write metadata to file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process metadata"})
		return
	}
	repo := repository.New()

	var thresholdReached bool
	var validationError error
	var currentSignatures int
	var requiredThreshold int
	var signedKeyIDs []string
	var requiredKeyIDs []string
	var oldKeyIDs []string
	var newKeyIDs []string
	var isRootRotation bool

	taskKey := fmt.Sprintf("%s_SIGNING_TASK_%s", roleUpper, keySuffix)
	taskIDStr, err := redisClient.Get(ctx, taskKey).Result()
	var taskID string
	if err == redis.Nil || taskIDStr == "" {
		taskID = uuid.New().String()
		logrus.Debugf("Generated new task_id: %s", taskID)
		if setErr := redisClient.Set(ctx, taskKey, taskID, stagedSigningDataTTL).Err(); setErr != nil {
			logrus.Warnf("Failed to persist signing task_id %s: %v", taskID, setErr)
		}
	} else {
		taskID = taskIDStr
		logrus.Debugf("Using existing task_id: %s", taskID)
	}

	switch metadataType {
	case "root":
		root := metadata.Root(time.Now().Add(365 * 24 * time.Hour))
		repo.SetRoot(root)
		if _, err := repo.Root().FromFile(metadataPath); err != nil {
			logrus.Errorf("Failed to load root metadata: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Failed to load root metadata: %v", err),
			})
			return
		}

		rootMeta := repo.Root()
		signatures := rootMeta.Signatures
		rootRole := rootMeta.Signed.Roles["root"]
		logrus.Infof("Root metadata v%d: signatures count=%d, threshold=%d, required keyids=%v",
			rootMeta.Signed.Version,
			len(signatures),
			rootRole.Threshold,
			rootRole.KeyIDs)

		sigKeyIDs := make([]string, 0, len(signatures))
		for _, sig := range signatures {
			sigKeyIDs = append(sigKeyIDs, sig.KeyID)
		}
		logrus.Infof("Signature key IDs: %v", sigKeyIDs)

		currentSignatures = len(signatures)
		requiredThreshold = rootRole.Threshold
		signedKeyIDs = sigKeyIDs
		requiredKeyIDs = rootRole.KeyIDs
		newKeyIDs = rootRole.KeyIDs

		if isSigningState {
			logrus.Debugf("Bootstrap signing: validating root against itself")
			if err := repo.Root().VerifyDelegate("root", repo.Root()); err != nil {
				logrus.Warnf("Bootstrap root validation failed: %v", err)
				validationError = err
				thresholdReached = false
			} else {
				logrus.Infof("Bootstrap root validation succeeded: threshold reached")
				thresholdReached = true
			}
		} else {
			logrus.Debugf("Metadata update: loading trusted root from S3")
			trustedRoot, err := loadTrustedRootFromS3(ctx, adminName, appName)
			if err == nil {
				trustedRootPath := filepath.Join(tmpDir, "trusted_root.json")
				trustedRootJSON, _ := json.Marshal(trustedRoot)
				if writeErr := os.WriteFile(trustedRootPath, trustedRootJSON, 0644); writeErr != nil {
					logrus.Warnf("Failed to persist trusted root locally: %v", writeErr)
					validationError = fmt.Errorf("trusted root is required for root rotation: %w", writeErr)
					thresholdReached = false
					break
				}

				trustedRepo := repository.New()
				trustedRootMeta := metadata.Root(time.Now().Add(365 * 24 * time.Hour))
				trustedRepo.SetRoot(trustedRootMeta)
				if _, parseErr := trustedRepo.Root().FromFile(trustedRootPath); parseErr == nil {

					trustedRootRole := trustedRepo.Root().Signed.Roles["root"]
					oldKeyIDs = trustedRootRole.KeyIDs
					isRootRotation = true

					logrus.Debugf("Validating new root against trusted root and itself")
					if err := verifyNewRootMetadata(trustedRepo.Root(), repo.Root()); err == nil {
						logrus.Infof("Root rotation verification succeeded: threshold reached with trusted and new root signatures")
						thresholdReached = true
					} else {
						logrus.Warnf("Root rotation verification failed: %v", err)
						thresholdReached = false
						validationError = err
					}
				} else {
					logrus.Warnf("Failed to load trusted root from file: %v", parseErr)
					validationError = fmt.Errorf("trusted root is required for root rotation: %w", parseErr)
					thresholdReached = false
				}
			} else {
				logrus.Warnf("Failed to load trusted root from S3: %v", err)
				validationError = fmt.Errorf("trusted root is required for root rotation: %w", err)
				thresholdReached = false
			}
		}

		if thresholdReached {
			logrus.Infof("Threshold reached for root metadata update - finalizing")
			if err := finalizeRootMetadataUpdate(ctx, repo, adminName, appName, tmpDir, isSigningState, bootstrapValue, redisClient); err != nil {
				logrus.Errorf("Failed to finalize root metadata: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to finalize metadata: %v", err),
				})
				return
			}
			if delErr := redisClient.Del(ctx, signingKey).Err(); delErr != nil {
				logrus.Warnf("Failed to clear signing key %s after finalization: %v", signingKey, delErr)
			}
			if delErr := redisClient.Del(ctx, taskKey).Err(); delErr != nil {
				logrus.Warnf("Failed to clear task key %s after finalization: %v", taskKey, delErr)
			}
			logrus.Infof("Root metadata update finalized and signing key cleared from Redis")
		} else {
			logrus.Infof("Threshold not reached - saving updated metadata back to Redis (error: %v)", validationError)
			updatedJSON, err := json.Marshal(metadataJSON)
			if err != nil {
				logrus.Errorf("Failed to marshal updated root metadata: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save signing progress"})
				return
			}
			if setErr := redisClient.Set(ctx, signingKey, string(updatedJSON), stagedSigningDataTTL).Err(); setErr != nil {
				logrus.Errorf("Failed to save signing progress for root: %v", setErr)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save signing progress"})
				return
			}
		}
	case "targets":
		targets := metadata.Targets(time.Now().Add(365 * 24 * time.Hour))
		repo.SetTargets(payload.Role, targets)
		if _, err := repo.Targets(payload.Role).FromFile(metadataPath); err != nil {
			logrus.Errorf("Failed to load targets metadata: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Failed to load targets metadata: %v", err),
			})
			return
		}

		_, targetsFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "targets")
		if err != nil {
			validationError = fmt.Errorf("failed to find trusted targets metadata: %w", err)
			thresholdReached = false
			break
		}
		targetsPath := filepath.Join(tmpDir, targetsFilename)
		if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, targetsFilename, targetsPath); err != nil {
			validationError = fmt.Errorf("failed to download trusted targets metadata: %w", err)
			thresholdReached = false
			break
		}
		trustedTargets := metadata.Targets(time.Now().Add(365 * 24 * time.Hour))
		trustedRepo := repository.New()
		trustedRepo.SetTargets("targets", trustedTargets)
		if _, err := trustedRepo.Targets("targets").FromFile(targetsPath); err != nil {
			validationError = fmt.Errorf("failed to load trusted targets metadata: %w", err)
			thresholdReached = false
			break
		}
		if payload.Role == "targets" {
			trustedRoleVersion := int64(trustedRepo.Targets("targets").Signed.Version)
			if int64(repo.Targets(payload.Role).Signed.Version) <= trustedRoleVersion {
				validationError = fmt.Errorf("version must be greater than trusted version %d", trustedRoleVersion)
				thresholdReached = false
				break
			}

			trustedRootMeta, loadErr := loadTrustedRootMetadataFromS3(ctx, adminName, appName)
			if loadErr != nil {
				validationError = fmt.Errorf("failed to load trusted root metadata: %w", loadErr)
				thresholdReached = false
				break
			}

			if err := trustedRootMeta.VerifyDelegate("targets", repo.Targets(payload.Role)); err != nil {
				validationError = err
				thresholdReached = false
			} else {
				thresholdReached = true
			}
		} else {
			trustedRole, loadErr := loadTrustedTargetsMetadataFromS3(ctx, adminName, appName, payload.Role)
			if loadErr != nil {
				validationError = fmt.Errorf("failed to load trusted delegated role %s: %w", payload.Role, loadErr)
				thresholdReached = false
				break
			}
			trustedRoleVersion := int64(trustedRole.Signed.Version)
			if int64(repo.Targets(payload.Role).Signed.Version) <= trustedRoleVersion {
				validationError = fmt.Errorf("version must be greater than trusted version %d", trustedRoleVersion)
				thresholdReached = false
				break
			}

			trustedRootMeta, loadErr := loadTrustedRootMetadataFromS3(ctx, adminName, appName)
			if loadErr != nil {
				validationError = fmt.Errorf("failed to load trusted root metadata: %w", loadErr)
				thresholdReached = false
				break
			}
			if !trustedRepo.Targets("targets").Signed.Expires.After(time.Now().UTC()) {
				validationError = fmt.Errorf("trusted targets metadata is expired at %s", trustedRepo.Targets("targets").Signed.Expires.UTC().Format(time.RFC3339))
				thresholdReached = false
				break
			}
			if err := trustedRootMeta.VerifyDelegate("targets", trustedRepo.Targets("targets")); err != nil {
				validationError = fmt.Errorf("trusted targets metadata signature verification failed: %w", err)
				thresholdReached = false
				break
			}

			if err := trustedRepo.Targets("targets").VerifyDelegate(payload.Role, repo.Targets(payload.Role)); err != nil {
				validationError = err
				thresholdReached = false
			} else {
				thresholdReached = true
			}
		}

		if thresholdReached {
			if err := finalizeTargetsMetadataUpdate(ctx, repo, payload.Role, adminName, appName, tmpDir, redisClient); err != nil {
				logrus.Errorf("Failed to finalize targets metadata: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to finalize metadata: %v", err),
				})
				return
			}

			if delErr := redisClient.Del(ctx, signingKey).Err(); delErr != nil {
				logrus.Warnf("Failed to clear signing key %s after finalization: %v", signingKey, delErr)
			}
			if delErr := redisClient.Del(ctx, taskKey).Err(); delErr != nil {
				logrus.Warnf("Failed to clear task key %s after finalization: %v", taskKey, delErr)
			}
		} else {
			updatedJSON, err := json.Marshal(metadataJSON)
			if err != nil {
				logrus.Errorf("Failed to marshal updated targets metadata: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save signing progress"})
				return
			}
			if setErr := redisClient.Set(ctx, signingKey, string(updatedJSON), stagedSigningDataTTL).Err(); setErr != nil {
				logrus.Errorf("Failed to save signing progress for %s: %v", payload.Role, setErr)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save signing progress"})
				return
			}
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Unsupported metadata type: %s", metadataType),
		})
		return
	}

	taskName := tasks.TaskNameSignMetadata
	tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStatePending, &tasks.TaskResult{
		Task: &taskName,
	})

	if thresholdReached {
		successStatus := true
		message := func() string {
			if metadataType == "root" && isSigningState {
				return "Bootstrap Finished"
			} else if metadataType == "root" {
				return "Metadata update finished"
			} else {
				return fmt.Sprintf("Role %s signing complete", payload.Role)
			}
		}()
		tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateSuccess, &tasks.TaskResult{
			Task:    &taskName,
			Status:  &successStatus,
			Message: &message,
		})
	} else {
		pendingMessage := func() string {
			if metadataType == "root" {
				if signedData["version"] != nil {
					return fmt.Sprintf("Root v%.0f is pending signatures", signedData["version"].(float64))
				}
				return "Root is pending signatures"
			} else {
				if signedData["version"] != nil {
					return fmt.Sprintf("%s v%.0f is pending signatures", payload.Role, signedData["version"].(float64))
				}
				return fmt.Sprintf("%s is pending signatures", payload.Role)
			}
		}()
		tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStatePending, &tasks.TaskResult{
			Task:    &taskName,
			Message: &pendingMessage,
		})
	}

	response := models.MetadataSignPostResponse{
		Data: models.MetadataSignData{
			TaskID:     taskID,
			LastUpdate: time.Now(),
		},
		Message: func() string {
			if thresholdReached {
				if metadataType == "root" && isSigningState {
					return "Bootstrap Finished"
				} else if metadataType == "root" {
					return "Metadata update finished"
				} else {
					return fmt.Sprintf("Role %s signing complete", payload.Role)
				}
			} else {
				if metadataType == "root" {
					if signedData["version"] != nil {
						return fmt.Sprintf("Root v%.0f is pending signatures", signedData["version"].(float64))
					}
					return "Root is pending signatures"
				} else {
					if signedData["version"] != nil {
						return fmt.Sprintf("%s v%.0f is pending signatures", payload.Role, signedData["version"].(float64))
					}
					return fmt.Sprintf("%s is pending signatures", payload.Role)
				}
			}
		}(),
	}

	if validationError != nil && !thresholdReached {
		// Build detailed error message with progress information
		errorMsg := fmt.Sprintf("Invalid signature or threshold not reached: %v", validationError)

		if metadataType == "root" {
			if isRootRotation {
				// For root rotation, we need threshold * 2 signatures total
				expectedTotal := requiredThreshold * 2

				oldKeySignatures := 0
				newKeySignatures := 0
				oldSignedKeys := make([]string, 0)
				newSignedKeys := make([]string, 0)

				for _, sigKeyID := range signedKeyIDs {
					isOldKey := false
					for _, oldKeyID := range oldKeyIDs {
						if sigKeyID == oldKeyID {
							isOldKey = true
							oldKeySignatures++
							oldSignedKeys = append(oldSignedKeys, sigKeyID)
							break
						}
					}
					if !isOldKey {
						for _, newKeyID := range newKeyIDs {
							if sigKeyID == newKeyID {
								newKeySignatures++
								newSignedKeys = append(newSignedKeys, sigKeyID)
								break
							}
						}
					}
				}

				remainingOld := requiredThreshold - oldKeySignatures
				remainingNew := requiredThreshold - newKeySignatures
				remainingTotal := remainingOld + remainingNew

				progressMsg := fmt.Sprintf("Progress: %d/%d signatures collected (%d old + %d new). %d more required (%d old + %d new).",
					currentSignatures, expectedTotal, oldKeySignatures, newKeySignatures, remainingTotal, remainingOld, remainingNew)
				errorMsg = fmt.Sprintf("%s %s", errorMsg, progressMsg)

				if len(oldSignedKeys) > 0 {
					errorMsg = fmt.Sprintf("%s Old keys signed: %v.", errorMsg, oldSignedKeys)
				}
				if len(newSignedKeys) > 0 {
					errorMsg = fmt.Sprintf("%s New keys signed: %v.", errorMsg, newSignedKeys)
				}

				missingOldKeys := make([]string, 0)
				for _, oldKeyID := range oldKeyIDs {
					found := false
					for _, sigKeyID := range signedKeyIDs {
						if oldKeyID == sigKeyID {
							found = true
							break
						}
					}
					if !found {
						missingOldKeys = append(missingOldKeys, oldKeyID)
					}
				}
				if len(missingOldKeys) > 0 && remainingOld > 0 {
					errorMsg = fmt.Sprintf("%s Missing old keys: %v.", errorMsg, missingOldKeys)
				}

				missingNewKeys := make([]string, 0)
				for _, newKeyID := range newKeyIDs {
					found := false
					for _, sigKeyID := range signedKeyIDs {
						if newKeyID == sigKeyID {
							found = true
							break
						}
					}
					if !found {
						missingNewKeys = append(missingNewKeys, newKeyID)
					}
				}
				if len(missingNewKeys) > 0 && remainingNew > 0 {
					errorMsg = fmt.Sprintf("%s Missing new keys: %v.", errorMsg, missingNewKeys)
				}
			} else {
				remaining := requiredThreshold - currentSignatures
				if remaining > 0 {
					progressMsg := fmt.Sprintf("Progress: %d/%d signatures collected. %d more signature(s) required.",
						currentSignatures, requiredThreshold, remaining)
					errorMsg = fmt.Sprintf("%s %s", errorMsg, progressMsg)

					if len(signedKeyIDs) > 0 {
						errorMsg = fmt.Sprintf("%s Signed keys: %v.", errorMsg, signedKeyIDs)
					}
					if len(requiredKeyIDs) > 0 {
						missingKeys := make([]string, 0)
						for _, reqKeyID := range requiredKeyIDs {
							found := false
							for _, sigKeyID := range signedKeyIDs {
								if reqKeyID == sigKeyID {
									found = true
									break
								}
							}
							if !found {
								missingKeys = append(missingKeys, reqKeyID)
							}
						}
						if len(missingKeys) > 0 {
							errorMsg = fmt.Sprintf("%s Missing keys: %v.", errorMsg, missingKeys)
						}
					}
				}
			}
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Signature Failed",
			"error":   errorMsg,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}
