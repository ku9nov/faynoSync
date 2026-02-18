package metadata

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
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
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
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
	cwd, err := os.Getwd()
	if err != nil {
		logrus.Errorf("Failed to get current working directory: %v", err)
		return fmt.Errorf("failed to get current working directory: %w", err)
	}
	tmpDir, err := os.MkdirTemp(cwd, "tmp")
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

	// Add targets to snapshot meta
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(int64(targets.Signed.Version))

	if payload.Settings.Roles.Delegations != nil {
		logrus.Debug("Creating custom delegations")
		customDelegations := payload.Settings.Roles.Delegations

		delegationKeys := make(map[string]*metadata.Key)
		for keyID, tufKey := range customDelegations.Keys {
			var delegationKey *metadata.Key

			if tufKey.KeyType == "ed25519" {
				publicKeyBytes, err := hex.DecodeString(tufKey.KeyVal.Public)
				if err != nil {
					logrus.Errorf("Failed to decode public key hex string for key %s: %v", keyID, err)
					continue
				}
				if len(publicKeyBytes) != ed25519.PublicKeySize {
					logrus.Errorf("Invalid public key length for key %s: expected %d, got %d", keyID, ed25519.PublicKeySize, len(publicKeyBytes))
					continue
				}
				var publicKey ed25519.PublicKey = publicKeyBytes
				delegationKey, err = metadata.KeyFromPublicKey(publicKey)
				if err != nil {
					logrus.Errorf("Failed to create metadata key from public key for key %s: %v", keyID, err)
					continue
				}

				computedKeyID, err := delegationKey.ID()
				if err != nil {
					logrus.Errorf("Failed to compute key ID from public key for key %s: %v", keyID, err)
					return fmt.Errorf("failed to compute key ID for delegation key %s: %w", keyID, err)
				}
				if computedKeyID != keyID {
					logrus.Errorf("Delegation key ID mismatch: provided %s, computed %s", keyID, computedKeyID)
					return fmt.Errorf("delegation key ID mismatch for key %s: computed %s", keyID, computedKeyID)
				}
			} else {
				logrus.Errorf("Unsupported key type for delegations: %s", tufKey.KeyType)
				continue
			}

			delegationKeys[keyID] = delegationKey
			logrus.Debugf("Added delegation key: %s", keyID)
		}

		delegatedRoles := make([]metadata.DelegatedRole, 0, len(customDelegations.Roles))
		for _, tufRole := range customDelegations.Roles {
			roleExpiration := 90

			// add role-specific expiration logic here?

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

			// Add role to snapshot meta
			snapshot.Signed.Meta[fmt.Sprintf("%s.json", roleName)] = metadata.MetaFile(1)

			roleKeyIDs := delegatedRoles[i].KeyIDs
			if len(roleKeyIDs) == 0 {
				logrus.Errorf("No key IDs found for delegated role %s", roleName)
				return fmt.Errorf("no key IDs found for delegated role %s", roleName)
			}

			threshold := delegatedRoles[i].Threshold
			if threshold < 1 {
				threshold = 1
			}
			seenKeyID := make(map[string]bool)
			keysToSign := make([]string, 0, threshold)
			for _, keyID := range roleKeyIDs {
				if seenKeyID[keyID] {
					continue
				}
				seenKeyID[keyID] = true
				keysToSign = append(keysToSign, keyID)
				if len(keysToSign) == threshold {
					break
				}
			}
			if len(keysToSign) < threshold {
				logrus.Errorf("Not enough distinct keys for delegated role %s: need %d, got %d", roleName, threshold, len(keysToSign))
				return fmt.Errorf("not enough distinct keys for delegated role %s: need %d, got %d", roleName, threshold, len(keysToSign))
			}

			for _, delegationKeyID := range keysToSign {
				delegationPrivateKey, err := signing.LoadPrivateKeyFromFilesystem(delegationKeyID, delegationKeyID)
				if err != nil {
					logrus.Errorf("Failed to load delegation private key %s for role %s: %v", delegationKeyID, roleName, err)
					return fmt.Errorf("failed to load delegation private key %s for role %s: %w", delegationKeyID, roleName, err)
				}

				delegationSigner, err := signature.LoadSigner(delegationPrivateKey, crypto.Hash(0))
				if err != nil {
					logrus.Errorf("Failed to create delegation signer for role %s: %v", roleName, err)
					return fmt.Errorf("failed to create delegation signer for role %s: %w", roleName, err)
				}

				if _, err := repo.Targets(roleName).Sign(delegationSigner); err != nil {
					logrus.Errorf("Failed to sign delegated role metadata %s with key %s: %v", roleName, delegationKeyID, err)
					return fmt.Errorf("failed to sign delegated role metadata %s with key %s: %w", roleName, delegationKeyID, err)
				}
				logrus.Debugf("Successfully signed delegated role metadata %s with key %s", roleName, delegationKeyID)
			}

			filename := fmt.Sprintf("1.%s.json", roleName)
			rolePath := filepath.Join(tmpDir, filename)
			if err := repo.Targets(roleName).ToFile(rolePath, true); err != nil {
				logrus.Errorf("Failed to persist delegated role metadata %s: %v", roleName, err)
				return fmt.Errorf("failed to persist delegated role metadata %s: %w", roleName, err)
			}
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
	timestampMeta["snapshot.json"] = metadata.MetaFile(int64(repo.Snapshot().Signed.Version))
	logrus.Debugf("Timestamp metadata references snapshot version %d", repo.Snapshot().Signed.Version)

	for i, s := range targetsSigners {
		if _, err := repo.Targets("targets").Sign(s); err != nil {
			logrus.Errorf("Failed to sign targets metadata with key %d: %v", i+1, err)
			return fmt.Errorf("failed to sign targets metadata with key %d: %w", i+1, err)
		}
	}
	logrus.Debug("Successfully signed targets metadata")

	for i, s := range snapshotSigners {
		if _, err := repo.Snapshot().Sign(s); err != nil {
			logrus.Errorf("Failed to sign snapshot metadata with key %d: %v", i+1, err)
			return fmt.Errorf("failed to sign snapshot metadata with key %d: %w", i+1, err)
		}
	}
	logrus.Debug("Successfully signed snapshot metadata")

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

// validateRoot validates the root metadata
func ValidateRoot(roles *repository.Type) {
	logrus.Debug("Performing root metadata validation")

	var err error
	err = roles.Root().VerifyDelegate("root", roles.Root())
	if err != nil {
		panic(fmt.Sprintln("TUF:", "verifying root metadata failed", err))
	}

	err = roles.Root().VerifyDelegate("targets", roles.Targets("targets"))
	if err != nil {
		panic(fmt.Sprintln("TUF:", "verifying targets metadata failed", err))
	}

	err = roles.Root().VerifyDelegate("snapshot", roles.Snapshot())
	if err != nil {
		panic(fmt.Sprintln("TUF:", "verifying snapshot metadata failed", err))
	}

	err = roles.Root().VerifyDelegate("timestamp", roles.Timestamp())
	if err != nil {
		panic(fmt.Sprintln("TUF:", "verifying timestamp metadata failed", err))
	}
	logrus.Debug("Root metadata validation completed")
}

func PostMetadataRotate(c *gin.Context, redisClient *redis.Client) {
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
	keySuffix := adminName + "_" + appName
	bootstrapKey := "BOOTSTRAP_" + keySuffix
	bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
	if err == redis.Nil || bootstrapValue == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "Task not accepted.",
			"error":   fmt.Sprintf("Requires bootstrap finished. State: %s", bootstrapValue),
		})
		return
	}

	if strings.HasPrefix(bootstrapValue, "pre-") || strings.HasPrefix(bootstrapValue, "signing-") {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "Task not accepted.",
			"error":   fmt.Sprintf("Requires bootstrap finished. State: %s", bootstrapValue),
		})
		return
	}

	var payload models.MetadataPostPayload
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

	cwd, err := os.Getwd()
	if err != nil {
		logrus.Errorf("Failed to get current working directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	tmpDir, err := os.MkdirTemp(cwd, "tmp-metadata-*")
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

		if strings.Contains(err.Error(), "unsigned") || strings.Contains(err.Error(), "signature") {

			signingKey := "ROOT_SIGNING_" + keySuffix
			redisClient.Set(ctx, signingKey, string(newRootJSON), 0)
			logrus.Infof("Root metadata v%d saved for offline signing", newRepo.Root().Signed.Version)

			taskID := uuid.New().String()
			logrus.Debugf("Generated task_id: %s", taskID)

			taskKey := "ROOT_SIGNING_TASK_" + keySuffix
			redisClient.Set(ctx, taskKey, taskID, 0)

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

func verifyNewRootMetadata(currentRoot, newRoot *metadata.Metadata[metadata.RootType]) error {
	if newRoot.Signed.Type != "root" {
		return fmt.Errorf("expected 'root', got '%s'", newRoot.Signed.Type)
	}

	if newRoot.Signed.Version != currentRoot.Signed.Version+1 {
		return fmt.Errorf("expected root version %d, got version %d", currentRoot.Signed.Version+1, newRoot.Signed.Version)
	}

	if err := currentRoot.VerifyDelegate("root", newRoot); err != nil {
		return fmt.Errorf("new root not signed by trusted root: %w", err)
	}

	if err := newRoot.VerifyDelegate("root", newRoot); err != nil {
		return fmt.Errorf("new root threshold not reached: %w", err)
	}

	return nil
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
	allSigningKeys, err := redisClient.Keys(ctx, pattern).Result()
	if err == nil {
		for _, key := range allSigningKeys {
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

func loadTrustedRootFromS3(ctx context.Context, adminName string, appName string) (map[string]interface{}, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}
	tmpDir, err := os.MkdirTemp(cwd, "tmp-trusted-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	rootPath := filepath.Join(tmpDir, "root.json")
	_, filename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "root")
	if err != nil {
		if err2 := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "root.json", rootPath); err2 != nil {
			return nil, fmt.Errorf("failed to download root metadata: %w", err)
		}
	} else {
		if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, filename, rootPath); err != nil {
			return nil, fmt.Errorf("failed to download root metadata: %w", err)
		}
	}

	rootData, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read root metadata: %w", err)
	}

	var rootJSON map[string]interface{}
	if err := json.Unmarshal(rootData, &rootJSON); err != nil {
		return nil, fmt.Errorf("failed to parse root metadata: %w", err)
	}

	return rootJSON, nil
}

func loadTrustedTargetsFromS3(ctx context.Context, adminName string, appName string) (map[string]interface{}, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}
	tmpDir, err := os.MkdirTemp(cwd, "tmp-trusted-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	targetsPath := filepath.Join(tmpDir, "targets.json")
	_, filename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "targets")
	if err != nil {
		return nil, fmt.Errorf("failed to find targets metadata: %w", err)
	}

	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, filename, targetsPath); err != nil {
		return nil, fmt.Errorf("failed to download targets metadata: %w", err)
	}

	targetsData, err := os.ReadFile(targetsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read targets metadata: %w", err)
	}

	var targetsJSON map[string]interface{}
	if err := json.Unmarshal(targetsData, &targetsJSON); err != nil {
		return nil, fmt.Errorf("failed to parse targets metadata: %w", err)
	}

	return targetsJSON, nil
}

func extractSignedSection(metadataJSON map[string]interface{}) (map[string]interface{}, error) {
	signedData, ok := metadataJSON["signed"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: missing 'signed' field")
	}
	return signedData, nil
}

func decodeAndValidateMetadataKey(keyData interface{}, expectedKeyID string) (*metadata.Key, error) {
	keyBytes, err := json.Marshal(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to encode key %s: %w", expectedKeyID, err)
	}
	var key metadata.Key
	if err := json.Unmarshal(keyBytes, &key); err != nil {
		return nil, fmt.Errorf("failed to decode key %s: %w", expectedKeyID, err)
	}

	computedKeyID, err := key.ID()
	if err != nil {
		return nil, fmt.Errorf("failed to compute key ID for %s: %w", expectedKeyID, err)
	}
	if computedKeyID != expectedKeyID {
		return nil, fmt.Errorf("keyid mismatch: provided %s, computed %s", expectedKeyID, computedKeyID)
	}

	return &key, nil
}

func getRootRoleKeysFromSigned(signedData map[string]interface{}, roleName string) (map[string]*metadata.Key, error) {
	rolesMap, ok := signedData["roles"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: missing 'roles' field")
	}
	roleData, ok := rolesMap[roleName].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("role %s not found in metadata", roleName)
	}
	keyIDsRaw, ok := roleData["keyids"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: role %s missing keyids", roleName)
	}
	keysMap, ok := signedData["keys"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: missing 'keys' field")
	}

	result := make(map[string]*metadata.Key, len(keyIDsRaw))
	for _, raw := range keyIDsRaw {
		keyID, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid keyid entry in role %s", roleName)
		}
		keyData, exists := keysMap[keyID]
		if !exists {
			return nil, fmt.Errorf("key %s referenced by role %s not found", keyID, roleName)
		}
		key, err := decodeAndValidateMetadataKey(keyData, keyID)
		if err != nil {
			return nil, err
		}
		result[keyID] = key
	}

	return result, nil
}

func getDelegatedRoleKeysFromTrustedTargets(trustedTargets map[string]interface{}, roleName string) (map[string]*metadata.Key, error) {
	signedData, err := extractSignedSection(trustedTargets)
	if err != nil {
		return nil, err
	}
	delegationsMap, ok := signedData["delegations"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid trusted targets metadata: missing delegations")
	}
	delegatedRolesRaw, ok := delegationsMap["roles"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid trusted targets metadata: missing delegated roles")
	}
	delegatedKeysRaw, ok := delegationsMap["keys"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid trusted targets metadata: missing delegated keys")
	}

	var delegatedRole map[string]interface{}
	for _, rawRole := range delegatedRolesRaw {
		roleMap, ok := rawRole.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := roleMap["name"].(string)
		if name == roleName {
			delegatedRole = roleMap
			break
		}
	}
	if delegatedRole == nil {
		return nil, fmt.Errorf("delegated role %s not found in trusted targets metadata", roleName)
	}

	keyIDsRaw, ok := delegatedRole["keyids"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid delegated role %s: missing keyids", roleName)
	}

	result := make(map[string]*metadata.Key, len(keyIDsRaw))
	for _, raw := range keyIDsRaw {
		keyID, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid delegated keyid for role %s", roleName)
		}
		keyData, exists := delegatedKeysRaw[keyID]
		if !exists {
			return nil, fmt.Errorf("delegated key %s for role %s not found", keyID, roleName)
		}
		key, err := decodeAndValidateMetadataKey(keyData, keyID)
		if err != nil {
			return nil, err
		}
		result[keyID] = key
	}

	return result, nil
}

func verifySignatureOverSignedPayload(signedData map[string]interface{}, key *metadata.Key, signatureHex string) error {
	canonicalSigned, err := cjson.EncodeCanonical(signedData)
	if err != nil {
		return fmt.Errorf("failed to canonicalize signed payload: %w", err)
	}

	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	publicKey, err := key.ToPublicKey()
	if err != nil {
		return fmt.Errorf("failed to parse public key for verification: %w", err)
	}
	verifier, err := signature.LoadVerifier(publicKey, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("failed to initialize verifier: %w", err)
	}

	if err := verifier.VerifySignature(bytes.NewReader(signatureBytes), bytes.NewReader(canonicalSigned)); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func validateIncomingMetadataSignature(
	ctx context.Context,
	adminName string,
	appName string,
	metadataType string,
	roleName string,
	keyID string,
	signatureHex string,
	signedData map[string]interface{},
	isSigningState bool,
) error {
	var allowedKeys map[string]*metadata.Key
	var err error

	switch metadataType {
	case "root":
		allowedKeys, err = getRootRoleKeysFromSigned(signedData, "root")
		if err != nil {
			return err
		}
		if !isSigningState {
			trustedRoot, trustedErr := loadTrustedRootFromS3(ctx, adminName, appName)
			if trustedErr != nil {
				return fmt.Errorf("trusted root is required for signature authorization: %w", trustedErr)
			}
			trustedRootSigned, signedErr := extractSignedSection(trustedRoot)
			if signedErr != nil {
				return fmt.Errorf("invalid trusted root metadata: %w", signedErr)
			}
			oldRootKeys, keyErr := getRootRoleKeysFromSigned(trustedRootSigned, "root")
			if keyErr != nil {
				return fmt.Errorf("failed to read trusted root keys: %w", keyErr)
			}
			for oldKeyID, oldKey := range oldRootKeys {
				if _, exists := allowedKeys[oldKeyID]; !exists {
					allowedKeys[oldKeyID] = oldKey
				}
			}
		}
	case "targets":
		if roleName == "targets" {
			trustedRoot, trustedErr := loadTrustedRootFromS3(ctx, adminName, appName)
			if trustedErr != nil {
				return fmt.Errorf("trusted root is required for signature authorization: %w", trustedErr)
			}
			trustedRootSigned, signedErr := extractSignedSection(trustedRoot)
			if signedErr != nil {
				return fmt.Errorf("invalid trusted root metadata: %w", signedErr)
			}
			allowedKeys, err = getRootRoleKeysFromSigned(trustedRootSigned, "targets")
			if err != nil {
				return fmt.Errorf("failed to read trusted root targets keys: %w", err)
			}
		} else {
			trustedTargets, trustedErr := loadTrustedTargetsFromS3(ctx, adminName, appName)
			if trustedErr != nil {
				return fmt.Errorf("trusted targets metadata is required for delegated signature authorization: %w", trustedErr)
			}
			allowedKeys, err = getDelegatedRoleKeysFromTrustedTargets(trustedTargets, roleName)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("signature validation not supported for metadata type %q", metadataType)
	}

	key, ok := allowedKeys[keyID]
	if !ok {
		return fmt.Errorf("keyid %s is not authorized for role %s", keyID, roleName)
	}

	if err := verifySignatureOverSignedPayload(signedData, key, signatureHex); err != nil {
		return err
	}

	return nil
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

	cwd, err := os.Getwd()
	if err != nil {
		logrus.Errorf("Failed to get current working directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	tmpDir, err := os.MkdirTemp(cwd, "tmp-sign-*")
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
		redisClient.Set(ctx, taskKey, taskID, 0)
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
			redisClient.Del(ctx, signingKey)
			redisClient.Del(ctx, taskKey)
			logrus.Infof("Root metadata update finalized and signing key cleared from Redis")
		} else {
			logrus.Infof("Threshold not reached - saving updated metadata back to Redis (error: %v)", validationError)
			updatedJSON, _ := json.Marshal(metadataJSON)
			redisClient.Set(ctx, signingKey, string(updatedJSON), 0)
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
		if err == nil {
			targetsPath := filepath.Join(tmpDir, targetsFilename)
			if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, targetsFilename, targetsPath); err == nil {
				trustedTargets := metadata.Targets(time.Now().Add(365 * 24 * time.Hour))
				trustedRepo := repository.New()
				trustedRepo.SetTargets("targets", trustedTargets)
				if _, err := trustedRepo.Targets("targets").FromFile(targetsPath); err == nil {
					if err := trustedRepo.Targets("targets").VerifyDelegate(payload.Role, repo.Targets(payload.Role)); err != nil {
						validationError = err
						thresholdReached = false
					} else {
						thresholdReached = true
					}
				}
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

			redisClient.Del(ctx, signingKey)
			redisClient.Del(ctx, taskKey)
		} else {

			updatedJSON, _ := json.Marshal(metadataJSON)
			redisClient.Set(ctx, signingKey, string(updatedJSON), 0)
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

func finalizeRootMetadataUpdate(
	ctx context.Context,
	repo *repository.Type,
	adminName string,
	appName string,
	tmpDir string,
	isBootstrap bool,
	bootstrapValue string,
	redisClient *redis.Client,
) error {
	root := repo.Root()
	if root == nil {
		return fmt.Errorf("root metadata not loaded")
	}

	rootFilename := fmt.Sprintf("%d.root.json", root.Signed.Version)
	rootPath := filepath.Join(tmpDir, rootFilename)
	if err := root.ToFile(rootPath, true); err != nil {
		return fmt.Errorf("failed to save root metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, rootFilename, rootPath); err != nil {
		return fmt.Errorf("failed to upload root metadata to S3: %w", err)
	}

	if isBootstrap {
		bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
		if strings.HasPrefix(bootstrapValue, "signing-") {
			taskID := strings.TrimPrefix(bootstrapValue, "signing-")
			if err := redisClient.Set(ctx, bootstrapKey, taskID, 0).Err(); err != nil {
				logrus.Warnf("Failed to update bootstrap state: %v", err)
			}
		}
	}

	logrus.Infof("Successfully finalized root metadata update: %s", rootFilename)
	return nil
}

func finalizeTargetsMetadataUpdate(
	ctx context.Context,
	repo *repository.Type,
	roleName string,
	adminName string,
	appName string,
	tmpDir string,
	redisClient *redis.Client,
) error {
	logrus.Debugf("Finalizing targets metadata update for role %s", roleName)
	targets := repo.Targets(roleName)
	if targets == nil {
		return fmt.Errorf("targets metadata not loaded for role %s", roleName)
	}

	targetsFilename := fmt.Sprintf("%d.%s.json", targets.Signed.Version, roleName)
	targetsPath := filepath.Join(tmpDir, targetsFilename)
	if err := targets.ToFile(targetsPath, true); err != nil {
		return fmt.Errorf("failed to save targets metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, targetsFilename, targetsPath); err != nil {
		return fmt.Errorf("failed to upload targets metadata to S3: %w", err)
	}

	// Load root metadata to obtain snapshot and timestamp key IDs for re-signing.
	rootPath := filepath.Join(tmpDir, "finalize_root.json")
	_, rootFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "root")
	if err != nil {
		return fmt.Errorf("failed to find root metadata version: %w", err)
	}
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, rootFilename, rootPath); err != nil {
		return fmt.Errorf("failed to download root metadata: %w", err)
	}

	rootData, err := os.ReadFile(rootPath)
	if err != nil {
		return fmt.Errorf("failed to read root metadata: %w", err)
	}

	var rootMetadata models.RootMetadata
	if err := json.Unmarshal(rootData, &rootMetadata); err != nil {
		return fmt.Errorf("failed to parse root metadata: %w", err)
	}

	// Build snapshot signers from root-declared keys.
	snapshotRole, ok := rootMetadata.Signed.Roles["snapshot"]
	if !ok || len(snapshotRole.KeyIDs) == 0 {
		return fmt.Errorf("snapshot role not found in root metadata")
	}
	snapshotSigners, err := buildOnlineRoleSigners(snapshotRole.KeyIDs, snapshotRole.Threshold, "snapshot")
	if err != nil {
		return fmt.Errorf("failed to build snapshot signers: %w", err)
	}

	// Build timestamp signers from root-declared keys.
	timestampRole, ok := rootMetadata.Signed.Roles["timestamp"]
	if !ok || len(timestampRole.KeyIDs) == 0 {
		return fmt.Errorf("timestamp role not found in root metadata")
	}
	timestampSigners, err := buildOnlineRoleSigners(timestampRole.KeyIDs, timestampRole.Threshold, "timestamp")
	if err != nil {
		return fmt.Errorf("failed to build timestamp signers: %w", err)
	}

	keySuffix := adminName + "_" + appName

	// --- Update and re-sign snapshot ---
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

	repo.Snapshot().Signed.Meta[fmt.Sprintf("%s.json", roleName)] = metadata.MetaFile(int64(targets.Signed.Version))
	repo.Snapshot().Signed.Version++
	repo.Snapshot().Signed.Expires = tuf_utils.HelperExpireIn(snapshotExpiration)
	repo.Snapshot().ClearSignatures()

	for i, s := range snapshotSigners {
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

	logrus.Infof("Successfully updated and signed snapshot to version %d", repo.Snapshot().Signed.Version)

	// --- Update and re-sign timestamp to reference new snapshot ---
	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "timestamp.json", timestampPath); err != nil {
		logrus.Debugf("Timestamp metadata not found in storage, will create new: %v", err)
	}

	timestampExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TIMESTAMP_EXPIRATION_"+keySuffix, 1)
	timestamp := metadata.Timestamp(tuf_utils.HelperExpireIn(timestampExpiration))
	repo.SetTimestamp(timestamp)
	loadedTimestamp := false
	if _, statErr := os.Stat(timestampPath); statErr == nil {
		if _, loadErr := repo.Timestamp().FromFile(timestampPath); loadErr != nil {
			logrus.Warnf("Failed to load timestamp metadata: %v, creating new one", loadErr)
		} else {
			loadedTimestamp = true
		}
	}

	timestampMeta := repo.Timestamp().Signed.Meta
	if timestampMeta == nil {
		timestampMeta = make(map[string]*metadata.MetaFiles)
		repo.Timestamp().Signed.Meta = timestampMeta
	}
	timestampMeta["snapshot.json"] = metadata.MetaFile(int64(repo.Snapshot().Signed.Version))

	if loadedTimestamp {
		repo.Timestamp().Signed.Version++
	}
	repo.Timestamp().Signed.Expires = tuf_utils.HelperExpireIn(timestampExpiration)
	repo.Timestamp().ClearSignatures()

	for i, s := range timestampSigners {
		if _, err := repo.Timestamp().Sign(s); err != nil {
			return fmt.Errorf("failed to sign timestamp metadata with key %d: %w", i+1, err)
		}
	}

	timestampOutPath := filepath.Join(tmpDir, "timestamp.json")
	if err := repo.Timestamp().ToFile(timestampOutPath, true); err != nil {
		return fmt.Errorf("failed to save timestamp metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, "timestamp.json", timestampOutPath); err != nil {
		return fmt.Errorf("failed to upload timestamp metadata to S3: %w", err)
	}

	logrus.Debugf("Successfully updated and signed timestamp referencing snapshot version %d", repo.Snapshot().Signed.Version)

	logrus.Infof("Successfully finalized targets metadata update: %s", targetsFilename)
	return nil
}
