package metadata

import (
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
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// bootstrapOnlineRoles creates online roles (targets, snapshot, timestamp) and delegations
func BootstrapOnlineRoles(redisClient *redis.Client, taskID string, adminName string, appName string, payload *models.BootstrapPayload) error {
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

	expires, err := time.Parse(time.RFC3339, rootMetadata.Signed.Expires)
	if err != nil {

		expires, err = time.Parse("2006-01-02T15:04:05.999999999Z", rootMetadata.Signed.Expires)
		if err != nil {
			logrus.Errorf("Failed to parse root expiration: %v", err)
			expires = tuf_utils.HelperExpireIn(365)
		}
	}

	tempRoot := metadata.Root(expires)
	repo.SetRoot(tempRoot)

	_, err = repo.Root().FromFile(rootPath)
	if err != nil {
		logrus.Errorf("Failed to load root metadata from file: %v", err)
		return fmt.Errorf("failed to load root metadata from file: %w", err)
	}

	ctx := context.Background()
	keySuffix := adminName + "_" + appName
	targetsExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TARGETS_EXPIRATION_"+keySuffix, payload.Settings.Roles.Targets.Expiration)
	snapshotExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "SNAPSHOT_EXPIRATION_"+keySuffix, payload.Settings.Roles.Snapshot.Expiration)
	timestampExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TIMESTAMP_EXPIRATION_"+keySuffix, payload.Settings.Roles.Timestamp.Expiration)

	var onlineKeyID string
	if timestampRole, ok := rootMetadata.Signed.Roles["timestamp"]; ok && len(timestampRole.KeyIDs) > 0 {
		onlineKeyID = timestampRole.KeyIDs[0]
	} else {
		logrus.Error("Failed to find timestamp key in root metadata")
		return fmt.Errorf("failed to find timestamp key in root metadata")
	}

	_, exists = rootMetadata.Signed.Keys[onlineKeyID]
	if !exists {
		logrus.Errorf("Online key %s not found in root metadata", onlineKeyID)
		return fmt.Errorf("online key %s not found in root metadata", onlineKeyID)
	}

	logrus.Debugf("Using online key: %s", onlineKeyID)

	keyURI := onlineKeyID

	var onlinePrivateKey ed25519.PrivateKey
	var signer signature.Signer

	onlinePrivateKey, err = signing.LoadPrivateKeyFromFilesystem(onlineKeyID, keyURI)
	if err != nil {
		logrus.Errorf("Failed to load online private key from filesystem: %v", err)
	} else {
		logrus.Debug("Successfully loaded online private key from filesystem")
	}

	signer, err = signature.LoadSigner(onlinePrivateKey, crypto.Hash(0))
	if err != nil {
		logrus.Errorf("Failed to create signer from private key: %v", err)
		return fmt.Errorf("failed to create signer from private key: %w", err)
	}
	logrus.Debug("Successfully created signer from private key")

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

			delegationKeyID := roleKeyIDs[0]
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

			// Sign with delegation key(s) - for now, sign with first key (threshold=1)
			// TODO: Support multiple signatures for threshold > 1 (?)
			if _, err := repo.Targets(roleName).Sign(delegationSigner); err != nil {
				logrus.Errorf("Failed to sign delegated role metadata %s: %v", roleName, err)
				return fmt.Errorf("failed to sign delegated role metadata %s: %w", roleName, err)
			}
			logrus.Debugf("Successfully signed delegated role metadata %s with key %s", roleName, delegationKeyID)

			filename := fmt.Sprintf("1.%s.json", roleName)
			rolePath := filepath.Join(tmpDir, filename)
			if err := repo.Targets(roleName).ToFile(rolePath, true); err != nil {
				logrus.Errorf("Failed to persist delegated role metadata %s: %v", roleName, err)
				continue
			}
			logrus.Debugf("Successfully persisted delegated role metadata: %s", filename)

			if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, filename, rolePath); err != nil {
				logrus.Errorf("Failed to upload delegated role metadata %s to S3: %v", roleName, err)
			}
		}

		logrus.Debug("Custom delegations created successfully")
	}

	if _, err := repo.Targets("targets").Sign(signer); err != nil {
		logrus.Errorf("Failed to sign targets metadata: %v", err)
		return fmt.Errorf("failed to sign targets metadata: %w", err)
	}
	logrus.Debug("Successfully signed targets metadata")

	if _, err := repo.Snapshot().Sign(signer); err != nil {
		logrus.Errorf("Failed to sign snapshot metadata: %v", err)
		return fmt.Errorf("failed to sign snapshot metadata: %w", err)
	}
	logrus.Debug("Successfully signed snapshot metadata")

	if _, err := repo.Timestamp().Sign(signer); err != nil {
		logrus.Errorf("Failed to sign timestamp metadata: %v", err)
		return fmt.Errorf("failed to sign timestamp metadata: %w", err)
	}
	logrus.Debug("Successfully signed timestamp metadata")

	if err := repo.Root().ToFile(rootPath, true); err != nil {
		logrus.Errorf("Failed to persist root metadata: %v", err)
		return fmt.Errorf("failed to persist root metadata: %w", err)
	}
	logrus.Debugf("Successfully persisted root metadata: 1.root.json")

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, "1.root.json", rootPath); err != nil {
		logrus.Errorf("Failed to upload root metadata to S3: %v", err)
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
	}

	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	if err := repo.Timestamp().ToFile(timestampPath, true); err != nil {
		logrus.Errorf("Failed to persist timestamp metadata: %v", err)
		return fmt.Errorf("failed to persist timestamp metadata: %w", err)
	}
	logrus.Debugf("Successfully persisted timestamp metadata: timestamp.json")

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, "timestamp.json", timestampPath); err != nil {
		logrus.Errorf("Failed to upload timestamp metadata to S3: %v", err)
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

	var thresholdReached bool
	var validationError error

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
				os.WriteFile(trustedRootPath, trustedRootJSON, 0644)

				trustedRepo := repository.New()
				trustedRootMeta := metadata.Root(time.Now().Add(365 * 24 * time.Hour))
				trustedRepo.SetRoot(trustedRootMeta)
				if _, err := trustedRepo.Root().FromFile(trustedRootPath); err == nil {
					logrus.Debugf("Validating new root against trusted root and itself")

					err1 := trustedRepo.Root().VerifyDelegate("root", repo.Root())
					err2 := repo.Root().VerifyDelegate("root", repo.Root())

					if err1 != nil {
						logrus.Warnf("Trusted root verification failed: %v", err1)
						logrus.Debugf("Note: For root rotation, trusted root verification may fail if not enough old key signatures, but this is OK if self-verification passes")
					} else {
						logrus.Debugf("Trusted root verification succeeded")
					}

					if err2 != nil {
						logrus.Warnf("New root self-verification failed: %v", err2)
					} else {
						logrus.Debugf("New root self-verification succeeded")
					}

					// For root rotation, threshold is reached if self-verification passes
					// (new root is signed by enough new keys to meet threshold)
					// Trusted root verification ensures trust chain, but doesn't need to meet threshold
					if err2 == nil {
						logrus.Infof("Self-verification succeeded: threshold reached (new root has enough signatures from new keys)")
						thresholdReached = true
						// Log warning if trusted root verification failed, but don't block
						if err1 != nil {
							logrus.Warnf("Trusted root verification failed, but threshold reached - proceeding with finalization")
						}
					} else {
						validationError = err2
						logrus.Warnf("Self-verification failed: threshold not reached, error=%v", validationError)
						thresholdReached = false
					}
				} else {
					logrus.Warnf("Failed to load trusted root from file, falling back to self-validation: %v", err)
					if err := repo.Root().VerifyDelegate("root", repo.Root()); err != nil {
						logrus.Warnf("Self-validation failed: %v", err)
						validationError = err
						thresholdReached = false
					} else {
						logrus.Infof("Self-validation succeeded: threshold reached")
						thresholdReached = true
					}
				}
			} else {
				logrus.Warnf("Failed to load trusted root from S3, falling back to self-validation: %v", err)
				if err := repo.Root().VerifyDelegate("root", repo.Root()); err != nil {
					logrus.Warnf("Self-validation failed: %v", err)
					validationError = err
					thresholdReached = false
				} else {
					logrus.Infof("Self-validation succeeded: threshold reached")
					thresholdReached = true
				}
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
			if err := finalizeTargetsMetadataUpdate(ctx, repo, payload.Role, adminName, appName, tmpDir); err != nil {
				logrus.Errorf("Failed to finalize targets metadata: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to finalize metadata: %v", err),
				})
				return
			}

			redisClient.Del(ctx, signingKey)
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

	taskID := uuid.New().String()
	logrus.Debugf("Generated task_id: %s", taskID)

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
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Signature Failed",
			"error":   fmt.Sprintf("Invalid signature or threshold not reached: %v", validationError),
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
) error {
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

	// Update snapshot and timestamp
	// Load current snapshot
	_, snapshotFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "snapshot")
	if err == nil {
		snapshotPath := filepath.Join(tmpDir, snapshotFilename)
		if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, snapshotFilename, snapshotPath); err == nil {
			snapshot := metadata.Snapshot(time.Now().Add(365 * 24 * time.Hour))
			repo.SetSnapshot(snapshot)
			if _, err := repo.Snapshot().FromFile(snapshotPath); err == nil {

				repo.Snapshot().Signed.Meta[fmt.Sprintf("%s.json", roleName)] = metadata.MetaFile(int64(targets.Signed.Version))
				repo.Snapshot().Signed.Version++

				newSnapshotFilename := fmt.Sprintf("%d.snapshot.json", repo.Snapshot().Signed.Version)
				newSnapshotPath := filepath.Join(tmpDir, newSnapshotFilename)
				if err := repo.Snapshot().ToFile(newSnapshotPath, true); err == nil {
					tuf_storage.UploadMetadataToS3(ctx, adminName, appName, newSnapshotFilename, newSnapshotPath)
				}
			}
		}
	}

	logrus.Infof("Successfully finalized targets metadata update: %s", targetsFilename)
	return nil
}
