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
	tuf_utils "faynoSync/server/tuf/utils"
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
)

// bootstrapOnlineRoles creates online roles (targets, snapshot, timestamp) and delegations
func BootstrapOnlineRoles(redisClient *redis.Client, mongoDatabase *mongo.Database, taskID string, adminName string, appName string, payload *models.BootstrapPayload) error {
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
	defer func() {
		logrus.Debugf("Metadata stored in: %s", tmpDir)
	}()

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

	var onlinePrivateKey ed25519.PrivateKey
	var signer signature.Signer
	if mongoDatabase != nil {
		var err error
		onlinePrivateKey, err = signing.LoadPrivateKeyFromMongoDB(mongoDatabase, adminName, onlineKeyID, ctx)
		if err != nil {
			logrus.Errorf("Failed to load online private key from MongoDB: %v", err)
			return fmt.Errorf("failed to load online private key from MongoDB: %w", err)
		}
		signer, err = signature.LoadSigner(onlinePrivateKey, crypto.Hash(0))
		if err != nil {
			logrus.Errorf("Failed to create signer from private key: %v", err)
			return fmt.Errorf("failed to create signer from private key: %w", err)
		}
		logrus.Debug("Successfully loaded online private key and created signer")
	} else {
		logrus.Error("MongoDB database is nil, cannot load private key for signing")
		return fmt.Errorf("MongoDB database is nil, cannot load private key for signing")
	}

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

			if _, err := repo.Targets(roleName).Sign(signer); err != nil {
				logrus.Errorf("Failed to sign delegated role metadata %s: %v", roleName, err)
				return fmt.Errorf("failed to sign delegated role metadata %s: %w", roleName, err)
			}
			logrus.Debugf("Successfully signed delegated role metadata: %s", roleName)

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
