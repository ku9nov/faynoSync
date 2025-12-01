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
func BootstrapOnlineRoles(redisClient *redis.Client, mongoDatabase *mongo.Database, taskID string, adminName string, payload *models.BootstrapPayload) {
	logrus.Debug("Starting bootstrap online roles creation")

	// Create temporary directory for storing metadata
	cwd, err := os.Getwd()
	if err != nil {
		logrus.Errorf("Failed to get current working directory: %v", err)
		return
	}
	tmpDir, err := os.MkdirTemp(cwd, "tmp")
	if err != nil {
		logrus.Errorf("Failed to create temporary directory: %v", err)
		return
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
		return
	}

	// Save root metadata to temporary file first
	rootJSON, err := json.Marshal(rootMetadata)
	if err != nil {
		logrus.Errorf("Failed to marshal root metadata: %v", err)
		return
	}
	logrus.Debugf("Tmp dir will be used to store metadata: %s", tmpDir)
	rootPath := filepath.Join(tmpDir, "1.root.json")
	if err := os.WriteFile(rootPath, rootJSON, 0644); err != nil {
		logrus.Errorf("Failed to write root metadata to file: %v", err)
		return
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
		return
	}

	ctx := context.Background()
	targetsExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TARGETS_EXPIRATION_"+adminName, payload.Settings.Roles.Targets.Expiration)
	snapshotExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "SNAPSHOT_EXPIRATION_"+adminName, payload.Settings.Roles.Snapshot.Expiration)
	timestampExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TIMESTAMP_EXPIRATION_"+adminName, payload.Settings.Roles.Timestamp.Expiration)

	var onlineKeyID string
	if timestampRole, ok := rootMetadata.Signed.Roles["timestamp"]; ok && len(timestampRole.KeyIDs) > 0 {
		onlineKeyID = timestampRole.KeyIDs[0]
	} else {
		logrus.Error("Failed to find timestamp key in root metadata")
		return
	}

	_, exists = rootMetadata.Signed.Keys[onlineKeyID]
	if !exists {
		logrus.Errorf("Online key %s not found in root metadata", onlineKeyID)
		return
	}

	logrus.Debugf("Using online key: %s", onlineKeyID)

	var onlinePrivateKey ed25519.PrivateKey
	var signer signature.Signer
	if mongoDatabase != nil {
		var err error
		onlinePrivateKey, err = signing.LoadPrivateKeyFromMongoDB(mongoDatabase, adminName, onlineKeyID, ctx)
		if err != nil {
			logrus.Errorf("Failed to load online private key from MongoDB: %v", err)
			logrus.Warn("Continuing without signing - metadata will be unsigned")
		} else {
			signer, err = signature.LoadSigner(onlinePrivateKey, crypto.Hash(0))
			if err != nil {
				logrus.Errorf("Failed to create signer from private key: %v", err)
				logrus.Warn("Continuing without signing - metadata will be unsigned")
				signer = nil
			} else {
				logrus.Debug("Successfully loaded online private key and created signer")
			}
		}
	} else {
		logrus.Warn("MongoDB database is nil, cannot load private key for signing")
	}

	targets := metadata.Targets(tuf_utils.HelperExpireIn(targetsExpiration))
	repo.SetTargets("targets", targets)

	snapshot := metadata.Snapshot(tuf_utils.HelperExpireIn(snapshotExpiration))
	repo.SetSnapshot(snapshot)

	timestamp := metadata.Timestamp(tuf_utils.HelperExpireIn(timestampExpiration))
	repo.SetTimestamp(timestamp)

	// Add targets to snapshot meta
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(int64(targets.Signed.Version))

	// Handle bins delegations if present
	if payload.Settings.Roles.Bins != nil {
		logrus.Debug("Creating bins delegations")
		numberOfBins := payload.Settings.Roles.Bins.NumberOfDelegatedBins
		binsExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "BINS_EXPIRATION_"+adminName, payload.Settings.Roles.Bins.Expiration)

		// Calculate bit length for succinct roles
		bitLength := 0
		for i := numberOfBins; i > 1; i /= 2 {
			bitLength++
		}

		// Get the online key from root metadata to add to delegations.keys
		onlineKey, exists := rootMetadata.Signed.Keys[onlineKeyID]
		if !exists {
			logrus.Errorf("Online key %s not found in root metadata", onlineKeyID)
			return
		}

		// Create succinct roles for bins
		succinctRoles := &metadata.SuccinctRoles{
			KeyIDs:     []string{onlineKeyID},
			Threshold:  1,
			BitLength:  bitLength,
			NamePrefix: "bin-",
		}

		// Convert root metadata key to go-tuf metadata key format
		// For succinct roles, we need to add the key to delegations.keys
		// so the client can verify bin metadata signatures
		// The key is stored as hex string in root metadata, we need to decode it
		var delegationKey *metadata.Key
		if onlineKey.KeyType == "ed25519" {
			// Decode hex string to bytes
			publicKeyBytes, err := hex.DecodeString(onlineKey.KeyVal.Public)
			if err != nil {
				logrus.Errorf("Failed to decode public key hex string: %v", err)
				return
			}
			// Convert bytes to ed25519.PublicKey
			if len(publicKeyBytes) != ed25519.PublicKeySize {
				logrus.Errorf("Invalid public key length: expected %d, got %d", ed25519.PublicKeySize, len(publicKeyBytes))
				return
			}
			var publicKey ed25519.PublicKey = publicKeyBytes
			// Create metadata.Key from public key
			delegationKey, err = metadata.KeyFromPublicKey(publicKey)
			if err != nil {
				logrus.Errorf("Failed to create metadata key from public key: %v", err)
				return
			}
		} else {
			logrus.Errorf("Unsupported key type for delegations: %s", onlineKey.KeyType)
			return
		}

		// Create delegations with both succinct roles and keys
		// Keys are needed for client to verify bin metadata signatures
		delegationKeys := make(map[string]*metadata.Key)
		delegationKeys[onlineKeyID] = delegationKey

		targets.Signed.Delegations = &metadata.Delegations{
			Keys:          delegationKeys,
			SuccinctRoles: succinctRoles,
		}

		// Update targets in repository with delegations
		repo.SetTargets("targets", targets)

		// Create bin metadata files
		for i := 0; i < numberOfBins; i++ {
			binName := fmt.Sprintf("bin-%d", i)
			binTargets := metadata.Targets(tuf_utils.HelperExpireIn(binsExpiration))
			binTargets.Signed.Version = 1

			repo.SetTargets(binName, binTargets)

			snapshot.Signed.Meta[fmt.Sprintf("%s.json", binName)] = metadata.MetaFile(1)

			if signer != nil {
				if _, err := repo.Targets(binName).Sign(signer); err != nil {
					logrus.Errorf("Failed to sign bin metadata %s: %v", binName, err)
				} else {
					logrus.Debugf("Successfully signed bin metadata: %s", binName)
				}
			}

			filename := fmt.Sprintf("1.%s.json", binName)
			binPath := filepath.Join(tmpDir, filename)
			if err := repo.Targets(binName).ToFile(binPath, true); err != nil {
				logrus.Errorf("Failed to persist bin metadata %s: %v", binName, err)
				continue
			}
			logrus.Debugf("Successfully persisted bin metadata: %s", filename)

			if err := tuf_storage.UploadMetadataToS3(ctx, adminName, filename, binPath); err != nil {
				logrus.Errorf("Failed to upload bin metadata %s to S3: %v", binName, err)
			}
		}
	}

	if signer != nil {

		if _, err := repo.Targets("targets").Sign(signer); err != nil {
			logrus.Errorf("Failed to sign targets metadata: %v", err)
		} else {
			logrus.Debug("Successfully signed targets metadata")
		}

		if _, err := repo.Snapshot().Sign(signer); err != nil {
			logrus.Errorf("Failed to sign snapshot metadata: %v", err)
		} else {
			logrus.Debug("Successfully signed snapshot metadata")
		}

		if _, err := repo.Timestamp().Sign(signer); err != nil {
			logrus.Errorf("Failed to sign timestamp metadata: %v", err)
		} else {
			logrus.Debug("Successfully signed timestamp metadata")
		}
	} else {
		logrus.Warn("Signer is not available, metadata will be saved without signatures")
	}

	if err := repo.Root().ToFile(rootPath, true); err != nil {
		logrus.Errorf("Failed to persist root metadata: %v", err)
		return
	}
	logrus.Debugf("Successfully persisted root metadata: 1.root.json")

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, "1.root.json", rootPath); err != nil {
		logrus.Errorf("Failed to upload root metadata to S3: %v", err)
	}

	targetsFilename := fmt.Sprintf("%d.targets.json", targets.Signed.Version)
	targetsPath := filepath.Join(tmpDir, targetsFilename)
	if err := repo.Targets("targets").ToFile(targetsPath, true); err != nil {
		logrus.Errorf("Failed to persist targets metadata: %v", err)
		return
	}
	logrus.Debugf("Successfully persisted targets metadata: %s", targetsFilename)

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, targetsFilename, targetsPath); err != nil {
		logrus.Errorf("Failed to upload targets metadata to S3: %v", err)
	}

	snapshotFilename := fmt.Sprintf("%d.snapshot.json", snapshot.Signed.Version)
	snapshotPath := filepath.Join(tmpDir, snapshotFilename)
	if err := repo.Snapshot().ToFile(snapshotPath, true); err != nil {
		logrus.Errorf("Failed to persist snapshot metadata: %v", err)
		return
	}
	logrus.Debugf("Successfully persisted snapshot metadata: %s", snapshotFilename)

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, snapshotFilename, snapshotPath); err != nil {
		logrus.Errorf("Failed to upload snapshot metadata to S3: %v", err)
	}

	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	if err := repo.Timestamp().ToFile(timestampPath, true); err != nil {
		logrus.Errorf("Failed to persist timestamp metadata: %v", err)
		return
	}
	logrus.Debugf("Successfully persisted timestamp metadata: timestamp.json")

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, "timestamp.json", timestampPath); err != nil {
		logrus.Errorf("Failed to upload timestamp metadata to S3: %v", err)
	}

	logrus.Debug("Bootstrap online roles creation completed")
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
