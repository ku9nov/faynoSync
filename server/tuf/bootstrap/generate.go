package bootstrap

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	tuf_metadata "faynoSync/server/tuf/metadata"
	"faynoSync/server/tuf/models"
	"faynoSync/server/tuf/signing"
	tuf_utils "faynoSync/server/tuf/utils"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"go.mongodb.org/mongo-driver/mongo"
)

// Generates root keys for the repository
func GenerateRootKeys(c *gin.Context, database *mongo.Database) {

	adminName, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get admin name from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	logrus.Debugf("Generating root keys for admin: %s", adminName)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	roles := repository.New()
	keys := map[string]ed25519.PrivateKey{}
	publicKeyIDs := map[string]string{}

	targets := metadata.Targets(tuf_utils.HelperExpireIn(7))
	roles.SetTargets("targets", targets)

	snapshot := metadata.Snapshot(tuf_utils.HelperExpireIn(7))
	roles.SetSnapshot(snapshot)
	timestamp := metadata.Timestamp(tuf_utils.HelperExpireIn(1))
	roles.SetTimestamp(timestamp)
	root := metadata.Root(tuf_utils.HelperExpireIn(365))
	roles.SetRoot(root)
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		_, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(fmt.Sprintln("TUF:", "key generation failed", err))
		}
		keys[name] = private
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			panic(fmt.Sprintln("TUF:", "key conversion failed", err))
		}
		err = roles.Root().Signed.AddKey(key, name)
		if err != nil {
			panic(fmt.Sprintln("TUF:", "adding key to root failed", err))
		}

		if role, ok := roles.Root().Signed.Roles[name]; ok && len(role.KeyIDs) > 0 {
			publicKeyIDs[name] = role.KeyIDs[len(role.KeyIDs)-1]
		} else {
			logrus.Warnf("Failed to get key ID for role %s from root metadata", name)
		}
	}
	_, anotherRootKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Sprintln("TUF:", "key generation failed", err))
	}

	anotherKey, err := metadata.KeyFromPublicKey(anotherRootKey.Public())
	if err != nil {
		panic(fmt.Sprintln("TUF:", "key conversion failed", err))
	}
	err = roles.Root().Signed.AddKey(anotherKey, "root")
	if err != nil {
		panic(fmt.Sprintln("TUF:", "adding another key to root failed", err))
	}
	roles.Root().Signed.Roles["root"].Threshold = 2

	keys["root_extra"] = anotherRootKey
	if role, ok := roles.Root().Signed.Roles["root"]; ok && len(role.KeyIDs) > 0 {
		publicKeyIDs["root_extra"] = role.KeyIDs[len(role.KeyIDs)-1]
	} else {
		logrus.Warnf("Failed to get key ID for root_extra key from root metadata")
	}
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		key := keys[name]
		signer, err := signature.LoadSigner(key, crypto.Hash(0))
		if err != nil {
			panic(fmt.Sprintln("TUF:", "loading a signer failed", err))
		}
		switch name {
		case "targets":
			_, err = roles.Targets("targets").Sign(signer)
		case "snapshot":
			_, err = roles.Snapshot().Sign(signer)
		case "timestamp":
			_, err = roles.Timestamp().Sign(signer)
		case "root":
			_, err = roles.Root().Sign(signer)
		}
		if err != nil {
			panic(fmt.Sprintln("TUF:", "metadata signing failed", err))
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		panic(fmt.Sprintln("TUF:", "getting cwd failed", err))
	}
	tmpDir, err := os.MkdirTemp(cwd, "tmp")
	if err != nil {
		panic(fmt.Sprintln("TUF:", "creating a temporary folder failed", err))
	}

	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		switch name {
		case "targets":
			filename := fmt.Sprintf("%d.%s.json", roles.Targets("targets").Signed.Version, name)
			err = roles.Targets("targets").ToFile(filepath.Join(tmpDir, filename), true)
		case "snapshot":
			filename := fmt.Sprintf("%d.%s.json", roles.Snapshot().Signed.Version, name)
			err = roles.Snapshot().ToFile(filepath.Join(tmpDir, filename), true)
		case "timestamp":
			filename := fmt.Sprintf("%s.json", name)
			err = roles.Timestamp().ToFile(filepath.Join(tmpDir, filename), true)
		case "root":
			filename := fmt.Sprintf("%d.%s.json", roles.Root().Signed.Version, name)
			err = roles.Root().ToFile(filepath.Join(tmpDir, filename), true)
		}
		if err != nil {
			panic(fmt.Sprintln("TUF:", "saving metadata to file failed", err))
		}
	}

	_, err = roles.Root().FromFile(filepath.Join(tmpDir, "1.root.json"))
	if err != nil {
		panic(fmt.Sprintln("TUF:", "loading root metadata from file failed", err))
	}
	outofbandSigner, err := signature.LoadSigner(anotherRootKey, crypto.Hash(0))
	if err != nil {
		panic(fmt.Sprintln("TUF:", "loading a signer failed", err))
	}
	_, err = roles.Root().Sign(outofbandSigner)
	if err != nil {
		panic(fmt.Sprintln("TUF:", "signing root failed", err))
	}
	err = roles.Root().ToFile(filepath.Join(tmpDir, "1.root.json"), true)
	if err != nil {
		panic(fmt.Sprintln("TUF:", "saving root metadata to file failed", err))
	}
	tuf_metadata.ValidateRoot(roles)
	logrus.Debug("Root keys generation completed")

	if database != nil {
		err = signing.SavePrivateKeysToMongoDB(database, adminName, keys, publicKeyIDs, ctx)
		if err != nil {
			logrus.Errorf("Failed to save private keys to MongoDB: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to save private keys to database",
			})
			return
		}
		logrus.Debug("Private keys saved to MongoDB successfully")
	} else {
		logrus.Warn("MongoDB database is nil, skipping private keys save")
	}

	payload, err := generatePayload(tmpDir)
	if err != nil {
		logrus.Errorf("Failed to generate payload: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate bootstrap payload",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":    payload,
		"message": "Root keys generated and payload created successfully",
	})
}

// generatePayload generates bootstrap payload from metadata directory
func generatePayload(metadataDir string) (*models.BootstrapPayload, error) {
	logrus.Debug("Generating payload")

	rootPath := filepath.Join(metadataDir, "1.root.json")
	rootData, err := ioutil.ReadFile(rootPath)
	if err != nil {
		return nil, fmt.Errorf("error reading root metadata: %w", err)
	}

	var rootMetadata models.RootMetadata
	if err := json.Unmarshal(rootData, &rootMetadata); err != nil {
		return nil, fmt.Errorf("error parsing root metadata: %w", err)
	}

	timestampPath := filepath.Join(metadataDir, "timestamp.json")
	snapshotPath := filepath.Join(metadataDir, "1.snapshot.json")
	targetsPath := filepath.Join(metadataDir, "1.targets.json")

	rootExpiration := tuf_utils.CalculateExpirationDays(rootMetadata.Signed.Expires)

	var timestampExpiration, snapshotExpiration, targetsExpiration int

	if timestampData, err := ioutil.ReadFile(timestampPath); err == nil {
		var timestampMeta map[string]interface{}
		if err := json.Unmarshal(timestampData, &timestampMeta); err == nil {
			if signed, ok := timestampMeta["signed"].(map[string]interface{}); ok {
				if expires, ok := signed["expires"].(string); ok {
					timestampExpiration = tuf_utils.CalculateExpirationDays(expires)
				}
			}
		}
	}

	if snapshotData, err := ioutil.ReadFile(snapshotPath); err == nil {
		var snapshotMeta map[string]interface{}
		if err := json.Unmarshal(snapshotData, &snapshotMeta); err == nil {
			if signed, ok := snapshotMeta["signed"].(map[string]interface{}); ok {
				if expires, ok := signed["expires"].(string); ok {
					snapshotExpiration = tuf_utils.CalculateExpirationDays(expires)
				}
			}
		}
	}

	if targetsData, err := ioutil.ReadFile(targetsPath); err == nil {
		var targetsMeta map[string]interface{}
		if err := json.Unmarshal(targetsData, &targetsMeta); err == nil {
			if signed, ok := targetsMeta["signed"].(map[string]interface{}); ok {
				if expires, ok := signed["expires"].(string); ok {
					targetsExpiration = tuf_utils.CalculateExpirationDays(expires)
				}
			}
		}
	}

	if timestampExpiration == 0 {
		timestampExpiration = 1
	}
	if snapshotExpiration == 0 {
		snapshotExpiration = 7
	}
	if targetsExpiration == 0 {
		targetsExpiration = 365
	}

	// Build payload
	timeout := 300
	payload := &models.BootstrapPayload{
		Settings: models.Settings{
			Roles: models.RolesData{
				Root:      models.RoleExpiration{Expiration: rootExpiration},
				Timestamp: models.RoleExpiration{Expiration: timestampExpiration},
				Snapshot:  models.RoleExpiration{Expiration: snapshotExpiration},
				Targets:   models.RoleExpiration{Expiration: targetsExpiration},
				Bins: &models.BinsRole{
					Expiration:            1,
					NumberOfDelegatedBins: 4,
				},
			},
		},
		Metadata: map[string]models.RootMetadata{
			"root": rootMetadata,
		},
		Timeout: &timeout,
	}

	logrus.Debug("Payload generation completed")
	return payload, nil
}
