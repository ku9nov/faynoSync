package bootstrap

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"faynoSync/mongod"
	"faynoSync/server/model"
	tuf_metadata "faynoSync/server/tuf/metadata"
	"faynoSync/server/tuf/models"
	"faynoSync/server/tuf/signing"
	tuf_utils "faynoSync/server/tuf/utils"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"go.mongodb.org/mongo-driver/mongo"
)

// GenerateRequest represents the request body for generating root keys
type GenerateRequest struct {
	AppName             string `json:"appName" binding:"required"`
	RootExpiration      *int   `json:"rootExpiration,omitempty"`
	TargetsExpiration   *int   `json:"targetsExpiration,omitempty"`
	SnapshotExpiration  *int   `json:"snapshotExpiration,omitempty"`
	TimestampExpiration *int   `json:"timestampExpiration,omitempty"`
	RoleName            string `json:"roleName,omitempty"`
}

// Generates root keys for the repository
func GenerateRootKeys(c *gin.Context, database *mongo.Database, redisClient *redis.Client, appRepository mongod.AppRepository) {

	adminName, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get admin name from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Parse request body for appName (required)
	var req GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logrus.Errorf("Failed to parse request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "appName is required in request body",
		})
		return
	}

	if req.AppName == "" {
		logrus.Error("appName is empty")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "appName cannot be empty",
		})
		return
	}

	// Validate that appRepository is available
	if appRepository == nil {
		logrus.Errorf("appName '%s' provided but AppRepository is nil", req.AppName)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "appName cannot be validated: AppRepository is not available",
		})
		return
	}

	logrus.Debugf("Generating root keys for admin: %s, appName: %s", adminName, req.AppName)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Set default expiration values if not provided
	rootExpiration := 365
	if req.RootExpiration != nil {
		rootExpiration = *req.RootExpiration
	}

	targetsExpiration := 7
	if req.TargetsExpiration != nil {
		targetsExpiration = *req.TargetsExpiration
	}

	snapshotExpiration := 7
	if req.SnapshotExpiration != nil {
		snapshotExpiration = *req.SnapshotExpiration
	}

	timestampExpiration := 1
	if req.TimestampExpiration != nil {
		timestampExpiration = *req.TimestampExpiration
	}

	logrus.Debugf("Using expiration values - root: %d days, targets: %d days, snapshot: %d days, timestamp: %d days",
		rootExpiration, targetsExpiration, snapshotExpiration, timestampExpiration)

	roles := repository.New()
	keys := map[string]ed25519.PrivateKey{}
	publicKeyIDs := map[string]string{}

	targets := metadata.Targets(tuf_utils.HelperExpireIn(targetsExpiration))
	roles.SetTargets("targets", targets)

	snapshot := metadata.Snapshot(tuf_utils.HelperExpireIn(snapshotExpiration))
	roles.SetSnapshot(snapshot)
	timestamp := metadata.Timestamp(tuf_utils.HelperExpireIn(timestampExpiration))
	roles.SetTimestamp(timestamp)
	root := metadata.Root(tuf_utils.HelperExpireIn(rootExpiration))
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

	// Validate that the provided appName exists and has Tuf enabled
	apps, err := appRepository.ListApps(ctx, adminName)
	if err != nil {
		logrus.Errorf("Failed to list apps: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list apps",
		})
		return
	}

	// Find the specific app and validate it has Tuf enabled
	var foundApp *model.App
	for i, app := range apps {
		if app == nil {
			continue
		}
		logrus.Debugf("App[%d]: ID=%s, AppName=%s, Owner=%s, Tuf=%v, Private=%v, Description=%s",
			i, app.ID.Hex(), app.AppName, app.Owner, app.Tuf, app.Private, app.Description)

		if app.AppName == req.AppName {
			foundApp = app
			break
		}
	}

	if foundApp == nil {
		logrus.Errorf("App '%s' not found for admin %s", req.AppName, adminName)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("appName '%s' not found for admin %s", req.AppName, adminName),
		})
		return
	}

	if !foundApp.Tuf {
		logrus.Errorf("App '%s' does not have Tuf enabled for admin %s", req.AppName, adminName)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("appName '%s' does not have Tuf enabled", req.AppName),
		})
		return
	}

	logrus.Infof("Validated appName '%s' for admin %s", req.AppName, adminName)

	if database != nil {
		err = signing.SavePrivateKeysToMongoDB(database, adminName, req.AppName, keys, publicKeyIDs, ctx)
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

	// Generate payload only for the specified appName
	payloadAppNames := []string{req.AppName}
	roleName := req.RoleName
	if roleName == "" {
		roleName = "default"
	}
	payload, err := generatePayload(tmpDir, adminName, payloadAppNames, roleName)
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

func generatePayload(metadataDir string, adminName string, tufAppNames []string, roleName string) (*models.BootstrapPayload, error) {
	logrus.Debug("Generating payload")

	rootPath := filepath.Join(metadataDir, "1.root.json")
	rootData, err := os.ReadFile(rootPath)
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

	if timestampData, err := os.ReadFile(timestampPath); err == nil {
		var timestampMeta map[string]interface{}
		if err := json.Unmarshal(timestampData, &timestampMeta); err == nil {
			if signed, ok := timestampMeta["signed"].(map[string]interface{}); ok {
				if expires, ok := signed["expires"].(string); ok {
					timestampExpiration = tuf_utils.CalculateExpirationDays(expires)
				}
			}
		}
	}

	if snapshotData, err := os.ReadFile(snapshotPath); err == nil {
		var snapshotMeta map[string]interface{}
		if err := json.Unmarshal(snapshotData, &snapshotMeta); err == nil {
			if signed, ok := snapshotMeta["signed"].(map[string]interface{}); ok {
				if expires, ok := signed["expires"].(string); ok {
					snapshotExpiration = tuf_utils.CalculateExpirationDays(expires)
				}
			}
		}
	}

	if targetsData, err := os.ReadFile(targetsPath); err == nil {
		var targetsMeta map[string]interface{}
		if err := json.Unmarshal(targetsData, &targetsMeta); err == nil {
			if signed, ok := targetsMeta["signed"].(map[string]interface{}); ok {
				if expires, ok := signed["expires"].(string); ok {
					targetsExpiration = tuf_utils.CalculateExpirationDays(expires)
				}
			}
		}
	}

	// Get online key ID from timestamp role (used for delegations)
	var onlineKeyID string
	if timestampRole, ok := rootMetadata.Signed.Roles["timestamp"]; ok && len(timestampRole.KeyIDs) > 0 {
		onlineKeyID = timestampRole.KeyIDs[0]
	} else {
		return nil, fmt.Errorf("failed to find timestamp key in root metadata")
	}

	// Get online key to include in delegations
	onlineKey, exists := rootMetadata.Signed.Keys[onlineKeyID]
	if !exists {
		return nil, fmt.Errorf("online key %s not found in root metadata", onlineKeyID)
	}

	// Create custom delegations with specific paths for each app that has Tuf=true
	var delegationPaths []string

	// Add paths for each app with Tuf=true
	for _, appName := range tufAppNames {
		delegationPaths = append(delegationPaths,
			fmt.Sprintf("%s/%s/", adminName, appName),                  // adminName/appName/...
			fmt.Sprintf("%s-%s/", appName, adminName),                  // appName-adminName/...
			fmt.Sprintf("electron-builder/%s-%s/", appName, adminName), // electron-builder/appName-adminName/...
			fmt.Sprintf("squirrel_windows/%s-%s/", appName, adminName), // squirrel_windows/appName-adminName/...
		)
	}

	// If no TUF apps found, keep the catch-all wildcard paths as fallback
	if len(delegationPaths) == 0 {
		logrus.Warn("No apps with Tuf=true found, using wildcard paths as fallback")
		delegationPaths = []string{
			fmt.Sprintf("%s/", adminName),                    // adminName/appName/...
			fmt.Sprintf("*-%s/", adminName),                  // appName-adminName/...
			fmt.Sprintf("electron-builder/*-%s/", adminName), // electron-builder/appName-adminName/...
			fmt.Sprintf("squirrel_windows/*-%s/", adminName), // squirrel_windows/appName-adminName/...
		}
	}

	logrus.Debugf("Created %d delegation paths for %d TUF apps", len(delegationPaths), len(tufAppNames))

	delegations := models.TUFDelegations{
		Keys: map[string]models.TUFKey{
			onlineKeyID: {
				KeyType: onlineKey.KeyType,
				Scheme:  onlineKey.KeyType, // For ed25519, scheme is same as keytype
				KeyVal: models.TUFKeyVal{
					Public: onlineKey.KeyVal.Public,
				},
			},
		},
		Roles: []models.TUFDelegatedRole{
			{
				Name:        roleName,
				Terminating: false, // Allow further delegation if needed? maybe true?
				KeyIDs:      []string{onlineKeyID},
				Threshold:   1,
				Paths:       delegationPaths,
			},
		},
	}

	// Build payload
	timeout := 300
	payload := &models.BootstrapPayload{
		AppName: tufAppNames[0],
		Settings: models.Settings{
			Roles: models.RolesData{
				Root:        models.RoleExpiration{Expiration: rootExpiration},
				Timestamp:   models.RoleExpiration{Expiration: timestampExpiration},
				Snapshot:    models.RoleExpiration{Expiration: snapshotExpiration},
				Targets:     models.RoleExpiration{Expiration: targetsExpiration},
				Delegations: &delegations,
			},
		},
		Metadata: map[string]models.RootMetadata{
			"root": rootMetadata,
		},
		Timeout: &timeout,
	}

	logrus.Debug("Payload generation completed with custom delegations")
	return payload, nil
}
