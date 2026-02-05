package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"faynoSync/server/tuf/models"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func SavePrivateKeysToMongoDB(database *mongo.Database, adminName string, appName string, keys map[string]ed25519.PrivateKey, publicKeyIDs map[string]string, ctx context.Context) error {
	collection := database.Collection("tuf_private_keys")
	now := time.Now()

	// Delete existing keys for this admin and app combination
	deleteFilter := bson.M{"admin_name": adminName}
	if appName != "" {
		deleteFilter["app_name"] = appName
	} else {
		// If appName is empty, delete keys where app_name is empty or doesn't exist
		deleteFilter["$or"] = []bson.M{
			{"app_name": ""},
			{"app_name": bson.M{"$exists": false}},
		}
	}
	_, err := collection.DeleteMany(ctx, deleteFilter)
	if err != nil {
		logrus.Warnf("Failed to delete existing keys for admin %s, app %s: %v", adminName, appName, err)
	}

	for roleName, privateKey := range keys {
		keyID, exists := publicKeyIDs[roleName]
		if !exists {
			logrus.Warnf("No key ID found for role %s, skipping", roleName)
			continue
		}

		privateKeyBytes := privateKey.Seed()
		privateKeyBase64 := base64.StdEncoding.EncodeToString(privateKeyBytes)

		keyDoc := models.TUFPrivateKey{
			AdminName:  adminName,
			AppName:    appName,
			RoleName:   roleName,
			KeyID:      keyID,
			PrivateKey: privateKeyBase64,
			KeyType:    "ed25519",
			CreatedAt:  now,
			UpdatedAt:  now,
		}

		_, err := collection.InsertOne(ctx, keyDoc)
		if err != nil {
			logrus.Errorf("Failed to save private key for role %s, admin %s, app %s: %v", roleName, adminName, appName, err)
			return fmt.Errorf("failed to save private key for role %s: %w", roleName, err)
		}
		logrus.Debugf("Successfully saved private key for role %s, admin %s, app %s, key_id: %s", roleName, adminName, appName, keyID)
	}

	return nil
}

func LoadPrivateKeyFromMongoDB(database *mongo.Database, adminName string, keyID string, ctx context.Context) (ed25519.PrivateKey, error) {
	collection := database.Collection("tuf_private_keys")

	var keyDoc struct {
		PrivateKey string `bson:"private_key"`
		KeyType    string `bson:"key_type"`
	}

	err := collection.FindOne(ctx, bson.M{
		"admin_name": adminName,
		"key_id":     keyID,
	}).Decode(&keyDoc)

	if err != nil {
		return nil, fmt.Errorf("failed to find private key for key_id %s, admin %s: %w", keyID, adminName, err)
	}

	privateKeyBytes, err := base64.StdEncoding.DecodeString(keyDoc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	if keyDoc.KeyType != "ed25519" {
		return nil, fmt.Errorf("unsupported key type: %s", keyDoc.KeyType)
	}

	privateKey := ed25519.NewKeyFromSeed(privateKeyBytes)

	return privateKey, nil
}

func LoadPrivateKeyFromFilesystem(keyID string, keyURI string) (ed25519.PrivateKey, error) {
	env := viper.GetViper()
	keyDir := env.GetString("ONLINE_KEY_DIR")
	if keyDir == "" {
		return nil, fmt.Errorf("ONLINE_KEY_DIR environment variable not set")
	}

	var fileName string
	if strings.HasPrefix(keyURI, "fn:") {
		fileName = strings.TrimPrefix(keyURI, "fn:")
	} else if keyURI != "" {
		fileName = keyURI
	} else {
		fileName = keyID
	}

	keyPath := filepath.Join(keyDir, fileName)
	logrus.Debugf("Loading private key from filesystem: %s (keyID: %s)", keyPath, keyID)

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", keyPath, err)
	}

	block, _ := pem.Decode(keyData)
	if block != nil {
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			if ed25519Key, ok := privateKey.(ed25519.PrivateKey); ok {
				logrus.Debugf("Successfully loaded Ed25519 private key from PEM file: %s", keyPath)
				return ed25519Key, nil
			}
		}
		if len(block.Bytes) == 32 {
			ed25519Key := ed25519.NewKeyFromSeed(block.Bytes)
			logrus.Debugf("Successfully loaded Ed25519 private key from raw seed in PEM: %s", keyPath)
			return ed25519Key, nil
		}
	}

	if len(keyData) == 32 {
		ed25519Key := ed25519.NewKeyFromSeed(keyData)
		logrus.Debugf("Successfully loaded Ed25519 private key from raw seed: %s", keyPath)
		return ed25519Key, nil
	}

	keyDataStr := strings.TrimSpace(string(keyData))
	if len(keyDataStr) == 64 {
		seedBytes, err := hex.DecodeString(keyDataStr)
		if err == nil && len(seedBytes) == 32 {
			ed25519Key := ed25519.NewKeyFromSeed(seedBytes)
			logrus.Debugf("Successfully loaded Ed25519 private key from hex-encoded seed: %s", keyPath)
			return ed25519Key, nil
		}
	}

	return nil, fmt.Errorf("could not load private key from %s: expected PEM format, raw 32 bytes, or hex-encoded seed", keyPath)
}
