package signing

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"faynoSync/server/tuf/models"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func SavePrivateKeysToMongoDB(database *mongo.Database, adminName string, keys map[string]ed25519.PrivateKey, publicKeyIDs map[string]string, ctx context.Context) error {
	collection := database.Collection("tuf_private_keys")
	now := time.Now()

	_, err := collection.DeleteMany(ctx, bson.M{"admin_name": adminName})
	if err != nil {
		logrus.Warnf("Failed to delete existing keys for admin %s: %v", adminName, err)
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
			RoleName:   roleName,
			KeyID:      keyID,
			PrivateKey: privateKeyBase64,
			KeyType:    "ed25519",
			CreatedAt:  now,
			UpdatedAt:  now,
		}

		_, err := collection.InsertOne(ctx, keyDoc)
		if err != nil {
			logrus.Errorf("Failed to save private key for role %s, admin %s: %v", roleName, adminName, err)
			return fmt.Errorf("failed to save private key for role %s: %w", roleName, err)
		}
		logrus.Debugf("Successfully saved private key for role %s, admin %s, key_id: %s", roleName, adminName, keyID)
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
