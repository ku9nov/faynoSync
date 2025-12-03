package bootstrap

import (
	"context"
	"faynoSync/server/tuf/models"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// saveSettings saves bootstrap settings to Redis
func saveSettings(redisClient *redis.Client, adminName string, appName string, payload *models.BootstrapPayload) {
	logrus.Debug("Saving bootstrap settings to Redis")
	if redisClient == nil {
		logrus.Warn("Redis client is nil, skipping settings save")
		return
	}

	ctx := context.Background()
	roles := payload.Settings.Roles

	rootMetadata, exists := payload.Metadata["root"]
	if !exists {
		logrus.Error("Root metadata not found in payload")
		return
	}

	rootThreshold := 1
	rootNumKeys := len(rootMetadata.Signatures)
	if len(rootMetadata.Signed.Roles) > 0 {
		if rootRole, ok := rootMetadata.Signed.Roles["root"]; ok {
			rootThreshold = rootRole.Threshold
		}
	}

	// Build key suffix: adminName_appName if appName is provided, otherwise just adminName
	keySuffix := adminName
	if appName != "" {
		keySuffix = adminName + "_" + appName
	}

	// Save ROOT settings (with admin name and app name suffix)
	if err := redisClient.Set(ctx, "ROOT_EXPIRATION_"+keySuffix, roles.Root.Expiration, 0).Err(); err != nil {
		logrus.Errorf("Failed to save ROOT_EXPIRATION for admin %s, app %s: %v", adminName, appName, err)
	}
	if err := redisClient.Set(ctx, "ROOT_THRESHOLD_"+keySuffix, rootThreshold, 0).Err(); err != nil {
		logrus.Errorf("Failed to save ROOT_THRESHOLD for admin %s, app %s: %v", adminName, appName, err)
	}
	if err := redisClient.Set(ctx, "ROOT_NUM_KEYS_"+keySuffix, rootNumKeys, 0).Err(); err != nil {
		logrus.Errorf("Failed to save ROOT_NUM_KEYS for admin %s, app %s: %v", adminName, appName, err)
	}

	// Save TARGETS settings (with admin name and app name suffix)
	if err := redisClient.Set(ctx, "TARGETS_EXPIRATION_"+keySuffix, roles.Targets.Expiration, 0).Err(); err != nil {
		logrus.Errorf("Failed to save TARGETS_EXPIRATION for admin %s, app %s: %v", adminName, appName, err)
	}
	if err := redisClient.Set(ctx, "TARGETS_THRESHOLD_"+keySuffix, 1, 0).Err(); err != nil {
		logrus.Errorf("Failed to save TARGETS_THRESHOLD for admin %s, app %s: %v", adminName, appName, err)
	}
	if err := redisClient.Set(ctx, "TARGETS_NUM_KEYS_"+keySuffix, 1, 0).Err(); err != nil {
		logrus.Errorf("Failed to save TARGETS_NUM_KEYS for admin %s, app %s: %v", adminName, appName, err)
	}
	if err := redisClient.Set(ctx, "TARGETS_ONLINE_KEY_"+keySuffix, true, 0).Err(); err != nil {
		logrus.Errorf("Failed to save TARGETS_ONLINE_KEY for admin %s, app %s: %v", adminName, appName, err)
	}

	// Save SNAPSHOT settings (with admin name and app name suffix)
	if err := redisClient.Set(ctx, "SNAPSHOT_EXPIRATION_"+keySuffix, roles.Snapshot.Expiration, 0).Err(); err != nil {
		logrus.Errorf("Failed to save SNAPSHOT_EXPIRATION for admin %s, app %s: %v", adminName, appName, err)
	}
	if err := redisClient.Set(ctx, "SNAPSHOT_THRESHOLD_"+keySuffix, 1, 0).Err(); err != nil {
		logrus.Errorf("Failed to save SNAPSHOT_THRESHOLD for admin %s, app %s: %v", adminName, appName, err)
	}
	if err := redisClient.Set(ctx, "SNAPSHOT_NUM_KEYS_"+keySuffix, 1, 0).Err(); err != nil {
		logrus.Errorf("Failed to save SNAPSHOT_NUM_KEYS for admin %s, app %s: %v", adminName, appName, err)
	}

	// Save TIMESTAMP settings (with admin name and app name suffix)
	if err := redisClient.Set(ctx, "TIMESTAMP_EXPIRATION_"+keySuffix, roles.Timestamp.Expiration, 0).Err(); err != nil {
		logrus.Errorf("Failed to save TIMESTAMP_EXPIRATION for admin %s, app %s: %v", adminName, appName, err)
	}
	if err := redisClient.Set(ctx, "TIMESTAMP_THRESHOLD_"+keySuffix, 1, 0).Err(); err != nil {
		logrus.Errorf("Failed to save TIMESTAMP_THRESHOLD for admin %s, app %s: %v", adminName, appName, err)
	}
	if err := redisClient.Set(ctx, "TIMESTAMP_NUM_KEYS_"+keySuffix, 1, 0).Err(); err != nil {
		logrus.Errorf("Failed to save TIMESTAMP_NUM_KEYS for admin %s, app %s: %v", adminName, appName, err)
	}

	// Save BINS settings if present (with admin name and app name suffix)
	if roles.Bins != nil {
		if err := redisClient.Set(ctx, "BINS_EXPIRATION_"+keySuffix, roles.Bins.Expiration, 0).Err(); err != nil {
			logrus.Errorf("Failed to save BINS_EXPIRATION for admin %s, app %s: %v", adminName, appName, err)
		}
		if err := redisClient.Set(ctx, "BINS_THRESHOLD_"+keySuffix, 1, 0).Err(); err != nil {
			logrus.Errorf("Failed to save BINS_THRESHOLD for admin %s, app %s: %v", adminName, appName, err)
		}
		if err := redisClient.Set(ctx, "BINS_NUM_KEYS_"+keySuffix, 1, 0).Err(); err != nil {
			logrus.Errorf("Failed to save BINS_NUM_KEYS for admin %s, app %s: %v", adminName, appName, err)
		}
		if err := redisClient.Set(ctx, "NUMBER_OF_DELEGATED_BINS_"+keySuffix, roles.Bins.NumberOfDelegatedBins, 0).Err(); err != nil {
			logrus.Errorf("Failed to save NUMBER_OF_DELEGATED_BINS for admin %s, app %s: %v", adminName, appName, err)
		}
	}

	logrus.Debug("Successfully saved all bootstrap settings to Redis")
}
