package bootstrap

import (
	"context"
	"faynoSync/server/tuf/models"
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type recoveredBootstrapSettings struct {
	RootExpiration      int
	RootThreshold       int
	RootNumKeys         int
	TargetsExpiration   int
	TargetsThreshold    int
	TargetsNumKeys      int
	SnapshotExpiration  int
	SnapshotThreshold   int
	SnapshotNumKeys     int
	TimestampExpiration int
	TimestampThreshold  int
	TimestampNumKeys    int
	TargetsOnlineKey    bool
	DelegatedExpiration map[string]int
}

func saveRecoveredSettings(
	redisClient *redis.Client,
	adminName string,
	appName string,
	settings recoveredBootstrapSettings,
) error {
	if redisClient == nil {
		return fmt.Errorf("redis client is nil")
	}

	ctx := context.Background()
	keySuffix := adminName
	if appName != "" {
		keySuffix = adminName + "_" + appName
	}

	writeKey := func(key string, value interface{}) error {
		return redisClient.Set(ctx, key, value, 0).Err()
	}

	coreSettings := map[string]interface{}{
		"ROOT_EXPIRATION_" + keySuffix:      settings.RootExpiration,
		"ROOT_THRESHOLD_" + keySuffix:       settings.RootThreshold,
		"ROOT_NUM_KEYS_" + keySuffix:        settings.RootNumKeys,
		"TARGETS_EXPIRATION_" + keySuffix:   settings.TargetsExpiration,
		"TARGETS_THRESHOLD_" + keySuffix:    settings.TargetsThreshold,
		"TARGETS_NUM_KEYS_" + keySuffix:     settings.TargetsNumKeys,
		"TARGETS_ONLINE_KEY_" + keySuffix:   settings.TargetsOnlineKey,
		"SNAPSHOT_EXPIRATION_" + keySuffix:  settings.SnapshotExpiration,
		"SNAPSHOT_THRESHOLD_" + keySuffix:   settings.SnapshotThreshold,
		"SNAPSHOT_NUM_KEYS_" + keySuffix:    settings.SnapshotNumKeys,
		"TIMESTAMP_EXPIRATION_" + keySuffix: settings.TimestampExpiration,
		"TIMESTAMP_THRESHOLD_" + keySuffix:  settings.TimestampThreshold,
		"TIMESTAMP_NUM_KEYS_" + keySuffix:   settings.TimestampNumKeys,
		"ROOT_SIGNING_" + keySuffix:         "",
	}

	for key, value := range coreSettings {
		if err := writeKey(key, value); err != nil {
			return fmt.Errorf("failed to save %s: %w", key, err)
		}
	}

	for roleName, expiration := range settings.DelegatedExpiration {
		key := fmt.Sprintf("%s_EXPIRATION_%s", roleName, keySuffix)
		if err := writeKey(key, expiration); err != nil {
			return fmt.Errorf("failed to save delegated expiration %s: %w", key, err)
		}
	}

	return nil
}

// saveSettings saves bootstrap settings to Redis
func saveSettings(redisClient *redis.Client, adminName string, appName string, payload *models.BootstrapPayload) {
	logrus.Debug("Saving bootstrap settings to Redis")
	if redisClient == nil {
		logrus.Warn("Redis client is nil, skipping settings save")
		return
	}

	roles := payload.Settings.Roles

	rootMetadata, exists := payload.Metadata["root"]
	if !exists {
		logrus.Error("Root metadata not found in payload")
		return
	}

	rootThreshold := 1
	rootNumKeys := len(rootMetadata.Signatures)
	targetsThreshold := 1
	targetsNumKeys := 1
	snapshotThreshold := 1
	snapshotNumKeys := 1
	timestampThreshold := 1
	timestampNumKeys := 1
	if len(rootMetadata.Signed.Roles) > 0 {
		if r, ok := rootMetadata.Signed.Roles["root"]; ok {
			rootThreshold = r.Threshold
		}
		if r, ok := rootMetadata.Signed.Roles["targets"]; ok {
			targetsThreshold = r.Threshold
			targetsNumKeys = len(r.KeyIDs)
			if targetsNumKeys < 1 {
				targetsNumKeys = 1
			}
		}
		if r, ok := rootMetadata.Signed.Roles["snapshot"]; ok {
			snapshotThreshold = r.Threshold
			snapshotNumKeys = len(r.KeyIDs)
			if snapshotNumKeys < 1 {
				snapshotNumKeys = 1
			}
		}
		if r, ok := rootMetadata.Signed.Roles["timestamp"]; ok {
			timestampThreshold = r.Threshold
			timestampNumKeys = len(r.KeyIDs)
			if timestampNumKeys < 1 {
				timestampNumKeys = 1
			}
		}
	}

	recovered := recoveredBootstrapSettings{
		RootExpiration:      roles.Root.Expiration,
		RootThreshold:       rootThreshold,
		RootNumKeys:         rootNumKeys,
		TargetsExpiration:   roles.Targets.Expiration,
		TargetsThreshold:    targetsThreshold,
		TargetsNumKeys:      targetsNumKeys,
		SnapshotExpiration:  roles.Snapshot.Expiration,
		SnapshotThreshold:   snapshotThreshold,
		SnapshotNumKeys:     snapshotNumKeys,
		TimestampExpiration: roles.Timestamp.Expiration,
		TimestampThreshold:  timestampThreshold,
		TimestampNumKeys:    timestampNumKeys,
		TargetsOnlineKey:    true,
		DelegatedExpiration: map[string]int{},
	}

	if err := saveRecoveredSettings(redisClient, adminName, appName, recovered); err != nil {
		logrus.Errorf("Failed to save bootstrap settings for admin %s, app %s: %v", adminName, appName, err)
		return
	}

	logrus.Debug("Successfully saved all bootstrap settings to Redis")
}
