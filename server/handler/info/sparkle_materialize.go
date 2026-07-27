package info

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"faynoSync/server/utils/updaters/sparkle"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type sparkleFeedKey struct {
	channel  string
	platform string
	arch     string
}

// MaterializeSparkleForApp regenerates and writes all sparkle appcasts for an app.
// It self-gates: apps without sparkle artifacts produce no work and no writes.
func MaterializeSparkleForApp(ctx context.Context, database *mongo.Database, env *viper.Viper, owner, appName string) {
	factory := utils.NewStorageFactory(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		logrus.Errorf("Failed to create storage client for sparkle appcast materialization: %v", err)
		return
	}
	if err := MaterializeSparkleFeeds(ctx, database, storageClient, env, owner, appName); err != nil {
		logrus.Errorf("Failed to materialize sparkle appcasts for %s/%s: %v", owner, appName, err)
	}
}

func MaterializeSparkleFeeds(ctx context.Context, database *mongo.Database, storageClient utils.StorageClient, env *viper.Viper, owner, appName string) error {
	tuples, err := discoverSparkleTuples(ctx, database, owner, appName)
	if err != nil {
		return err
	}
	if len(tuples) == 0 {
		logrus.Debugf("No sparkle versions for %s/%s, skipping appcast materialization", owner, appName)
		return nil
	}
	return materializeSparkleKeys(ctx, database, storageClient, env, owner, appName, tuples)
}

func MaterializeSparkleForTuples(ctx context.Context, database *mongo.Database, env *viper.Viper, owner, appName string, tuples []FeedTuple) {
	factory := utils.NewStorageFactory(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		logrus.Errorf("Failed to create storage client for sparkle appcast materialization: %v", err)
		return
	}
	if err := MaterializeSparkleFeedsForTuples(ctx, database, storageClient, env, owner, appName, tuples); err != nil {
		logrus.Errorf("Failed to materialize sparkle appcasts for %s/%s: %v", owner, appName, err)
	}
}

func MaterializeSparkleForTuplesOrFull(ctx context.Context, database *mongo.Database, env *viper.Viper, owner, appName string, tuples []FeedTuple) {
	if len(tuples) == 0 {
		MaterializeSparkleForApp(ctx, database, env, owner, appName)
		return
	}
	MaterializeSparkleForTuples(ctx, database, env, owner, appName, tuples)
}

func MaterializeSparkleFeedsForTuples(ctx context.Context, database *mongo.Database, storageClient utils.StorageClient, env *viper.Viper, owner, appName string, tuples []FeedTuple) error {
	keys := sparkleKeysFromTuples(tuples)
	if len(keys) == 0 {
		return nil
	}
	return materializeSparkleKeys(ctx, database, storageClient, env, owner, appName, keys)
}

func materializeSparkleKeys(ctx context.Context, database *mongo.Database, storageClient utils.StorageClient, env *viper.Viper, owner, appName string, keys []sparkleFeedKey) error {
	bucketName := env.GetString("S3_BUCKET_NAME")
	var errs []error
	for _, key := range keys {
		releases, err := loadSparkleReleases(ctx, database, owner, appName, key.channel, key.platform, key.arch)
		if err != nil {
			errs = append(errs, fmt.Errorf("load releases for %+v: %w", key, err))
			continue
		}

		appcast, err := sparkle.BuildAppcast(appName, releases)
		if err != nil {
			errs = append(errs, fmt.Errorf("build appcast for %+v: %w", key, err))
			continue
		}

		objectKey := sparkle.AppcastObjectKey(owner, appName, key.platform, key.arch, key.channel)
		if err := writeSparkleFeed(ctx, storageClient, bucketName, objectKey, appcast); err != nil {
			errs = append(errs, fmt.Errorf("write appcast %s: %w", objectKey, err))
			continue
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("materialized %d/%d sparkle appcasts, %d failed: %w", len(keys)-len(errs), len(keys), len(errs), errors.Join(errs...))
	}

	return nil
}

func sparkleKeysFromTuples(tuples []FeedTuple) []sparkleFeedKey {
	seen := make(map[sparkleFeedKey]struct{})
	var keys []sparkleFeedKey
	for _, t := range tuples {
		if t.Channel == "" || t.Platform == "" || t.Arch == "" {
			continue
		}
		key := sparkleFeedKey{channel: t.Channel, platform: t.Platform, arch: t.Arch}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func discoverSparkleTuples(ctx context.Context, database *mongo.Database, owner, appName string) ([]sparkleFeedKey, error) {
	metaCollection := database.Collection("apps_meta")

	appID, err := resolveMetaID(ctx, metaCollection, "app_name", appName, owner)
	if err != nil {
		return nil, err
	}

	cursor, err := database.Collection("apps").Find(ctx, bson.D{
		{Key: "app_id", Value: appID},
		{Key: "owner", Value: owner},
		{Key: "artifacts.sparkle", Value: bson.D{{Key: "$exists", Value: true}}},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query sparkle versions: %w", err)
	}
	defer cursor.Close(ctx)

	var versions []model.SpecificApp
	if err := cursor.All(ctx, &versions); err != nil {
		return nil, fmt.Errorf("failed to decode sparkle versions: %w", err)
	}
	if len(versions) == 0 {
		return nil, nil
	}

	nameResolver, err := buildMetaNameResolver(ctx, metaCollection, versions)
	if err != nil {
		return nil, err
	}

	seen := make(map[sparkleFeedKey]struct{})
	var tuples []sparkleFeedKey
	for _, v := range versions {
		channel := nameResolver[v.ChannelID]
		for _, a := range v.Artifacts {
			if a.Sparkle == nil {
				continue
			}
			key := sparkleFeedKey{
				channel:  channel,
				platform: nameResolver[a.Platform],
				arch:     nameResolver[a.Arch],
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			tuples = append(tuples, key)
		}
	}

	return tuples, nil
}

func writeSparkleFeed(ctx context.Context, storageClient utils.StorageClient, bucketName, objectKey string, feed []byte) error {
	if statClient, ok := storageClient.(cdnObjectStatClient); ok {
		existingETag, exists, err := statClient.GetObjectETag(ctx, bucketName, objectKey)
		if err != nil {
			logrus.Errorf("Failed to stat existing sparkle appcast %s/%s: %v", bucketName, objectKey, err)
		} else if exists && existingETag != "" {
			newETag := strings.ToLower(fmt.Sprintf("%x", md5.Sum(feed)))
			if normalizeETag(existingETag) == newETag {
				logrus.Debugf("Skipping sparkle appcast write, content unchanged: %s/%s", bucketName, objectKey)
				return nil
			}
		}
	}

	fileReader := &memoryFile{Reader: bytes.NewReader(feed)}
	if uploader, ok := storageClient.(cdnPublicUploaderWithCacheControl); ok {
		if _, err := uploader.UploadPublicObjectWithCacheControl(ctx, bucketName, objectKey, fileReader, "application/xml", latestResponseCacheControl); err != nil {
			return fmt.Errorf("failed to write sparkle appcast %s/%s: %w", bucketName, objectKey, err)
		}
	} else if _, err := storageClient.UploadPublicObject(ctx, bucketName, objectKey, fileReader, "application/xml"); err != nil {
		return fmt.Errorf("failed to write sparkle appcast %s/%s: %w", bucketName, objectKey, err)
	}

	logrus.Debugf("Materialized sparkle appcast: %s/%s", bucketName, objectKey)
	return nil
}
