package info

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"faynoSync/server/utils/updaters/velopack"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type velopackFeedKey struct {
	channel  string
	platform string
	arch     string
}

// MaterializeVelopackForApp regenerates and writes all velopack feeds for an app.
// It self-gates: apps without velopack artifacts produce no work and no writes.
func MaterializeVelopackForApp(ctx context.Context, database *mongo.Database, env *viper.Viper, owner, appName string) {
	factory := utils.NewStorageFactory(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		logrus.Errorf("Failed to create storage client for velopack feed materialization: %v", err)
		return
	}
	if err := MaterializeVelopackFeeds(ctx, database, storageClient, env, owner, appName); err != nil {
		logrus.Errorf("Failed to materialize velopack feeds for %s/%s: %v", owner, appName, err)
	}
}

func MaterializeVelopackFeeds(ctx context.Context, database *mongo.Database, storageClient utils.StorageClient, env *viper.Viper, owner, appName string) error {
	tuples, err := discoverVelopackTuples(ctx, database, owner, appName)
	if err != nil {
		return err
	}
	if len(tuples) == 0 {
		logrus.Debugf("No velopack versions for %s/%s, skipping feed materialization", owner, appName)
		return nil
	}
	return materializeVelopackKeys(ctx, database, storageClient, env, owner, appName, tuples)
}

func MaterializeVelopackForTuples(ctx context.Context, database *mongo.Database, env *viper.Viper, owner, appName string, tuples []FeedTuple) {
	factory := utils.NewStorageFactory(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		logrus.Errorf("Failed to create storage client for velopack feed materialization: %v", err)
		return
	}
	if err := MaterializeVelopackFeedsForTuples(ctx, database, storageClient, env, owner, appName, tuples); err != nil {
		logrus.Errorf("Failed to materialize velopack feeds for %s/%s: %v", owner, appName, err)
	}
}

func MaterializeVelopackForTuplesOrFull(ctx context.Context, database *mongo.Database, env *viper.Viper, owner, appName string, tuples []FeedTuple) {
	if len(tuples) == 0 {
		MaterializeVelopackForApp(ctx, database, env, owner, appName)
		return
	}
	MaterializeVelopackForTuples(ctx, database, env, owner, appName, tuples)
}

func MaterializeVelopackFeedsForTuples(ctx context.Context, database *mongo.Database, storageClient utils.StorageClient, env *viper.Viper, owner, appName string, tuples []FeedTuple) error {
	keys := velopackKeysFromTuples(tuples)
	if len(keys) == 0 {
		return nil
	}
	return materializeVelopackKeys(ctx, database, storageClient, env, owner, appName, keys)
}

func materializeVelopackKeys(ctx context.Context, database *mongo.Database, storageClient utils.StorageClient, env *viper.Viper, owner, appName string, keys []velopackFeedKey) error {
	bucketName := env.GetString("S3_BUCKET_NAME")
	var errs []error
	for _, key := range keys {
		releases, err := loadVelopackReleases(ctx, database, owner, appName, key.channel, key.platform, key.arch)
		if err != nil {
			errs = append(errs, fmt.Errorf("load releases for %+v: %w", key, err))
			continue
		}

		feed, err := velopack.BuildFeed(appName, releases)
		if err != nil {
			errs = append(errs, fmt.Errorf("build feed for %+v: %w", key, err))
			continue
		}

		objectKey := velopack.FeedObjectKey(owner, appName, key.platform, key.arch, key.channel)
		if err := writeVelopackFeed(ctx, storageClient, bucketName, objectKey, feed); err != nil {
			errs = append(errs, fmt.Errorf("write feed %s: %w", objectKey, err))
			continue
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("materialized %d/%d velopack feeds, %d failed: %w", len(keys)-len(errs), len(keys), len(errs), errors.Join(errs...))
	}

	return nil
}

func velopackKeysFromTuples(tuples []FeedTuple) []velopackFeedKey {
	seen := make(map[velopackFeedKey]struct{})
	var keys []velopackFeedKey
	for _, t := range tuples {
		if t.Channel == "" || t.Platform == "" || t.Arch == "" {
			continue
		}
		key := velopackFeedKey{channel: t.Channel, platform: t.Platform, arch: t.Arch}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func discoverVelopackTuples(ctx context.Context, database *mongo.Database, owner, appName string) ([]velopackFeedKey, error) {
	metaCollection := database.Collection("apps_meta")

	appID, err := resolveMetaID(ctx, metaCollection, "app_name", appName, owner)
	if err != nil {
		return nil, err
	}

	cursor, err := database.Collection("apps").Find(ctx, bson.D{
		{Key: "app_id", Value: appID},
		{Key: "owner", Value: owner},
		{Key: "artifacts.velopack", Value: bson.D{{Key: "$exists", Value: true}}},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query velopack versions: %w", err)
	}
	defer cursor.Close(ctx)

	var versions []model.SpecificApp
	if err := cursor.All(ctx, &versions); err != nil {
		return nil, fmt.Errorf("failed to decode velopack versions: %w", err)
	}
	if len(versions) == 0 {
		return nil, nil
	}

	nameResolver, err := buildMetaNameResolver(ctx, metaCollection, versions)
	if err != nil {
		return nil, err
	}

	seen := make(map[velopackFeedKey]struct{})
	var tuples []velopackFeedKey
	for _, v := range versions {
		channel := nameResolver[v.ChannelID]
		for _, a := range v.Artifacts {
			if a.Velopack == nil {
				continue
			}
			key := velopackFeedKey{
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

func writeVelopackFeed(ctx context.Context, storageClient utils.StorageClient, bucketName, objectKey string, feed []byte) error {
	if statClient, ok := storageClient.(cdnObjectStatClient); ok {
		existingETag, exists, err := statClient.GetObjectETag(ctx, bucketName, objectKey)
		if err != nil {
			logrus.Errorf("Failed to stat existing velopack feed %s/%s: %v", bucketName, objectKey, err)
		} else if exists && existingETag != "" {
			newETag := strings.ToLower(fmt.Sprintf("%x", md5.Sum(feed)))
			if normalizeETag(existingETag) == newETag {
				logrus.Debugf("Skipping velopack feed write, content unchanged: %s/%s", bucketName, objectKey)
				return nil
			}
		}
	}

	fileReader := &memoryFile{Reader: bytes.NewReader(feed)}
	if uploader, ok := storageClient.(cdnPublicUploaderWithCacheControl); ok {
		if _, err := uploader.UploadPublicObjectWithCacheControl(ctx, bucketName, objectKey, fileReader, "application/json", latestResponseCacheControl); err != nil {
			return fmt.Errorf("failed to write velopack feed %s/%s: %w", bucketName, objectKey, err)
		}
	} else if _, err := storageClient.UploadPublicObject(ctx, bucketName, objectKey, fileReader, "application/json"); err != nil {
		return fmt.Errorf("failed to write velopack feed %s/%s: %w", bucketName, objectKey, err)
	}

	logrus.Debugf("Materialized velopack feed: %s/%s", bucketName, objectKey)
	return nil
}

func velopackNotesForVersion(v model.SpecificApp) string {
	for _, entry := range v.Changelog {
		if entry.Version == v.Version {
			return entry.Changes
		}
	}
	return ""
}

func buildMetaNameResolver(ctx context.Context, metaCollection *mongo.Collection, versions []model.SpecificApp) (map[primitive.ObjectID]string, error) {
	idSet := make(map[primitive.ObjectID]struct{})
	for _, v := range versions {
		idSet[v.ChannelID] = struct{}{}
		for _, a := range v.Artifacts {
			idSet[a.Platform] = struct{}{}
			idSet[a.Arch] = struct{}{}
		}
	}

	ids := make([]primitive.ObjectID, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}

	cursor, err := metaCollection.Find(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: ids}}}})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve apps_meta names: %w", err)
	}
	defer cursor.Close(ctx)

	resolver := make(map[primitive.ObjectID]string)
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			logrus.Errorf("Failed to decode apps_meta doc: %v", err)
			continue
		}
		id, ok := doc["_id"].(primitive.ObjectID)
		if !ok {
			continue
		}
		for _, field := range []string{"channel_name", "platform_name", "arch_id"} {
			if name, ok := doc[field].(string); ok {
				resolver[id] = name
				break
			}
		}
	}

	return resolver, nil
}
