package mongod

import (
	"context"
	"faynoSync/server/utils"
	"faynoSync/server/utils/updaters"
	"faynoSync/server/utils/updaters/sparkle"
	"faynoSync/server/utils/updaters/velopack"
	"fmt"
	"path"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// feedLinkCandidate is a cheap prefilter, not the decision
const feedLinkCandidate = `(?i)(\.ya?ml|\.xml|releases\.[^/%]*\.json|releases)$`

func updaterFromObjectKey(objectKey string) string {
	switch {
	case strings.HasPrefix(objectKey, velopack.UpdaterType+"/"):
		return velopack.UpdaterType
	case strings.HasPrefix(objectKey, sparkle.UpdaterType+"/"):
		return sparkle.UpdaterType
	case strings.HasPrefix(objectKey, "squirrel_windows/"):
		return "squirrel_windows"
	case strings.HasPrefix(objectKey, "electron-builder/"):
		return "electron-builder"
	}
	return ""
}

// linkIsFeed reports whether an artifact link points at its updater's feed.
func linkIsFeed(link string, env *viper.Viper) bool {
	objectKey, err := utils.ExtractS3Key(link, strings.Contains(link, "/download?key="), env)
	if err != nil {
		logrus.Debugf("Feed backfill: cannot extract object key from %s: %v", link, err)
		return false
	}
	return updaters.IsFeedFile(path.Base(objectKey), updaterFromObjectKey(objectKey))
}

// backfillFeedArtifacts marks pre-existing feed artifacts so publish stops adding them
// to TUF targets. It only ever sets is_feed: true — tuf_signed is left alone, because
// feeds signed before the split really are in targets, and removing a stale target is a
// TUF operation (new targets + snapshot + timestamp), not a Mongo update.
func backfillFeedArtifacts(ctx context.Context, database *mongo.Database, env *viper.Viper) error {
	collection := database.Collection("apps")
	filter := bson.M{"artifacts": bson.M{"$elemMatch": bson.M{
		"link":    bson.M{"$regex": feedLinkCandidate},
		"is_feed": bson.M{"$exists": false},
	}}}
	cursor, err := collection.Find(ctx, filter, options.Find().SetProjection(bson.M{"artifacts.link": 1, "artifacts.is_feed": 1}))
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	updated := 0
	for cursor.Next(ctx) {
		var doc struct {
			ID        primitive.ObjectID `bson:"_id"`
			Artifacts []struct {
				Link   string `bson:"link"`
				IsFeed bool   `bson:"is_feed"`
			} `bson:"artifacts"`
		}
		if err := cursor.Decode(&doc); err != nil {
			return err
		}
		for i, artifact := range doc.Artifacts {
			if artifact.IsFeed || !linkIsFeed(artifact.Link, env) {
				continue
			}
			// Matching on the link guards against the array having changed since it was read.
			_, err := collection.UpdateOne(ctx,
				bson.M{"_id": doc.ID, fmt.Sprintf("artifacts.%d.link", i): artifact.Link},
				bson.M{"$set": bson.M{fmt.Sprintf("artifacts.%d.is_feed", i): true}},
			)
			if err != nil {
				return err
			}
			updated++
		}
	}
	if err := cursor.Err(); err != nil {
		return err
	}
	logrus.Debugf("Marked %d artifacts as updater feeds", updated)
	return nil
}
