package mongod

import (
	"context"
	"faynoSync/server/utils"
	"fmt"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// backfillPrivateDownloads is idempotent: file migrations cannot URL-decode links or read ENABLE_PRIVATE_APP_DOWNLOADING.
func backfillPrivateDownloads(ctx context.Context, database *mongo.Database, defaultDownloadMode string) error {
	if err := backfillArtifactS3Keys(ctx, database); err != nil {
		return fmt.Errorf("backfill artifact s3 keys: %w", err)
	}

	result, err := database.Collection("apps_meta").UpdateMany(ctx,
		bson.M{
			"app_name":      bson.M{"$exists": true},
			"private":       true,
			"download_mode": bson.M{"$exists": false},
		},
		bson.M{"$set": bson.M{"download_mode": defaultDownloadMode}},
	)
	if err != nil {
		return fmt.Errorf("backfill download modes: %w", err)
	}
	logrus.Debugf("Set download_mode=%s on %d private apps", defaultDownloadMode, result.ModifiedCount)
	return nil
}

func backfillArtifactS3Keys(ctx context.Context, database *mongo.Database) error {
	collection := database.Collection("apps")
	filter := bson.M{"artifacts": bson.M{"$elemMatch": bson.M{
		"link":   bson.M{"$regex": `/download\?key=`},
		"s3_key": bson.M{"$exists": false},
	}}}
	cursor, err := collection.Find(ctx, filter, options.Find().SetProjection(bson.M{"artifacts.link": 1, "artifacts.s3_key": 1}))
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	updated := 0
	for cursor.Next(ctx) {
		var doc struct {
			ID        primitive.ObjectID `bson:"_id"`
			Artifacts []struct {
				Link  string `bson:"link"`
				S3Key string `bson:"s3_key"`
			} `bson:"artifacts"`
		}
		if err := cursor.Decode(&doc); err != nil {
			return err
		}
		for i, artifact := range doc.Artifacts {
			key := utils.PrivateObjectKey(artifact.Link)
			if key == "" || artifact.S3Key != "" {
				continue
			}
			// Matching on the link guards against the array having changed since it was read.
			_, err := collection.UpdateOne(ctx,
				bson.M{"_id": doc.ID, fmt.Sprintf("artifacts.%d.link", i): artifact.Link},
				bson.M{"$set": bson.M{fmt.Sprintf("artifacts.%d.s3_key", i): key}},
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
	logrus.Debugf("Backfilled s3_key on %d private artifacts", updated)
	return nil
}
