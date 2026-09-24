package mongod

import (
	"context"
	"errors"
	"faynoSync/server/utils"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mongodb"
	"github.com/golang-migrate/migrate/v4/source/file"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func newMigration(client *mongo.Client, dbName string) (*migrate.Migrate, error) {
	sourceDriver, err := (&file.File{}).Open("mongod/migrations/")
	if err != nil {
		return nil, err
	}
	dbDriver, err := mongodb.WithInstance(client, &mongodb.Config{
		DatabaseName: dbName,
	})
	if err != nil {
		return nil, err
	}
	m, err := migrate.NewWithInstance("file", sourceDriver, dbName, dbDriver)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// REMOVE-IN v3.0.0: one-time check for the v2.4.0 unique_app_version_owner index; upgrades from < v2.4.0 must go through the last v2.x.
// checkDuplicateAppVersions runs before any migration so that duplicates blocking the
// unique_app_version_owner index abort the run cleanly instead of leaving it dirty.
func checkDuplicateAppVersions(ctx context.Context, database *mongo.Database) error {
	cursor, err := database.Collection("apps").Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"app_id": bson.M{"$type": "objectId"}}}},
		{{Key: "$group", Value: bson.M{
			"_id":   bson.M{"app_id": "$app_id", "version": "$version", "owner": "$owner"},
			"ids":   bson.M{"$push": "$_id"},
			"count": bson.M{"$sum": 1},
		}}},
		{{Key: "$match", Value: bson.M{"count": bson.M{"$gt": 1}}}},
	})
	if err != nil {
		return fmt.Errorf("check duplicate app versions: %w", err)
	}
	defer cursor.Close(ctx)

	var duplicates []string
	for cursor.Next(ctx) {
		var group struct {
			Key struct {
				AppID   primitive.ObjectID `bson:"app_id"`
				Version interface{}        `bson:"version"`
				Owner   interface{}        `bson:"owner"`
			} `bson:"_id"`
			IDs []primitive.ObjectID `bson:"ids"`
		}
		if err := cursor.Decode(&group); err != nil {
			return fmt.Errorf("check duplicate app versions: %w", err)
		}
		ids := make([]string, 0, len(group.IDs))
		for _, id := range group.IDs {
			ids = append(ids, id.Hex())
		}
		duplicates = append(duplicates, fmt.Sprintf("app_id=%s version=%v owner=%v documents=[%s]",
			group.Key.AppID.Hex(), group.Key.Version, group.Key.Owner, strings.Join(ids, ", ")))
	}
	if err := cursor.Err(); err != nil {
		return fmt.Errorf("check duplicate app versions: %w", err)
	}
	if len(duplicates) > 0 {
		return fmt.Errorf("found %d app versions stored in more than one document; merge or remove the extra documents manually, then re-run migrate up (no migration was applied):\n%s",
			len(duplicates), strings.Join(duplicates, "\n"))
	}
	return nil
}

func RunMigrationsUp(client *mongo.Client, dbName string) error {
	if err := checkDuplicateAppVersions(context.Background(), client.Database(dbName)); err != nil {
		return err
	}
	m, err := newMigration(client, dbName)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil {
		if !errors.Is(err, migrate.ErrNoChange) {
			return err
		}
		logrus.Infoln("No pending migrations to apply")
	} else {
		logrus.Infoln("Migrations completed")
	}
	database := client.Database(dbName)
	if err := backfillPrivateDownloads(context.Background(), database, utils.DefaultDownloadMode(viper.GetViper())); err != nil {
		return err
	}
	return backfillFeedArtifacts(context.Background(), database, viper.GetViper())
}

func RunMigrationsDown(client *mongo.Client, dbName string) error {
	m, err := newMigration(client, dbName)
	if err != nil {
		return err
	}
	if err := m.Down(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			logrus.Infoln("No migrations to roll back")
			return nil
		}
		return err
	}
	logrus.Infoln("Migrations rollback completed")
	return nil
}
