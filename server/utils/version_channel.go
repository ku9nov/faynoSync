package utils

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// VersionChannelName returns the channel name of a version, "" when it has none or
// does not exist (the update itself then reports the missing version).
func VersionChannelName(ctx context.Context, database *mongo.Database, versionID primitive.ObjectID, owner string) (string, error) {
	var version struct {
		ChannelID primitive.ObjectID `bson:"channel_id"`
	}
	err := database.Collection("apps").FindOne(ctx, bson.M{"_id": versionID, "owner": owner}).Decode(&version)
	if errors.Is(err, mongo.ErrNoDocuments) || err == nil && version.ChannelID.IsZero() {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var channel struct {
		Name string `bson:"channel_name"`
	}
	err = database.Collection("apps_meta").FindOne(ctx, bson.M{"_id": version.ChannelID}).Decode(&channel)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", nil
	}
	return channel.Name, err
}
