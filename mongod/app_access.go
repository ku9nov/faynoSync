package mongod

import (
	"context"
	"errors"
	"faynoSync/server/model"
	"faynoSync/server/utils"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ResolveAppAccess reads the access policy of an app before any version data is built, so read paths can gate a private app.
func (c *appRepository) ResolveAppAccess(ctx context.Context, owner, appName, channelName string) (*model.AppAccess, error) {
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")

	var access model.AppAccess
	err := metaCollection.FindOne(ctx,
		bson.M{"app_name": appName, "owner": owner},
		options.FindOne().SetProjection(bson.M{"private": 1, "download_mode": 1, "cdn_edge": 1}),
	).Decode(&access)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, utils.ErrAppNotFound
		}
		return nil, err
	}
	access.Owner = owner

	// The channel only matters for the scope of a download token, and an unknown channel leaves the zero id no token can match.
	if !access.Private || channelName == "" {
		return &access, nil
	}

	var channel struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	err = metaCollection.FindOne(ctx, bson.M{"channel_name": channelName, "owner": owner}).Decode(&channel)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return &access, nil
		}
		return nil, err
	}
	access.ChannelID = channel.ID

	return &access, nil
}
