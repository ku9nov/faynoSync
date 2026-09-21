package mongod

import (
	"context"
	"errors"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"time"

	"github.com/sirupsen/logrus"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	ErrPrivateArtifactNotFound      = errors.New("artifact not found")
	ErrDownloadTokenPublicApp       = errors.New("download tokens are only available for private apps")
	ErrChannelNotFound              = errors.New("channel not found")
	ErrDownloadTokenChannelRequired = errors.New("channel_id is required while channels exist")
)

func (c *appRepository) FindPrivateArtifact(ctx context.Context, key string) (*model.PrivateArtifact, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"artifacts.s3_key": key}}},
		{{Key: "$limit", Value: 1}},
		{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "app_id",
			"foreignField": "_id",
			"as":           "app_meta",
		}}},
		{{Key: "$unwind", Value: "$app_meta"}},
		{{Key: "$match", Value: bson.M{"app_meta.private": true}}},
		{{Key: "$project", Value: bson.M{
			"app_id":        1,
			"channel_id":    1,
			"owner":         1,
			"download_mode": "$app_meta.download_mode",
		}}},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if !cursor.Next(ctx) {
		if err := cursor.Err(); err != nil {
			return nil, err
		}
		return nil, ErrPrivateArtifactNotFound
	}

	var artifact model.PrivateArtifact
	if err := cursor.Decode(&artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func (c *appRepository) CanDownloadPrivateArtifact(ctx context.Context, username string, artifact *model.PrivateArtifact) (bool, error) {
	owner, teamUser, err := c.resolveOwnerAndTeamUser(ctx, username)
	if err != nil {
		return false, err
	}
	if owner != artifact.Owner {
		return false, nil
	}
	if teamUser == nil {
		return true, nil
	}
	if !teamUser.Permissions.Apps.Download {
		return false, nil
	}
	if checkEntityAccess(*teamUser, artifact.AppID.Hex(), teamUser.Permissions.Apps.Allowed, "app") != nil {
		return false, nil
	}
	if !artifact.ChannelID.IsZero() && checkEntityAccess(*teamUser, artifact.ChannelID.Hex(), teamUser.Permissions.Channels.Allowed, "channel") != nil {
		return false, nil
	}
	return true, nil
}

func (c *appRepository) HasDownloadToken(ctx context.Context, token string, artifact *model.PrivateArtifact) (bool, error) {
	collection := c.client.Database(c.config.Database).Collection("download_tokens")
	count, err := collection.CountDocuments(ctx, bson.M{
		"token_hash": utils.HashAPIToken(token),
		"app_id":     artifact.AppID,
		"channel_id": artifact.ChannelID,
		"owner":      artifact.Owner,
	}, options.Count().SetLimit(1))
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (c *appRepository) channelsExist(ctx context.Context) (bool, error) {
	count, err := c.client.Database(c.config.Database).Collection("apps_meta").
		CountDocuments(ctx, bson.M{"channel_name": bson.M{"$exists": true}}, options.Count().SetLimit(1))
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// RegenerateDownloadToken creates the token for (app, channel) on first call and rotates it afterwards.
func (c *appRepository) RegenerateDownloadToken(appID, channelID primitive.ObjectID, requester string, ctx context.Context) (string, error) {
	app, err := c.GetAppByID(appID, requester, ctx)
	if err != nil {
		return "", err
	}
	if !app.Private {
		return "", ErrDownloadTokenPublicApp
	}

	if channelID.IsZero() {
		channelsExist, err := c.channelsExist(ctx)
		if err != nil {
			return "", err
		}
		if channelsExist {
			return "", ErrDownloadTokenChannelRequired
		}
	}

	if !channelID.IsZero() {
		metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
		err := metaCollection.FindOne(ctx, bson.M{
			"_id":          channelID,
			"owner":        app.Owner,
			"channel_name": bson.M{"$exists": true},
		}).Err()
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", ErrChannelNotFound
		}
		if err != nil {
			return "", err
		}

		_, teamUser, err := c.resolveOwnerAndTeamUser(ctx, requester)
		if err != nil {
			return "", err
		}
		if teamUser != nil {
			if err := checkEntityAccess(*teamUser, channelID.Hex(), teamUser.Permissions.Channels.Allowed, "channel"); err != nil {
				return "", err
			}
		}
	}

	rawToken, tokenPrefix, tokenHash, err := utils.GenerateDownloadToken()
	if err != nil {
		return "", err
	}

	now := primitive.NewDateTimeFromTime(time.Now())
	collection := c.client.Database(c.config.Database).Collection("download_tokens")
	_, err = collection.UpdateOne(ctx,
		bson.M{"app_id": appID, "channel_id": channelID},
		bson.M{
			"$set": bson.M{
				"owner":        app.Owner,
				"token_hash":   tokenHash,
				"token_prefix": tokenPrefix,
				"updated_at":   now,
			},
			"$setOnInsert": bson.M{"created_at": now},
		},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		return "", err
	}

	return rawToken, nil
}

func (c *appRepository) ListDownloadTokens(requester string, ctx context.Context) ([]*model.DownloadTokenListItem, error) {
	filter, ok, err := c.editableAppsFilter(ctx, requester)
	if err != nil {
		return nil, err
	}
	if !ok {
		return []*model.DownloadTokenListItem{}, nil
	}

	collection := c.client.Database(c.config.Database).Collection("download_tokens")
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: filter}},
		{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "app_id",
			"foreignField": "_id",
			"as":           "app_meta",
		}}},
		{{Key: "$unwind", Value: "$app_meta"}},
		{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "channel_id",
			"foreignField": "_id",
			"as":           "channel_meta",
		}}},
		{{Key: "$unwind", Value: bson.M{"path": "$channel_meta", "preserveNullAndEmptyArrays": true}}},
		{{Key: "$project", Value: bson.M{
			"_id":          1,
			"app_id":       1,
			"app_name":     "$app_meta.app_name",
			"channel_id":   1,
			"channel_name": "$channel_meta.channel_name",
			"token_prefix": 1,
			"updated_at":   1,
		}}},
		{{Key: "$sort", Value: bson.D{{Key: "updated_at", Value: -1}}}},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	downloadTokens := []*model.DownloadTokenListItem{}
	if err := cursor.All(ctx, &downloadTokens); err != nil {
		return nil, err
	}

	return downloadTokens, nil
}

// deleteDownloadTokens drops the tokens of a deleted app or channel: their scope can never be resolved again.
func (c *appRepository) deleteDownloadTokens(ctx context.Context, keyType string, id primitive.ObjectID) error {
	var filter bson.M
	switch keyType {
	case "app":
		filter = bson.M{"app_id": id}
	case "channel":
		filter = bson.M{"channel_id": id}
	default:
		return nil
	}

	result, err := c.client.Database(c.config.Database).Collection("download_tokens").DeleteMany(ctx, filter)
	if err != nil {
		return err
	}
	logrus.Debugf("Deleted %d download tokens of %s %s", result.DeletedCount, keyType, id.Hex())
	return nil
}
