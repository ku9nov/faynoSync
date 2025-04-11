package mongod

import (
	"context"
	"faynoSync/server/model"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (c *appRepository) listItems(ctx context.Context, collectionName string, filter bson.M, owner string, resultSlice interface{}) error {
	findOptions := options.Find()
	findOptions.SetLimit(100)

	logrus.Debugf("listItems called for owner: %s, collection: %s", owner, collectionName)
	logrus.Debugf("Initial filter: %v", filter)

	// Check if the user is a team user
	teamUsersCollection := c.client.Database(c.config.Database).Collection("team_users")
	var teamUser model.TeamUser
	err := teamUsersCollection.FindOne(ctx, bson.M{"username": owner}).Decode(&teamUser)

	// If user is a team user, we need to consider their permissions
	if err == nil {
		logrus.Debugf("User %s is a team user owned by %s", owner, teamUser.Owner)
		// User is a team user, check their permissions
		var allowedIDs []string

		// Determine which resource type we're dealing with based on the filter
		if _, exists := filter["channel_name"]; exists {
			// This is a channel list operation
			allowedIDs = teamUser.Permissions.Channels.Allowed
			logrus.Debugf("Channel list operation, allowed IDs: %v", allowedIDs)
		} else if _, exists := filter["platform_name"]; exists {
			// This is a platform list operation
			allowedIDs = teamUser.Permissions.Platforms.Allowed
			logrus.Debugf("Platform list operation, allowed IDs: %v", allowedIDs)
		} else if _, exists := filter["arch_id"]; exists {
			// This is an arch list operation
			allowedIDs = teamUser.Permissions.Archs.Allowed
			logrus.Debugf("Arch list operation, allowed IDs: %v", allowedIDs)
		} else if _, exists := filter["app_name"]; exists {
			// This is an app list operation
			allowedIDs = teamUser.Permissions.Apps.Allowed
			logrus.Debugf("App list operation, allowed IDs: %v", allowedIDs)
		}

		// If the user has specific allowed resources, include those
		if len(allowedIDs) > 0 {
			// Convert string IDs to ObjectIDs for all resource types
			var objectIDs []primitive.ObjectID
			for _, idStr := range allowedIDs {
				if id, err := primitive.ObjectIDFromHex(idStr); err == nil {
					objectIDs = append(objectIDs, id)
				} else {
					logrus.Warnf("Invalid ObjectID format: %s", idStr)
				}
			}

			// Only add the _id filter if we have valid ObjectIDs
			if len(objectIDs) > 0 {
				filter["_id"] = bson.M{"$in": objectIDs}
				// Also ensure we only show resources owned by the team user's admin
				filter["owner"] = teamUser.Owner
				logrus.Debugf("Filtering by specific allowed IDs: %v and owner: %s", objectIDs, teamUser.Owner)
			} else {
				// If no valid ObjectIDs, return empty result
				logrus.Debugf("No valid ObjectIDs found in allowed resources, returning empty result")
				return nil
			}
		} else {
			// If no specific allowed resources, return empty result
			logrus.Debugf("No specific allowed resources defined, returning empty result")
			return nil
		}
	} else {
		// User is not a team user, filter by owner as before
		if owner != "" {
			filter["owner"] = owner
			logrus.Debugf("User is not a team user, filtering by owner: %s", owner)
		}
	}

	logrus.Debugf("Final filter: %v", filter)
	collection := c.client.Database(c.config.Database).Collection(collectionName)

	cur, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		logrus.Errorf("Error executing find query: %v", err)
		return err
	}
	defer cur.Close(ctx)

	// Decode all items into the result slice
	if err := cur.All(ctx, resultSlice); err != nil {
		logrus.Errorf("Error decoding items: %v", err)
		return err
	}

	return nil
}

func (c *appRepository) ListChannels(ctx context.Context, owner string) ([]*model.Channel, error) {
	var channels []*model.Channel
	filter := bson.M{"channel_name": bson.M{"$exists": true}}
	if err := c.listItems(ctx, "apps_meta", filter, owner, &channels); err != nil {
		return nil, err
	}
	return channels, nil
}

func (c *appRepository) ListPlatforms(ctx context.Context, owner string) ([]*model.Platform, error) {
	var platforms []*model.Platform
	filter := bson.M{"platform_name": bson.M{"$exists": true}}
	if err := c.listItems(ctx, "apps_meta", filter, owner, &platforms); err != nil {
		return nil, err
	}
	return platforms, nil
}

func (c *appRepository) ListArchs(ctx context.Context, owner string) ([]*model.Arch, error) {
	var archs []*model.Arch
	filter := bson.M{"arch_id": bson.M{"$exists": true}}
	if err := c.listItems(ctx, "apps_meta", filter, owner, &archs); err != nil {
		return nil, err
	}
	return archs, nil
}

func (c *appRepository) ListApps(ctx context.Context, owner string) ([]*model.App, error) {
	var apps []*model.App
	filter := bson.M{"app_name": bson.M{"$exists": true}}
	if err := c.listItems(ctx, "apps_meta", filter, owner, &apps); err != nil {
		return nil, err
	}
	return apps, nil
}
