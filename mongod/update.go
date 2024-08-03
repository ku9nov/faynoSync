package mongod

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (c *appRepository) UpdateDocument(collectionName string, filter bson.D, update bson.D, uniqueKey, keyType string, ctx context.Context) (bool, error) {
	collection := c.client.Database(c.config.Database).Collection(collectionName)

	// Set the updated_at field to the current time
	update = append(update, bson.E{Key: "$set", Value: bson.D{{Key: "updated_at", Value: time.Now()}}})
	logrus.Debugln("Update document: ", update)
	updateResult, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		logrus.Errorf("Error updating document: %v", err)
		return false, err
	}

	if updateResult.MatchedCount == 0 {
		return false, fmt.Errorf("%s not found", keyType)
	}

	return true, nil
}

// UpdateChannel updates an existing channel document
func (c *appRepository) UpdateChannel(id primitive.ObjectID, channelName string, ctx context.Context) (interface{}, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "channel_name", Value: channelName}}}}
	return c.UpdateDocument("apps_meta", filter, update, "channel_name_sort_by_asc_updated", "channel", ctx)
}

// UpdatePlatform updates an existing platform document
func (c *appRepository) UpdatePlatform(id primitive.ObjectID, platformName string, ctx context.Context) (interface{}, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "platform_name", Value: platformName}}}}
	return c.UpdateDocument("apps_meta", filter, update, "platform_name_sort_by_asc_updated", "platform", ctx)
}

// UpdateArch updates an existing arch document
func (c *appRepository) UpdateArch(id primitive.ObjectID, archID string, ctx context.Context) (interface{}, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "arch_id", Value: archID}}}}
	return c.UpdateDocument("apps_meta", filter, update, "arch_id_sort_by_asc_updated", "arch", ctx)
}

// UpdateApp updates an existing app_name document
func (c *appRepository) UpdateApp(id primitive.ObjectID, appName string, ctx context.Context) (interface{}, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "app_name", Value: appName}}}}
	return c.UpdateDocument("apps_meta", filter, update, "app_name_sort_by_asc_updated", "app", ctx)
}
