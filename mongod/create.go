package mongod

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func (c *appRepository) CreateDocument(collectionName string, document bson.D, uniqueKey, keyType string, ctx context.Context) (interface{}, error) {
	collection := c.client.Database(c.config.Database).Collection(collectionName)

	// Set the updated_at field to the current time
	document = append(document, bson.E{Key: "updated_at", Value: time.Now()})
	fmt.Println("DOCUMENT: ", document[1])
	uploadResult, err := collection.InsertOne(ctx, document)
	if err != nil {
		if mongoErr, ok := err.(mongo.WriteException); ok {
			for _, writeErr := range mongoErr.WriteErrors {
				if writeErr.Code == 11000 && strings.Contains(writeErr.Message, uniqueKey) {
					return nil, fmt.Errorf("%s with this name already exists", keyType)
				}
			}
		}
		logrus.Errorf("Error inserting document: %v", err)
		return nil, err
	}

	return uploadResult.InsertedID, nil
}

// CreateChannel creates a new channel document
func (c *appRepository) CreateChannel(channelName string, ctx context.Context) (interface{}, error) {
	document := bson.D{{Key: "channel_name", Value: channelName}}
	return c.CreateDocument("apps", document, "channel_name_sort_by_asc_created", "channel", ctx)
}

// CreatePlatform creates a new platform document
func (c *appRepository) CreatePlatform(platformName string, ctx context.Context) (interface{}, error) {
	document := bson.D{{Key: "platform_name", Value: platformName}}
	return c.CreateDocument("apps", document, "platform_name_sort_by_asc_created", "platform", ctx)
}

// CreateArch creates a new arch document
func (c *appRepository) CreateArch(archID string, ctx context.Context) (interface{}, error) {
	document := bson.D{{Key: "arch_id", Value: archID}}
	return c.CreateDocument("apps", document, "arch_id_sort_by_asc_created", "arch", ctx)
}
