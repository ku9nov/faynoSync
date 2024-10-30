package mongod

import (
	"context"
	"errors"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func (c *appRepository) CreateDocument(collectionName string, document bson.D, uniqueKey, keyType string, ctx context.Context) (interface{}, error) {
	collection := c.client.Database(c.config.Database).Collection(collectionName)

	// Set the updated_at field to the current time
	document = append(document, bson.E{Key: "updated_at", Value: time.Now()})
	logrus.Debugln("Document: ", document)
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
	return c.CreateDocument("apps_meta", document, "channel_name_sort_by_asc_created", "channel", ctx)
}

// CreatePlatform creates a new platform document
func (c *appRepository) CreatePlatform(platformName string, ctx context.Context) (interface{}, error) {
	document := bson.D{{Key: "platform_name", Value: platformName}}
	return c.CreateDocument("apps_meta", document, "platform_name_sort_by_asc_created", "platform", ctx)
}

// CreateArch creates a new arch document
func (c *appRepository) CreateArch(archID string, ctx context.Context) (interface{}, error) {
	document := bson.D{{Key: "arch_id", Value: archID}}
	return c.CreateDocument("apps_meta", document, "arch_id_sort_by_asc_created", "arch", ctx)
}

// CreateApp creates a new app_name document
func (c *appRepository) CreateApp(appName string, ctx context.Context) (interface{}, error) {
	document := bson.D{{Key: "app_name", Value: appName}}
	return c.CreateDocument("apps_meta", document, "app_name_sort_by_asc_created", "app", ctx)
}

func (c *appRepository) Upload(ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (interface{}, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	var uploadResult interface{}
	var err error

	// Find app_id from apps_meta by app_name
	err = c.getMeta(ctx, metaCollection, "app_name", ctxQuery["app_name"].(string), &appMeta)
	if err != nil {
		return nil, err
	}

	// Fetch channel_id
	if channelName, ok := ctxQuery["channel"].(string); ok && channelName != "" {
		err = c.getMeta(ctx, metaCollection, "channel_name", channelName, &channelMeta)
		if err != nil {
			return nil, err
		}
		logrus.Debugf("Found channelMeta: %v", channelMeta)
	}

	// Fetch platform_id
	if platformName, ok := ctxQuery["platform"].(string); ok && platformName != "" {
		err = c.getMeta(ctx, metaCollection, "platform_name", platformName, &platformMeta)
		if err != nil {
			return nil, err
		}
		logrus.Debugf("Found platformMeta: %v", platformMeta)
	}

	// Fetch arch_id
	if archName, ok := ctxQuery["arch"].(string); ok && archName != "" {
		err = c.getMeta(ctx, metaCollection, "arch_id", archName, &archMeta)
		if err != nil {
			return nil, err
		}
		logrus.Debugf("Found archMeta: %v", archMeta)
	}

	// Check if a document with the same "app_id" and "version" already exists
	existingDoc := collection.FindOne(ctx, bson.D{
		{Key: "app_id", Value: appMeta.ID},
		{Key: "version", Value: ctxQuery["version"].(string)},
	})

	if existingDoc.Err() == nil {
		var appData model.SpecificApp
		if err := existingDoc.Decode(&appData); err != nil {
			return nil, err
		}

		for _, artifact := range appData.Artifacts {
			if artifact.Package == extension && artifact.Arch == archMeta.ID && artifact.Platform == platformMeta.ID {
				msg := "app with this name, version, platform, architecture and extension already exists"
				return msg, errors.New(msg)
			}
		}

		appData.Artifacts = append(appData.Artifacts, model.Artifact{
			Link:     appLink,
			Platform: platformMeta.ID,
			Arch:     archMeta.ID,
			Package:  extension,
		})
		_, err = collection.UpdateOne(
			ctx,
			bson.D{{Key: "app_id", Value: appMeta.ID}, {Key: "version", Value: ctxQuery["version"].(string)}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "artifacts", Value: appData.Artifacts}, {Key: "updated_at", Value: time.Now()}}}},
		)
		if err != nil {
			return nil, err
		}

		uploadResult = appData.ID
	} else {
		// Handle the case when no document exists
		publishParam, publishExists := ctxQuery["publish"]
		criticalParam, criticalExists := ctxQuery["critical"]

		publish := false
		if publishExists {
			publish = utils.GetBoolParam(publishParam)
		}

		critical := false
		if criticalExists {
			critical = utils.GetBoolParam(criticalParam)
		}

		artifact := model.Artifact{
			Link:     appLink,
			Platform: platformMeta.ID,
			Arch:     archMeta.ID,
			Package:  extension,
		}
		changelog := model.Changelog{
			Version: ctxQuery["version"].(string),
			Changes: ctxQuery["changelog"].(string),
			Date:    time.Now().Format("2006-01-02"),
		}
		filter := bson.D{
			{Key: "app_id", Value: appMeta.ID},
			{Key: "version", Value: ctxQuery["version"].(string)},
			{Key: "channel_id", Value: channelMeta.ID},
			{Key: "published", Value: publish},
			{Key: "critical", Value: critical},
			{Key: "artifacts", Value: []model.Artifact{artifact}},
			{Key: "changelog", Value: []model.Changelog{changelog}},
			{Key: "updated_at", Value: time.Now()},
		}
		logrus.Debugf("Channel Meta: %v", channelMeta)
		logrus.Debugf("Platform Meta: %v", platformMeta)
		logrus.Debugf("Arch Meta: %v", archMeta)
		uploadResult, err = collection.InsertOne(ctx, filter)
		if err != nil {
			logrus.Errorf("Error inserting document: %v", err)
			return nil, err
		}

		mongoErr, ok := err.(mongo.WriteException)
		if ok {
			for _, writeErr := range mongoErr.WriteErrors {
				if writeErr.Code == 11000 && strings.Contains(writeErr.Message, "unique_link_to_app_with_specific_version") {
					return "app with this link already exists", errors.New("app with this link already exists")
				}
			}
		}
	}

	// if insertResult, ok := uploadResult.(*mongo.InsertOneResult); ok {
	// 	insertedID, ok := insertResult.InsertedID.(primitive.ObjectID)
	// 	if !ok {
	// 		logrus.Errorln("error extracting ID from InsertOneResult")
	// 	}
	// 	var appData model.SpecificApp
	// 	err = collection.FindOne(ctx, bson.D{{Key: "_id", Value: insertedID}}).Decode(&appData)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	logrus.Debugf("Uploaded result to mongo: %+v", appData)
	// } else if updatedID, ok := uploadResult.(primitive.ObjectID); ok {
	// 	var appData model.SpecificApp
	// 	err = collection.FindOne(ctx, bson.D{{Key: "_id", Value: updatedID}}).Decode(&appData)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	logrus.Debugf("Updated result in mongo: %+v", appData)
	// }

	switch v := uploadResult.(type) {
	case *mongo.InsertOneResult:
		insertedID, ok := v.InsertedID.(primitive.ObjectID)
		if !ok {
			return nil, errors.New("error extracting ID from InsertOneResult")
		}
		var appData model.SpecificApp
		err = collection.FindOne(ctx, bson.D{{Key: "_id", Value: insertedID}}).Decode(&appData)
		if err != nil {
			return nil, err
		}
		logrus.Debugf("Uploaded result to mongo: %+v", appData)
		return appData, nil

	case primitive.ObjectID:
		var appData model.SpecificApp
		err = collection.FindOne(ctx, bson.D{{Key: "_id", Value: v}}).Decode(&appData)
		if err != nil {
			return nil, err
		}
		logrus.Debugf("Updated result in mongo: %+v", appData)
		return appData, nil

	default:
		return nil, errors.New("unexpected return type")
	}
}
