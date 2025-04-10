package mongod

import (
	"context"
	"faynoSync/server/model"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func (c *appRepository) DeleteSpecificVersionOfApp(id primitive.ObjectID, ctx context.Context) ([]string, int64, string, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Retrieve the document before deletion
	var app *model.SpecificApp
	err := collection.FindOne(ctx, filter).Decode(&app)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, 0, "", fmt.Errorf("no app found with ID %s", id)
		}
		return nil, 0, "", fmt.Errorf("error retrieving app with ID %s: %s", id, err.Error())
	}
	appName, err := c.FetchAppByID(app.ID, ctx)

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		logrus.Fatal(err)

		return nil, 0, "", err
	}

	var links []string
	for _, artifact := range app.Artifacts {
		link := string(artifact.Link)
		links = append(links, link)
	}

	return links, deleteResult.DeletedCount, appName[0].AppName, nil
}

func (c *appRepository) DeleteSpecificArtifactOfApp(id primitive.ObjectID, ctxQuery map[string]interface{}, ctx context.Context) ([]string, bool, error) {
	var err error
	var links []string
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")

	err = c.getMeta(ctx, metaCollection, "app_name", ctxQuery["app_name"].(string), &appMeta)
	if err != nil {
		logrus.Errorln("Error getting app_id in DeleteSpecificArtifactOfApp:", err)
	}
	existingDoc := collection.FindOne(ctx, bson.D{
		{Key: "_id", Value: id},
		{Key: "app_id", Value: appMeta.ID},
		{Key: "version", Value: ctxQuery["version"].(string)},
	})

	if existingDoc.Err() == nil {

		var appData model.SpecificApp
		if err := existingDoc.Decode(&appData); err != nil {
			logrus.Errorln("Error decoding appData in DeleteSpecificArtifactOfApp:", err)
		}

		updateFields := bson.D{{Key: "updated_at", Value: time.Now()}}
		var deletedLinks []string

		if artifactsToDelete, ok := ctxQuery["artifacts_to_delete"].([]string); ok {
			for _, index := range artifactsToDelete {
				if idx, err := strconv.Atoi(index); err == nil && idx < len(appData.Artifacts) {
					deletedLinks = append(deletedLinks, string(appData.Artifacts[idx].Link))
					appData.Artifacts = append(appData.Artifacts[:idx], appData.Artifacts[idx+1:]...)
				} else {
					logrus.Errorf("Invalid index in DeleteSpecificArtifactOfApp: %s\n", index)
					return nil, false, err
				}
			}
			updateFields = append(updateFields, bson.E{Key: "artifacts", Value: appData.Artifacts})
		}

		links = append(links, deletedLinks...)

		_, err = collection.UpdateOne(
			ctx,
			bson.D{{Key: "_id", Value: id}},
			bson.D{{Key: "$set", Value: updateFields}},
		)
		if err != nil {
			logrus.Fatal(err)

			return nil, false, err
		}

	}
	return links, true, nil
}

type Document interface{}

func (c *appRepository) DeleteDocument(collectionName string, id primitive.ObjectID, docType Document, ctx context.Context) (int64, error) {
	collection := c.client.Database(c.config.Database).Collection(collectionName)

	filter := bson.D{primitive.E{Key: "_id", Value: id}}
	// Retrieve the document before deletion
	err := collection.FindOne(ctx, filter).Decode(docType)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, fmt.Errorf("no document found with ID %s", id)
		}
		return 0, fmt.Errorf("error retrieving document with ID %s: %s", id, err.Error())
	}

	var relatedFilter bson.D

	switch docType.(type) {
	case *model.App:
		relatedFilter = bson.D{primitive.E{Key: "app_id", Value: id}}
	case *model.Channel:
		relatedFilter = bson.D{primitive.E{Key: "channel_id", Value: id}}
	case *model.Platform:
		relatedFilter = bson.D{
			primitive.E{Key: "artifacts", Value: bson.D{
				primitive.E{Key: "$elemMatch", Value: bson.D{primitive.E{Key: "platform", Value: id}}},
			}},
		}
	case *model.Arch:
		relatedFilter = bson.D{
			primitive.E{Key: "artifacts", Value: bson.D{
				primitive.E{Key: "$elemMatch", Value: bson.D{primitive.E{Key: "arch", Value: id}}},
			}},
		}
	default:
		return 0, fmt.Errorf("unsupported document type")
	}

	checkRelatedApps := c.client.Database(c.config.Database).Collection("apps")

	var foundDoc bson.M

	err = checkRelatedApps.FindOne(ctx, relatedFilter).Decode(&foundDoc)
	if err == nil {
		return 0, fmt.Errorf("you can't delete this item because it is related to other items")
	}

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		log.Fatalf("error deleting document with ID %s: %s", id, err.Error())
		return 0, err
	}

	return deleteResult.DeletedCount, nil
}

func (c *appRepository) DeleteChannel(id primitive.ObjectID, ctx context.Context) (int64, error) {
	var channel model.Channel
	return c.DeleteDocument("apps_meta", id, &channel, ctx)
}

func (c *appRepository) DeletePlatform(id primitive.ObjectID, ctx context.Context) (int64, error) {
	var platform model.Platform
	return c.DeleteDocument("apps_meta", id, &platform, ctx)
}

func (c *appRepository) DeleteArch(id primitive.ObjectID, ctx context.Context) (int64, error) {
	var arch model.Arch
	return c.DeleteDocument("apps_meta", id, &arch, ctx)
}

func (c *appRepository) DeleteApp(id primitive.ObjectID, ctx context.Context) (int64, error) {
	var app model.App
	return c.DeleteDocument("apps_meta", id, &app, ctx)
}
