package mongod

import (
	"context"
	"faynoSync/server/model"
	"fmt"
	"log"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func (c *appRepository) DeleteApp(id primitive.ObjectID, ctx context.Context) ([]string, int64, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Retrieve the document before deletion
	var app *model.App
	err := collection.FindOne(ctx, filter).Decode(&app)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, 0, fmt.Errorf("no app found with ID %s", id)
		}
		return nil, 0, fmt.Errorf("error retrieving app with ID %s: %s", id, err.Error())
	}

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		logrus.Fatal(err)

		return nil, 0, err
	}

	var links []string
	for _, artifact := range app.Artifacts {
		link := string(artifact.Link)
		links = append(links, link)
	}

	return links, deleteResult.DeletedCount, nil
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
