package mongod

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"SAU/server/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

type AppRepository interface {
	Get(ctx context.Context) ([]*model.App, error)
	GetAppByName(email string, ctx context.Context) ([]*model.App, error)
	Delete(id primitive.ObjectID, ctx context.Context) (string, int64, error)
	Upload(appName, version, appLink string, ctx context.Context) (interface{}, error)
	DownloadLatestVersion(id primitive.ObjectID, ctx context.Context) (string, error)
}

type appRepository struct {
	client *mongo.Client
	config *connstring.ConnString
}

func NewAppRepository(config *connstring.ConnString, client *mongo.Client) AppRepository {
	return &appRepository{config: config, client: client}
}

func (c *appRepository) Get(ctx context.Context) ([]*model.App, error) {

	findOptions := options.Find()
	findOptions.SetLimit(100)

	var apps []*model.App

	collection := c.client.Database(c.config.Database).Collection("apps")

	// Passing bson.D{{}} as the filter matches all documents in the collection
	cur, err := collection.Find(ctx, bson.D{{}}, findOptions)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	// Finding multiple documents returns a cursor
	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		var elem model.App
		if err := cur.Decode(&elem); err != nil {
			log.Fatal(err)
			return nil, err
		}

		apps = append(apps, &elem)
	}

	cur.Close(ctx)

	return apps, nil
}

func (c *appRepository) GetAppByName(appName string, ctx context.Context) ([]*model.App, error) {

	findOptions := options.Find()
	findOptions.SetLimit(100)

	var apps []*model.App

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{primitive.E{Key: "app_name", Value: appName}}

	// Passing the filter matches all documents by app_name in the collection
	cur, err := collection.Find(ctx, filter)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	// Finding multiple documents returns a cursor
	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		var elem model.App
		if err := cur.Decode(&elem); err != nil {
			log.Fatal(err)
			return nil, err
		}

		apps = append(apps, &elem)
	}

	cur.Close(ctx)

	return apps, nil
}

func (c *appRepository) DownloadLatestVersion(id primitive.ObjectID, ctx context.Context) (string, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Retrieve the document before deletion
	var app *model.App
	err := collection.FindOne(ctx, filter).Decode(&app)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", fmt.Errorf("no app found with ID %s", id)
		}
		return "", fmt.Errorf("error retrieving app with ID %s: %s", id, err.Error())
	}

	return app.Link, nil
}

func (c *appRepository) Delete(id primitive.ObjectID, ctx context.Context) (string, int64, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Retrieve the document before deletion
	var app *model.App
	err := collection.FindOne(ctx, filter).Decode(&app)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", 0, fmt.Errorf("no app found with ID %s", id)
		}
		return "", 0, fmt.Errorf("error retrieving app with ID %s: %s", id, err.Error())
	}

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		log.Fatal(err)

		return "", 0, err
	}

	return app.Link, deleteResult.DeletedCount, nil
}

func (c *appRepository) Upload(appName, version, appLink string, ctx context.Context) (interface{}, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{
		{Key: "app_name", Value: appName},
		{Key: "version", Value: version},
		{Key: "link", Value: appLink},
		{Key: "updated_at", Value: time.Now()}, // add updated_at with the current time
	}

	uploadResult, err := collection.InsertOne(ctx, filter)
	mongoErr, ok := err.(mongo.WriteException)
	if ok {
		for _, writeErr := range mongoErr.WriteErrors {
			if writeErr.Code == 11000 && strings.Contains(writeErr.Message, "unique_link_to_app_with_specific_version") {
				return "app with this link already exists", errors.New("app with this link already exists")
			}
		}
	}

	return uploadResult.InsertedID, nil
}
