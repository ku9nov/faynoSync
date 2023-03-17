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
	Upload(ctxQuery map[string]interface{}, appLink string, ctx context.Context) (interface{}, error)
	CheckLatestVersion(appName, version string, ctx context.Context) (bool, string, error)
	CreateChannel(channelName string, ctx context.Context) (interface{}, error)
	ListChannels(ctx context.Context) ([]*model.Channel, error)
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

func (c *appRepository) ListChannels(ctx context.Context) ([]*model.Channel, error) {

	findOptions := options.Find()
	findOptions.SetLimit(100)

	var channels []*model.Channel

	collection := c.client.Database(c.config.Database).Collection("channels")

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
		var elem model.Channel
		if err := cur.Decode(&elem); err != nil {
			log.Fatal(err)
			return nil, err
		}

		channels = append(channels, &elem)
	}

	cur.Close(ctx)

	return channels, nil
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

func (c *appRepository) Upload(ctxQuery map[string]interface{}, appLink string, ctx context.Context) (interface{}, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{
		{Key: "app_name", Value: ctxQuery["app_name"].(string)},
		{Key: "version", Value: ctxQuery["version"].(string)},
		{Key: "link", Value: appLink},
		{Key: "channel", Value: ctxQuery["channel_name"].(string)},
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

func (c *appRepository) CreateChannel(channelName string, ctx context.Context) (interface{}, error) {

	collection := c.client.Database(c.config.Database).Collection("channels")

	filter := bson.D{
		{Key: "channel_name", Value: channelName},
		{Key: "updated_at", Value: time.Now()}, // add updated_at with the current time
	}

	uploadResult, err := collection.InsertOne(ctx, filter)
	mongoErr, ok := err.(mongo.WriteException)
	if ok {
		for _, writeErr := range mongoErr.WriteErrors {
			if writeErr.Code == 11000 && strings.Contains(writeErr.Message, "channel_name_sort_by_asc_created") {
				return "channel with this name already exists", errors.New("channel with this name already exists")
			}
		}
	}

	return uploadResult.InsertedID, nil
}

func (c *appRepository) CheckLatestVersion(appName, version string, ctx context.Context) (bool, string, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")

	// Find the latest version of the given app_name
	filter := bson.M{"app_name": appName}
	cursor, err := collection.Find(ctx, filter, options.Find().SetSort(bson.M{"version": -1}))
	if err != nil {
		panic(err)
	}
	defer cursor.Close(ctx)

	var latestVersion string
	for cursor.Next(ctx) {
		var app *model.App
		err := cursor.Decode(&app)
		if err != nil {
			panic(err)
		}
		if latestVersion == "" {
			// First version found, so set it as the latest version
			latestVersion = app.Version
		}
	}

	// No exact match found, so return the latest version of the app
	if latestVersion != "" {
		// Retrieve the latest document for the given app_name and latest version
		filter = bson.M{"app_name": appName, "version": latestVersion}
		options := options.FindOne().SetSort(bson.M{"updated_at": -1})
		var latestApp *model.App
		err := collection.FindOne(ctx, filter, options).Decode(&latestApp)
		if err != nil {
			panic(err)
		}
		if latestVersion == version {
			return false, latestApp.Link, nil
		} else {
			return true, latestApp.Link, nil
		}
	} else {
		return false, "Not found", fmt.Errorf("no matching documents found for app_name: %s", appName)
	}
}
