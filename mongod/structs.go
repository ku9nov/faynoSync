package mongod

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"SAU/server/model"

	"github.com/hashicorp/go-version"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

type AppRepository interface {
	Get(ctx context.Context) ([]*model.App, error)
	GetAppByName(email string, ctx context.Context) ([]*model.App, error)
	DeleteApp(id primitive.ObjectID, ctx context.Context) (string, int64, error)
	DeleteChannel(id primitive.ObjectID, ctx context.Context) (int64, error)
	Upload(ctxQuery map[string]interface{}, appLink string, ctx context.Context) (interface{}, error)
	CheckLatestVersion(appName, version, channel, platform, arch string, ctx context.Context) (bool, string, error)
	CreateChannel(channelName string, ctx context.Context) (interface{}, error)
	ListChannels(ctx context.Context) ([]*model.Channel, error)
	CreatePlatform(platformName string, ctx context.Context) (interface{}, error)
	ListPlatforms(ctx context.Context) ([]*model.Platform, error)
	DeletePlatform(id primitive.ObjectID, ctx context.Context) (int64, error)
	CreateArch(archName string, ctx context.Context) (interface{}, error)
	ListArchs(ctx context.Context) ([]*model.Arch, error)
	DeleteArch(id primitive.ObjectID, ctx context.Context) (int64, error)
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

func (c *appRepository) ListPlatforms(ctx context.Context) ([]*model.Platform, error) {

	findOptions := options.Find()
	findOptions.SetLimit(100)

	var platforms []*model.Platform

	collection := c.client.Database(c.config.Database).Collection("platforms")

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
		var elem model.Platform
		if err := cur.Decode(&elem); err != nil {
			log.Fatal(err)
			return nil, err
		}

		platforms = append(platforms, &elem)
	}

	cur.Close(ctx)

	return platforms, nil
}

func (c *appRepository) ListArchs(ctx context.Context) ([]*model.Arch, error) {

	findOptions := options.Find()
	findOptions.SetLimit(100)

	var archs []*model.Arch

	collection := c.client.Database(c.config.Database).Collection("archs")

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
		var elem model.Arch
		if err := cur.Decode(&elem); err != nil {
			log.Fatal(err)
			return nil, err
		}

		archs = append(archs, &elem)
	}

	cur.Close(ctx)

	return archs, nil
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

func (c *appRepository) DeleteApp(id primitive.ObjectID, ctx context.Context) (string, int64, error) {

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

func (c *appRepository) DeleteChannel(id primitive.ObjectID, ctx context.Context) (int64, error) {

	collection := c.client.Database(c.config.Database).Collection("channels")

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Retrieve the document before deletion
	var app *model.App
	err := collection.FindOne(ctx, filter).Decode(&app)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, fmt.Errorf("no channel found with ID %s", id)
		}
		return 0, fmt.Errorf("error retrieving channel with ID %s: %s", id, err.Error())
	}

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		log.Fatal(err)

		return 0, err
	}

	return deleteResult.DeletedCount, nil
}

func (c *appRepository) DeletePlatform(id primitive.ObjectID, ctx context.Context) (int64, error) {

	collection := c.client.Database(c.config.Database).Collection("platforms")

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Retrieve the document before deletion
	var app *model.App
	err := collection.FindOne(ctx, filter).Decode(&app)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, fmt.Errorf("no platform found with ID %s", id)
		}
		return 0, fmt.Errorf("error retrieving platform with ID %s: %s", id, err.Error())
	}

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		log.Fatal(err)

		return 0, err
	}

	return deleteResult.DeletedCount, nil
}

func (c *appRepository) DeleteArch(id primitive.ObjectID, ctx context.Context) (int64, error) {

	collection := c.client.Database(c.config.Database).Collection("archs")

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Retrieve the document before deletion
	var app *model.App
	err := collection.FindOne(ctx, filter).Decode(&app)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, fmt.Errorf("no arch found with ID %s", id)
		}
		return 0, fmt.Errorf("error retrieving arch with ID %s: %s", id, err.Error())
	}

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		log.Fatal(err)

		return 0, err
	}

	return deleteResult.DeletedCount, nil
}

func (c *appRepository) Upload(ctxQuery map[string]interface{}, appLink string, ctx context.Context) (interface{}, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")
	// Check if a document with the same "app_name" and "version" already exists
	existingDoc := collection.FindOne(ctx, bson.D{{Key: "app_name", Value: ctxQuery["app_name"].(string)}, {Key: "version", Value: ctxQuery["version"].(string)}})

	if existingDoc.Err() == nil {
		// A document with the same "app_name" and "version" combination already exists.
		return "app with this name and version already exists", errors.New("app with this name and version already exists")
	}
	publishParam, publishExists := ctxQuery["publish"]
	var publish bool

	if publishExists {
		publishVal := publishParam.(string)
		publish = publishVal == "true"
	} else {
		publish = false
	}
	filter := bson.D{
		{Key: "app_name", Value: ctxQuery["app_name"].(string)},
		{Key: "version", Value: ctxQuery["version"].(string)},
		{Key: "link", Value: appLink},
		{Key: "channel", Value: ctxQuery["channel"].(string)},
		{Key: "platform", Value: ctxQuery["platform"].(string)},
		{Key: "arch", Value: ctxQuery["arch"].(string)},
		{Key: "published", Value: publish},
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

func (c *appRepository) CreatePlatform(platformName string, ctx context.Context) (interface{}, error) {

	collection := c.client.Database(c.config.Database).Collection("platforms")

	filter := bson.D{
		{Key: "platform_name", Value: platformName},
		{Key: "updated_at", Value: time.Now()}, // add updated_at with the current time
	}

	uploadResult, err := collection.InsertOne(ctx, filter)
	mongoErr, ok := err.(mongo.WriteException)
	if ok {
		for _, writeErr := range mongoErr.WriteErrors {
			if writeErr.Code == 11000 && strings.Contains(writeErr.Message, "platform_name_sort_by_asc_created") {
				return "platform with this name already exists", errors.New("platform with this name already exists")
			}
		}
	}

	return uploadResult.InsertedID, nil
}

func (c *appRepository) CreateArch(archID string, ctx context.Context) (interface{}, error) {

	collection := c.client.Database(c.config.Database).Collection("archs")

	filter := bson.D{
		{Key: "arch_id", Value: archID},
		{Key: "updated_at", Value: time.Now()}, // add updated_at with the current time
	}

	uploadResult, err := collection.InsertOne(ctx, filter)
	mongoErr, ok := err.(mongo.WriteException)
	if ok {
		for _, writeErr := range mongoErr.WriteErrors {
			if writeErr.Code == 11000 && strings.Contains(writeErr.Message, "arch_id_sort_by_asc_created") {
				return "arch with this name already exists", errors.New("arch with this name already exists")
			}
		}
	}

	return uploadResult.InsertedID, nil
}

func (c *appRepository) CheckLatestVersion(appName, currentVersion, channel, platform, arch string, ctx context.Context) (bool, string, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")

	// Define the filter based on appName and optional channel
	filter := bson.D{
		{Key: "app_name", Value: appName},
		{Key: "published", Value: true},
	}

	if channel != "" {
		filter = append(filter, bson.E{Key: "channel", Value: channel})
	}

	if platform != "" {
		filter = append(filter, bson.E{Key: "platform", Value: platform})
	}

	if arch != "" {
		filter = append(filter, bson.E{Key: "arch", Value: arch})
	}

	// Create an aggregation pipeline to sort by version and updated_at
	// Use only bson.D for correct results
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: filter}},
		{{Key: "$addFields", Value: bson.D{
			{Key: "versions_arr", Value: bson.D{
				{Key: "$split", Value: bson.A{"$version", "."}},
			}},
		}}},
		{{Key: "$addFields", Value: bson.D{
			{Key: "major_v", Value: bson.D{
				{Key: "$toInt", Value: bson.D{
					{Key: "$arrayElemAt", Value: bson.A{"$versions_arr", 0}},
				}},
			}},
			{Key: "minor_v", Value: bson.D{
				{Key: "$toInt", Value: bson.D{
					{Key: "$arrayElemAt", Value: bson.A{"$versions_arr", 1}},
				}},
			}},
			{Key: "patch_v", Value: bson.D{
				{Key: "$toInt", Value: bson.D{
					{Key: "$arrayElemAt", Value: bson.A{"$versions_arr", 2}},
				}},
			}},
		}}},
		{{Key: "$sort", Value: bson.D{
			{Key: "major_v", Value: -1},
			{Key: "minor_v", Value: -1},
			{Key: "patch_v", Value: -1},
		}}},
		{{Key: "$limit", Value: 1}},
	}

	// Execute the aggregation pipeline
	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return false, "", err
	}
	defer cursor.Close(ctx)

	// Reset the cursor to its original position
	cursor.Close(ctx)
	cursor, err = collection.Aggregate(ctx, pipeline)
	if err != nil {
		return false, "", err
	}
	defer cursor.Close(ctx)

	// Decode the result
	var latestApp *model.App
	if cursor.Next(ctx) {
		err := cursor.Decode(&latestApp)
		if err != nil {
			return false, "", err
		}
		latestAppVersion, err := version.NewVersion(latestApp.Version)
		if err != nil {
			return false, "", err
		}

		requestedVersion, err := version.NewVersion(currentVersion)
		if err != nil {
			return false, "", err
		}

		if requestedVersion.Equal(latestAppVersion) {
			return false, latestApp.Link, nil
		} else if requestedVersion.GreaterThan(latestAppVersion) {
			return false, "Not found", fmt.Errorf("requested version %s is newest than the latest version available", requestedVersion)
		} else {
			return true, latestApp.Link, nil
		}

	} else {
		return false, "Not found", fmt.Errorf("no matching documents found for app_name: %s", appName)
	}

}
