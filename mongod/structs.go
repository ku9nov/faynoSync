package mongod

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"faynoSync/server/model"
	"faynoSync/server/utils"

	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

type AppRepository interface {
	Get(ctx context.Context) ([]*model.App, error)
	GetAppByName(email string, ctx context.Context) ([]*model.App, error)
	DeleteApp(id primitive.ObjectID, ctx context.Context) ([]string, int64, error)
	DeleteChannel(id primitive.ObjectID, ctx context.Context) (int64, error)
	Upload(ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (interface{}, error)
	Update(objID primitive.ObjectID, ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (bool, error)
	CheckLatestVersion(appName, version, channel, platform, arch string, ctx context.Context) (CheckResult, error)
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

	filter := bson.M{"app_name": bson.M{"$exists": true}}
	// Passing bson.D{{}} as the filter matches all documents in the collection
	cur, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		logrus.Fatal(err)
		return nil, err
	}

	// Finding multiple documents returns a cursor
	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		var elem model.App
		if err := cur.Decode(&elem); err != nil {
			logrus.Fatal(err)
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

	collection := c.client.Database(c.config.Database).Collection("apps")
	// Define a filter to fetch documents with the "channel_name" field
	filter := bson.M{"channel_name": bson.M{"$exists": true}}

	cur, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		logrus.Fatal(err)
		return nil, err
	}

	// Finding multiple documents returns a cursor
	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		var elem model.Channel
		if err := cur.Decode(&elem); err != nil {
			logrus.Fatal(err)
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

	collection := c.client.Database(c.config.Database).Collection("apps")
	// Define a filter to fetch documents with the "platform_name" field
	filter := bson.M{"platform_name": bson.M{"$exists": true}}

	cur, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		logrus.Fatal(err)
		return nil, err
	}

	// Finding multiple documents returns a cursor
	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		var elem model.Platform
		if err := cur.Decode(&elem); err != nil {
			logrus.Fatal(err)
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

	collection := c.client.Database(c.config.Database).Collection("apps")
	// Define a filter to fetch documents with the "arch_id" field
	filter := bson.M{"arch_id": bson.M{"$exists": true}}

	cur, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		logrus.Fatal(err)
		return nil, err
	}

	// Finding multiple documents returns a cursor
	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		var elem model.Arch
		if err := cur.Decode(&elem); err != nil {
			logrus.Fatal(err)
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
		logrus.Fatal(err)
		return nil, err
	}
	// Finding multiple documents returns a cursor
	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		var elem model.App
		if err := cur.Decode(&elem); err != nil {
			logrus.Fatal(err)
			return nil, err
		}

		apps = append(apps, &elem)
	}

	cur.Close(ctx)

	return apps, nil
}

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

func (c *appRepository) DeleteChannel(id primitive.ObjectID, ctx context.Context) (int64, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Retrieve the document before deletion
	var channel *model.Channel
	err := collection.FindOne(ctx, filter).Decode(&channel)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, fmt.Errorf("no channel found with ID %s", id)
		}
		return 0, fmt.Errorf("error retrieving channel with ID %s: %s", id, err.Error())
	}

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		logrus.Fatal(err)

		return 0, err
	}

	return deleteResult.DeletedCount, nil
}

func (c *appRepository) DeletePlatform(id primitive.ObjectID, ctx context.Context) (int64, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Retrieve the document before deletion
	var platform *model.Platform
	err := collection.FindOne(ctx, filter).Decode(&platform)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, fmt.Errorf("no platform found with ID %s", id)
		}
		return 0, fmt.Errorf("error retrieving platform with ID %s: %s", id, err.Error())
	}

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		logrus.Fatal(err)

		return 0, err
	}

	return deleteResult.DeletedCount, nil
}

func (c *appRepository) DeleteArch(id primitive.ObjectID, ctx context.Context) (int64, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Retrieve the document before deletion
	var arch *model.Arch
	err := collection.FindOne(ctx, filter).Decode(&arch)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, fmt.Errorf("no arch found with ID %s", id)
		}
		return 0, fmt.Errorf("error retrieving arch with ID %s: %s", id, err.Error())
	}

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		logrus.Fatal(err)

		return 0, err
	}

	return deleteResult.DeletedCount, nil
}

func (c *appRepository) Upload(ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (interface{}, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	var uploadResult interface{}
	var err error
	// Check if a document with the same "app_name" and "version" already exists
	existingDoc := collection.FindOne(ctx, bson.D{
		{Key: "app_name", Value: ctxQuery["app_name"].(string)},
		{Key: "version", Value: ctxQuery["version"].(string)},
	})
	platform := utils.GetStringValue(ctxQuery, "platform")
	arch := utils.GetStringValue(ctxQuery, "arch")
	if existingDoc.Err() == nil {
		var appData model.App
		if err := existingDoc.Decode(&appData); err != nil {
			return nil, err
		}

		for _, artifact := range appData.Artifacts {
			if artifact.Package == extension {
				msg := "app with this name, version, and extension already exists"
				return msg, errors.New(msg)
			}
		}

		appData.Artifacts = append(appData.Artifacts, model.Artifact{
			Link:     appLink,
			Platform: platform,
			Arch:     arch,
			Package:  extension,
		})
		_, err = collection.UpdateOne(
			ctx,
			bson.D{{Key: "app_name", Value: ctxQuery["app_name"].(string)}, {Key: "version", Value: ctxQuery["version"].(string)}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "artifacts", Value: appData.Artifacts}, {Key: "updated_at", Value: time.Now()}}}},
		)
		if err != nil {
			return nil, err
		}

		uploadResult = appData.ID
	} else {
		// Handle the case when no document exists
		publishParam, publishExists := ctxQuery["publish"]
		var publish bool

		if publishExists {
			publishVal := publishParam.(string)
			publish = publishVal == "true"
		} else {
			publish = false
		}

		artifact := model.Artifact{
			Link:     appLink,
			Platform: platform,
			Arch:     arch,
			Package:  extension,
		}
		changelog := model.Changelog{
			Version: ctxQuery["version"].(string),
			Changes: ctxQuery["changelog"].(string),
			Date:    time.Now().Format("2006-01-02"),
		}
		filter := bson.D{
			{Key: "app_name", Value: ctxQuery["app_name"].(string)},
			{Key: "version", Value: ctxQuery["version"].(string)},
			{Key: "channel", Value: ctxQuery["channel"].(string)},
			{Key: "published", Value: publish},
			{Key: "artifacts", Value: []model.Artifact{artifact}},
			{Key: "changelog", Value: []model.Changelog{changelog}},
			{Key: "updated_at", Value: time.Now()},
		}

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
	switch uploadResult.(type) {
	case *mongo.InsertOneResult:
		result, ok := uploadResult.(*mongo.InsertOneResult)
		if !ok {
			return nil, errors.New("error casting to InsertOneResult")
		}
		insertedID, ok := result.InsertedID.(primitive.ObjectID)
		if !ok {
			return nil, errors.New("error extracting ID from InsertOneResult")
		}
		return insertedID.Hex(), nil
	case primitive.ObjectID:
		id, ok := uploadResult.(primitive.ObjectID)
		if !ok {
			return nil, errors.New("error casting to ObjectID")
		}
		return id.Hex(), nil
	default:
		return nil, errors.New("unexpected return type")
	}
}

func (c *appRepository) Update(objID primitive.ObjectID, ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (bool, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	var err error

	// Check if a document with the same "app_name" and "version" already exists
	existingDoc := collection.FindOne(ctx, bson.D{
		{Key: "_id", Value: objID},
		{Key: "app_name", Value: ctxQuery["app_name"].(string)},
		{Key: "version", Value: ctxQuery["version"].(string)},
	})
	platform := utils.GetStringValue(ctxQuery, "platform")
	arch := utils.GetStringValue(ctxQuery, "arch")

	if existingDoc.Err() == nil {
		var appData model.App
		if err := existingDoc.Decode(&appData); err != nil {
			return false, err
		}

		publishParam, publishExists := ctxQuery["publish"]
		var publish bool

		if publishExists {
			publishVal := publishParam.(string)
			publish = publishVal == "true"
		} else {
			publish = false
		}

		updateFields := bson.D{{Key: "updated_at", Value: time.Now()}}
		if ctxQuery["app_name"].(string) != "" {
			updateFields = append(updateFields, bson.E{Key: "app_name", Value: ctxQuery["app_name"].(string)})
		}
		if ctxQuery["version"].(string) != "" {
			updateFields = append(updateFields, bson.E{Key: "version", Value: ctxQuery["version"].(string)})
		}
		if ctxQuery["channel"].(string) != "" {
			updateFields = append(updateFields, bson.E{Key: "channel", Value: ctxQuery["channel"].(string)})
		}
		if publishExists {
			updateFields = append(updateFields, bson.E{Key: "published", Value: publish})
		}

		duplicateFound := false
		for _, artifact := range appData.Artifacts {
			if artifact.Link == appLink && artifact.Platform == platform && artifact.Arch == arch && artifact.Package == extension {
				duplicateFound = true
				break
			}
		}

		if !duplicateFound && appLink != "" && extension != "" {
			newArtifact := model.Artifact{
				Link:     appLink,
				Platform: platform,
				Arch:     arch,
				Package:  extension,
			}
			appData.Artifacts = append(appData.Artifacts, newArtifact)
		}
		if len(appData.Artifacts) > 0 {
			updateFields = append(updateFields, bson.E{Key: "artifacts", Value: appData.Artifacts})
		}

		// Add or update changelog
		if changelog, exists := ctxQuery["changelog"].(string); exists && changelog != "" {
			changelogUpdated := false
			for i, log := range appData.Changelog {
				if log.Version == ctxQuery["version"].(string) {
					appData.Changelog[i].Changes = changelog
					appData.Changelog[i].Date = time.Now().Format("2006-01-02")
					changelogUpdated = true
					break
				}
			}
			if !changelogUpdated {
				newChangelog := model.Changelog{
					Version: ctxQuery["version"].(string),
					Changes: changelog,
					Date:    time.Now().Format("2006-01-02"),
				}
				appData.Changelog = append(appData.Changelog, newChangelog)
			}
			updateFields = append(updateFields, bson.E{Key: "changelog", Value: appData.Changelog})
		}

		_, err = collection.UpdateOne(
			ctx,
			bson.D{{Key: "_id", Value: objID}},
			bson.D{{Key: "$set", Value: updateFields}},
		)
		if err != nil {
			return false, err
		}

		return true, nil
	} else {
		return false, errors.New("app with this parameters doesn't exist")
	}
}

func (c *appRepository) CreateChannel(channelName string, ctx context.Context) (interface{}, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{
		{Key: "channel_name", Value: channelName},
		{Key: "updated_at", Value: time.Now()}, // add updated_at with the current time
	}
	uploadResult, err := collection.InsertOne(ctx, filter)
	if err != nil {
		logrus.Errorf("Error inserting document: %v", err)
		return nil, err
	}
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

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{
		{Key: "platform_name", Value: platformName},
		{Key: "updated_at", Value: time.Now()}, // add updated_at with the current time
	}

	uploadResult, err := collection.InsertOne(ctx, filter)
	if err != nil {
		logrus.Errorf("Error inserting document: %v", err)
		return nil, err
	}
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

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{
		{Key: "arch_id", Value: archID},
		{Key: "updated_at", Value: time.Now()}, // add updated_at with the current time
	}

	uploadResult, err := collection.InsertOne(ctx, filter)
	if err != nil {
		logrus.Errorf("Error inserting document: %v", err)
		return nil, err
	}
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

type Artifact struct {
	Link    string
	Package string
}
type Changelog struct {
	Changes string
}
type CheckResult struct {
	Found     bool
	Artifacts []Artifact
	Changelog []Changelog
}

func (c *appRepository) CheckLatestVersion(appName, currentVersion, channel, platform, arch string, ctx context.Context) (CheckResult, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")

	// Define the filter based on appName and optional channel
	filter := bson.D{
		{Key: "app_name", Value: appName},
		{Key: "published", Value: true},
		{
			Key: "artifacts", Value: bson.D{
				{Key: "$elemMatch", Value: bson.D{
					{Key: "platform", Value: platform},
					{Key: "arch", Value: arch},
				}},
			},
		},
	}

	if channel != "" {
		filter = append(filter, bson.E{Key: "channel", Value: channel})
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
		return CheckResult{Found: false, Artifacts: []Artifact{}}, err
	}
	defer cursor.Close(ctx)

	// Decode the result
	var latestApp *model.App
	if cursor.Next(ctx) {
		err := cursor.Decode(&latestApp)
		if err != nil {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, err
		}
		logrus.Debug("Latest app: ", latestApp)
		latestAppVersion, err := version.NewVersion(latestApp.Version)
		if err != nil {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, err
		}

		requestedVersion, err := version.NewVersion(currentVersion)
		if err != nil {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, err
		}
		var artifacts []Artifact

		// Convert latestApp.Changelog to []Changelog
		changelog := make([]Changelog, len(latestApp.Changelog))
		for i, entry := range latestApp.Changelog {
			changelog[i] = Changelog{
				Changes: entry.Changes,
			}
		}
		// Iterate through all elements in latestApp.Artifacts and append both link and package type
		for _, artifact := range latestApp.Artifacts {
			artifacts = append(artifacts, Artifact{
				Link:    artifact.Link,
				Package: artifact.Package,
			})
		}
		if requestedVersion.Equal(latestAppVersion) {
			return CheckResult{Found: false, Artifacts: artifacts}, nil
		} else if requestedVersion.GreaterThan(latestAppVersion) {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, fmt.Errorf("requested version %s is newer than the latest version available", requestedVersion)
		} else {
			return CheckResult{Found: true, Artifacts: artifacts, Changelog: changelog}, nil
		}

	} else {
		return CheckResult{Found: false, Artifacts: []Artifact{}}, fmt.Errorf("no matching documents found for app_name: %s", appName)
	}

}
