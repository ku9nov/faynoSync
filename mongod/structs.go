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
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

type AppRepository interface {
	Get(ctx context.Context) ([]*model.SpecificApp, error)
	GetAppByName(email string, ctx context.Context) ([]*model.SpecificApp, error)
	DeleteSpecificVersionOfApp(id primitive.ObjectID, ctx context.Context) ([]string, int64, error)
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
	CreateApp(archName string, ctx context.Context) (interface{}, error)
	ListApps(ctx context.Context) ([]*model.App, error)
	DeleteApp(id primitive.ObjectID, ctx context.Context) (int64, error)
}

type appRepository struct {
	client *mongo.Client
	config *connstring.ConnString
}

var appMeta struct {
	ID primitive.ObjectID `bson:"_id"`
}

func NewAppRepository(config *connstring.ConnString, client *mongo.Client) AppRepository {
	return &appRepository{config: config, client: client}
}

func (c *appRepository) Get(ctx context.Context) ([]*model.SpecificApp, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"app_id": bson.M{"$exists": true}}}},
		{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "app_id",
			"foreignField": "_id",
			"as":           "app_meta",
		}}},
		{{Key: "$unwind", Value: "$app_meta"}},
		{{Key: "$addFields", Value: bson.M{
			"app_name": "$app_meta.app_name",
		}}},
		{{Key: "$limit", Value: 100}},
	}

	cur, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		logrus.Fatal(err)
		return nil, err
	}
	defer cur.Close(ctx)

	var apps []*model.SpecificApp
	for cur.Next(ctx) {
		var elem model.SpecificApp
		if err := cur.Decode(&elem); err != nil {
			logrus.Fatal(err)
			return nil, err
		}
		apps = append(apps, &elem)
	}

	return apps, nil
}

func (c *appRepository) GetAppByName(appName string, ctx context.Context) ([]*model.SpecificApp, error) {
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	var appMeta struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	metaFilter := bson.D{{Key: "app_name", Value: appName}}
	err := metaCollection.FindOne(ctx, metaFilter).Decode(&appMeta)
	if err != nil {
		return nil, errors.New("app_name not found in apps_meta collection")
	}

	collection := c.client.Database(c.config.Database).Collection("apps")

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{primitive.E{Key: "app_id", Value: appMeta.ID}}}},
		{{Key: "$addFields", Value: bson.M{"app_name": appName}}},
		{{Key: "$limit", Value: 100}},
	}

	cur, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		logrus.Fatal(err)
		return nil, err
	}
	defer cur.Close(ctx)

	var apps []*model.SpecificApp
	for cur.Next(ctx) {
		var elem model.SpecificApp
		if err := cur.Decode(&elem); err != nil {
			logrus.Fatal(err)
			return nil, err
		}
		apps = append(apps, &elem)
	}

	return apps, nil
}

func (c *appRepository) Upload(ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (interface{}, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	var uploadResult interface{}
	var err error

	// Find app_id from apps_meta by app_name
	metaFilter := bson.D{{Key: "app_name", Value: ctxQuery["app_name"].(string)}}
	err = metaCollection.FindOne(ctx, metaFilter).Decode(&appMeta)
	if err != nil {
		return nil, errors.New("app_name not found in apps_meta collection")
	}

	// Check if a document with the same "app_id" and "version" already exists
	existingDoc := collection.FindOne(ctx, bson.D{
		{Key: "app_id", Value: appMeta.ID},
		{Key: "version", Value: ctxQuery["version"].(string)},
	})
	platform := utils.GetStringValue(ctxQuery, "platform")
	arch := utils.GetStringValue(ctxQuery, "arch")
	if existingDoc.Err() == nil {
		var appData model.SpecificApp
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
			{Key: "app_id", Value: appMeta.ID},
			{Key: "version", Value: ctxQuery["version"].(string)},
			{Key: "channel", Value: ctxQuery["channel"].(string)},
			{Key: "published", Value: publish},
			{Key: "critical", Value: critical},
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
	switch v := uploadResult.(type) {
	case *mongo.InsertOneResult:
		insertedID, ok := v.InsertedID.(primitive.ObjectID)
		if !ok {
			return nil, errors.New("error extracting ID from InsertOneResult")
		}
		return insertedID.Hex(), nil
	case primitive.ObjectID:
		return v.Hex(), nil
	default:
		return nil, errors.New("unexpected return type")
	}
}

func (c *appRepository) Update(objID primitive.ObjectID, ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (bool, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	var err error

	// Find app_id from apps_meta by app_name
	metaFilter := bson.D{{Key: "app_name", Value: ctxQuery["app_name"].(string)}}
	err = metaCollection.FindOne(ctx, metaFilter).Decode(&appMeta)
	if err != nil {
		return false, errors.New("app_name not found in apps_meta collection")
	}

	// Check if a document with the same "app_id" and "version" already exists
	existingDoc := collection.FindOne(ctx, bson.D{
		{Key: "_id", Value: objID},
		{Key: "app_id", Value: appMeta.ID},
		{Key: "version", Value: ctxQuery["version"].(string)},
	})
	platform := utils.GetStringValue(ctxQuery, "platform")
	arch := utils.GetStringValue(ctxQuery, "arch")

	if existingDoc.Err() == nil {
		var appData model.SpecificApp
		if err := existingDoc.Decode(&appData); err != nil {
			return false, err
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
		publishParam, publishExists := ctxQuery["publish"]
		criticalParam, criticalExists := ctxQuery["critical"]

		publish := false
		if publishExists {
			publish = utils.GetBoolParam(publishParam)
			updateFields = append(updateFields, bson.E{Key: "published", Value: publish})
		}

		critical := false
		if criticalExists {
			critical = utils.GetBoolParam(criticalParam)
			updateFields = append(updateFields, bson.E{Key: "critical", Value: critical})
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

type Artifact struct {
	Link    string
	Package string
}
type Changelog struct {
	Changes string
}
type CheckResult struct {
	Found     bool
	Critical  bool
	Artifacts []Artifact
	Changelog []Changelog
}

func (c *appRepository) CheckLatestVersion(appName, currentVersion, channel, platform, arch string, ctx context.Context) (CheckResult, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")

	// Find app_id from apps_meta by app_name
	metaFilter := bson.D{{Key: "app_name", Value: appName}}
	err := metaCollection.FindOne(ctx, metaFilter).Decode(&appMeta)
	if err != nil {
		return CheckResult{Found: false, Artifacts: []Artifact{}}, errors.New("app_name not found in apps_meta collection")
	}

	// Define the filter based on app_id and optional channel
	filter := bson.D{
		{Key: "app_id", Value: appMeta.ID},
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
	logrus.Debug("MongoDB Filter: ", filter)
	logrus.Debug("MongoDB Pipeline: ", pipeline)
	// Execute the aggregation pipeline
	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return CheckResult{Found: false, Artifacts: []Artifact{}}, err
	}
	defer cursor.Close(ctx)

	// Decode the result
	var latestApp *model.SpecificApp
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
			return CheckResult{Found: true, Artifacts: artifacts, Changelog: changelog, Critical: latestApp.Critical}, nil
		}

	} else {
		return CheckResult{Found: false, Artifacts: []Artifact{}}, fmt.Errorf("no matching documents found for app_name: %s", appName)
	}

}
