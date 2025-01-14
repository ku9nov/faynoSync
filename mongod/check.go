package mongod

import (
	"context"
	"errors"
	"faynoSync/server/model"
	"fmt"

	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func (c *appRepository) Get(ctx context.Context) ([]*model.SpecificAppWithoutIDs, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	basePipeline := c.getBasePipeline()
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.M{"app_id": bson.M{"$exists": true}}}},
	}
	pipeline = append(pipeline, basePipeline...)

	cur, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		logrus.Error("Aggregation failed: ", err)
		return nil, err
	}
	defer cur.Close(ctx)
	return c.processApps(cur, ctx)
}
func (c *appRepository) GetAppByName(appName string, ctx context.Context) ([]*model.SpecificAppWithoutIDs, error) {
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	metaFilter := bson.D{{Key: "app_name", Value: appName}}
	err := metaCollection.FindOne(ctx, metaFilter).Decode(&appMeta)
	if err != nil {
		return nil, errors.New("app_name not found in apps_meta collection")
	}

	collection := c.client.Database(c.config.Database).Collection("apps")

	basePipeline := c.getBasePipeline()
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.M{"app_id": appMeta.ID}}},
	}
	pipeline = append(pipeline, basePipeline...)

	cur, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		logrus.Fatal(err)
		return nil, err
	}
	defer cur.Close(ctx)

	return c.processApps(cur, ctx)
}
func (c *appRepository) CheckLatestVersion(appName, currentVersion, channelName, platformName, archName string, ctx context.Context) (CheckResult, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")

	var appMeta, channelMeta, platformMeta, archMeta struct {
		ID primitive.ObjectID `bson:"_id"`
	}

	// Find app_id from apps_meta by app_name
	err := c.getMeta(ctx, metaCollection, "app_name", appName, &appMeta)
	if err != nil {
		return CheckResult{Found: false, Artifacts: []Artifact{}}, err
	}

	// Fetch channel_id
	if channelName != "" {
		err = c.getMeta(ctx, metaCollection, "channel_name", channelName, &channelMeta)
		if err != nil {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, err
		}
		logrus.Debugf("Found channelMeta: %v", channelMeta)
	}

	// Fetch platform_id
	if platformName != "" {
		err = c.getMeta(ctx, metaCollection, "platform_name", platformName, &platformMeta)
		if err != nil {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, err
		}
		logrus.Debugf("Found platformMeta: %v", platformMeta)
	}

	// Fetch arch_id
	if archName != "" {
		err = c.getMeta(ctx, metaCollection, "arch_id", archName, &archMeta)
		if err != nil {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, err
		}
		logrus.Debugf("Found archMeta: %v", archMeta)
	}
	// Define the filter based on app_id and optional channel
	filter := bson.D{
		{Key: "app_id", Value: appMeta.ID},
		{Key: "published", Value: true},
		{
			Key: "artifacts", Value: bson.D{
				{Key: "$elemMatch", Value: bson.D{
					{Key: "platform", Value: platformMeta.ID},
					{Key: "arch", Value: archMeta.ID},
				}},
			},
		},
	}

	if channelName != "" {
		filter = append(filter, bson.E{Key: "channel_id", Value: channelMeta.ID})
	}

	// Create an aggregation pipeline to sort by version and updated_at
	// Use only bson.D for correct results
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: filter}},
	}
	pipeline = append(pipeline, c.sortVersionPipeline()...)
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

func (c *appRepository) FetchLatestVersionOfApp(appName, channel string, ctx context.Context) ([]*model.SpecificAppWithoutIDs, error) {
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	metaFilter := bson.D{{Key: "app_name", Value: appName}}
	err := metaCollection.FindOne(ctx, metaFilter).Decode(&appMeta)
	if err != nil {
		return nil, errors.New("app_name not found in apps_meta collection")
	}
	var channelMeta struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	if channel != "" {
		channelFilter := bson.D{{Key: "channel_name", Value: channel}}
		err := metaCollection.FindOne(ctx, channelFilter).Decode(&channelMeta)
		if err != nil {
			return nil, errors.New("channel not found in apps_meta collection")
		}
	}
	collection := c.client.Database(c.config.Database).Collection("apps")
	matchFilter := bson.M{"app_id": appMeta.ID, "published": true}

	if channel != "" {
		matchFilter["channel_id"] = channelMeta.ID
	}

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: matchFilter}},
	}
	pipeline = append(pipeline, c.sortVersionPipeline()...)
	basePipeline := c.getBasePipeline()
	pipeline = append(pipeline, basePipeline...)

	logrus.Debug("MongoDB Pipeline: ", pipeline)

	cur, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	return c.processApps(cur, ctx)
}

func (c *appRepository) FetchAppByID(appID primitive.ObjectID, ctx context.Context) ([]*model.SpecificAppWithoutIDs, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")

	matchFilter := bson.M{"_id": appID}

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: matchFilter}},
	}
	basePipeline := c.getBasePipeline()
	pipeline = append(pipeline, basePipeline...)

	logrus.Debug("MongoDB Pipeline for FetchAppByID: ", pipeline)

	cur, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	return c.processApps(cur, ctx)
}

func (c *appRepository) getMeta(ctx context.Context, metaCollection *mongo.Collection, key, value string, result interface{}) error {
	filter := bson.D{{Key: key, Value: value}}
	err := metaCollection.FindOne(ctx, filter).Decode(result)
	if err != nil {
		return fmt.Errorf("%s not found in apps_meta collection", key)
	}
	return nil
}

func (c *appRepository) processApps(cur *mongo.Cursor, ctx context.Context) ([]*model.SpecificAppWithoutIDs, error) {
	var apps []*model.SpecificAppWithoutIDs
	for cur.Next(ctx) {
		var tempApp model.SpecificAppWithoutIDs
		if err := cur.Decode(&tempApp); err != nil {
			logrus.Fatal(err)
			return nil, err
		}
		app := &model.SpecificAppWithoutIDs{
			ID:        tempApp.ID,
			AppName:   tempApp.AppName,
			Version:   tempApp.Version,
			Channel:   tempApp.Channel,
			Published: tempApp.Published,
			Critical:  tempApp.Critical,
			Artifacts: tempApp.Artifacts,
			Changelog: tempApp.Changelog,
			UpdatedAt: tempApp.UpdatedAt,
		}

		apps = append(apps, app)
	}
	return apps, nil
}
