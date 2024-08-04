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
	Get(ctx context.Context) ([]*model.SpecificAppWithoutIDs, error)
	GetAppByName(email string, ctx context.Context) ([]*model.SpecificAppWithoutIDs, error)
	DeleteSpecificVersionOfApp(id primitive.ObjectID, ctx context.Context) ([]string, int64, error)
	DeleteChannel(id primitive.ObjectID, ctx context.Context) (int64, error)
	Upload(ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (interface{}, error)
	UpdateSpecificApp(objID primitive.ObjectID, ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (bool, error)
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
	UpdateApp(id primitive.ObjectID, paramValue string, ctx context.Context) (interface{}, error)
	UpdateChannel(id primitive.ObjectID, paramValue string, ctx context.Context) (interface{}, error)
	UpdatePlatform(id primitive.ObjectID, paramValue string, ctx context.Context) (interface{}, error)
	UpdateArch(id primitive.ObjectID, paramValue string, ctx context.Context) (interface{}, error)
}

type appRepository struct {
	client *mongo.Client
	config *connstring.ConnString
}

var appMeta, channelMeta, platformMeta, archMeta struct {
	ID primitive.ObjectID `bson:"_id"`
}

func NewAppRepository(config *connstring.ConnString, client *mongo.Client) AppRepository {
	return &appRepository{config: config, client: client}
}

func (c *appRepository) getBasePipeline() mongo.Pipeline {
	return mongo.Pipeline{
		bson.D{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "app_id",
			"foreignField": "_id",
			"as":           "app_meta",
		}}},
		bson.D{{Key: "$unwind", Value: "$app_meta"}},
		bson.D{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "channel_id",
			"foreignField": "_id",
			"as":           "channel_meta",
		}}},
		bson.D{{Key: "$unwind", Value: bson.M{"path": "$channel_meta", "preserveNullAndEmptyArrays": true}}},
		bson.D{{Key: "$unwind", Value: "$artifacts"}},
		bson.D{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "artifacts.platform",
			"foreignField": "_id",
			"as":           "platform_meta",
		}}},
		bson.D{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "artifacts.arch",
			"foreignField": "_id",
			"as":           "arch_meta",
		}}},
		bson.D{{Key: "$unwind", Value: bson.M{"path": "$platform_meta", "preserveNullAndEmptyArrays": true}}},
		bson.D{{Key: "$unwind", Value: bson.M{"path": "$arch_meta", "preserveNullAndEmptyArrays": true}}},
		bson.D{{Key: "$addFields", Value: bson.M{
			"artifacts.platform": "$platform_meta.platform_name",
			"artifacts.arch":     "$arch_meta.arch_id",
		}}},
		bson.D{{Key: "$addFields", Value: bson.D{
			{Key: "versions_arr", Value: bson.D{
				{Key: "$split", Value: bson.A{"$version", "."}},
			}},
		}}},
		bson.D{{Key: "$addFields", Value: bson.D{
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
		bson.D{{Key: "$sort", Value: bson.D{
			{Key: "major_v", Value: -1},
			{Key: "minor_v", Value: -1},
			{Key: "patch_v", Value: -1},
		}}},
		bson.D{{Key: "$group", Value: bson.M{
			"_id":        "$_id",
			"app_name":   bson.M{"$first": "$app_meta.app_name"},
			"channel":    bson.M{"$first": "$channel_meta.channel_name"},
			"version":    bson.M{"$first": "$version"},
			"published":  bson.M{"$first": "$published"},
			"critical":   bson.M{"$first": "$critical"},
			"artifacts":  bson.M{"$push": "$artifacts"},
			"changelog":  bson.M{"$first": "$changelog"},
			"updated_at": bson.M{"$first": "$updated_at"},
		}}},
		bson.D{{Key: "$sort", Value: bson.D{
			{Key: "app_name", Value: 1},
			// {Key: "channel", Value: 1},
			{Key: "version", Value: 1},
		}}},
		bson.D{{Key: "$limit", Value: 100}},
	}
}

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
	// Fetch channel_id
	if channelName, ok := ctxQuery["channel"].(string); ok && channelName != "" {
		channelFilter := bson.D{{Key: "channel_name", Value: channelName}}
		err = metaCollection.FindOne(ctx, channelFilter).Decode(&channelMeta)
		if err != nil {
			return nil, errors.New("channel_name not found in apps_meta collection")
		}
		logrus.Debugf("Found channelMeta: %v", channelMeta)
	}

	// Fetch platform_id
	if platformName, ok := ctxQuery["platform"].(string); ok && platformName != "" {
		platformFilter := bson.D{{Key: "platform_name", Value: platformName}}
		err = metaCollection.FindOne(ctx, platformFilter).Decode(&platformMeta)
		if err != nil {
			return nil, errors.New("platform not found in apps_meta collection")
		}
		logrus.Debugf("Found platformMeta: %v", platformMeta)
	}

	// Fetch arch_id
	if archName, ok := ctxQuery["arch"].(string); ok && archName != "" {
		archFilter := bson.D{{Key: "arch_id", Value: archName}}
		err = metaCollection.FindOne(ctx, archFilter).Decode(&archMeta)
		if err != nil {
			return nil, errors.New("arch not found in apps_meta collection")
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
			if artifact.Package == extension {
				msg := "app with this name, version, and extension already exists"
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

func (c *appRepository) UpdateSpecificApp(objID primitive.ObjectID, ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (bool, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	var err error

	// Find app_id from apps_meta by app_name
	metaFilter := bson.D{{Key: "app_name", Value: ctxQuery["app_name"].(string)}}
	err = metaCollection.FindOne(ctx, metaFilter).Decode(&appMeta)
	if err != nil {
		return false, errors.New("app_name not found in apps_meta collection")
	}
	// Fetch channel_id
	if channelName, ok := ctxQuery["channel"].(string); ok && channelName != "" {
		channelFilter := bson.D{{Key: "channel_name", Value: channelName}}
		err = metaCollection.FindOne(ctx, channelFilter).Decode(&channelMeta)
		if err != nil {
			return false, errors.New("channel_name not found in apps_meta collection")
		}
		logrus.Debugf("Found channelMeta: %v", channelMeta)
	}

	// Fetch platform_id
	if platformName, ok := ctxQuery["platform"].(string); ok && platformName != "" {
		platformFilter := bson.D{{Key: "platform_name", Value: platformName}}
		err = metaCollection.FindOne(ctx, platformFilter).Decode(&platformMeta)
		if err != nil {
			return false, errors.New("platform not found in apps_meta collection")
		}
		logrus.Debugf("Found platformMeta: %v", platformMeta)
	}

	// Fetch arch_id
	if archName, ok := ctxQuery["arch"].(string); ok && archName != "" {
		archFilter := bson.D{{Key: "arch_id", Value: archName}}
		err = metaCollection.FindOne(ctx, archFilter).Decode(&archMeta)
		if err != nil {
			return false, errors.New("arch not found in apps_meta collection")
		}
		logrus.Debugf("Found archMeta: %v", archMeta)
	}
	// Check if a document with the same "app_id" and "version" already exists
	existingDoc := collection.FindOne(ctx, bson.D{
		{Key: "_id", Value: objID},
		{Key: "app_id", Value: appMeta.ID},
		{Key: "version", Value: ctxQuery["version"].(string)},
	})

	if existingDoc.Err() == nil {
		var appData model.SpecificApp
		if err := existingDoc.Decode(&appData); err != nil {
			return false, err
		}
		updateFields := bson.D{{Key: "updated_at", Value: time.Now()}}
		if ctxQuery["version"].(string) != "" {
			updateFields = append(updateFields, bson.E{Key: "version", Value: ctxQuery["version"].(string)})
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
			if artifact.Link == appLink && artifact.Platform == platformMeta.ID && artifact.Arch == archMeta.ID && artifact.Package == extension {
				duplicateFound = true
				break
			}
		}

		if !duplicateFound && appLink != "" && extension != "" {
			newArtifact := model.Artifact{
				Link:     appLink,
				Platform: platformMeta.ID,
				Arch:     archMeta.ID,
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

func (c *appRepository) CheckLatestVersion(appName, currentVersion, channelName, platformName, archName string, ctx context.Context) (CheckResult, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")

	// Find app_id from apps_meta by app_name
	metaFilter := bson.D{{Key: "app_name", Value: appName}}
	err := metaCollection.FindOne(ctx, metaFilter).Decode(&appMeta)
	if err != nil {
		return CheckResult{Found: false, Artifacts: []Artifact{}}, errors.New("app_name not found in apps_meta collection")
	}
	if channelName != "" {
		channelFilter := bson.D{{Key: "channel_name", Value: channelName}}
		err = metaCollection.FindOne(ctx, channelFilter).Decode(&channelMeta)
		if err != nil {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, errors.New("channel_name not found in apps_meta collection")
		}
		logrus.Debugf("Found channelMeta: %v", channelMeta)
	}

	// Fetch platform_id
	if platformName != "" {
		platformFilter := bson.D{{Key: "platform_name", Value: platformName}}
		err = metaCollection.FindOne(ctx, platformFilter).Decode(&platformMeta)
		if err != nil {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, errors.New("platform not found in apps_meta collection")
		}
		logrus.Debugf("Found platformMeta: %v", platformMeta)
	}

	// Fetch arch_id
	if archName != "" {
		archFilter := bson.D{{Key: "arch_id", Value: archName}}
		err = metaCollection.FindOne(ctx, archFilter).Decode(&archMeta)
		if err != nil {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, errors.New("arch not found in apps_meta collection")
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
