package mongod

import (
	"context"
	"errors"
	"faynoSync/server/model"
	"fmt"
	"sort"

	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func (c *appRepository) Get(ctx context.Context, limit int64, owner string) ([]*model.SpecificAppWithoutIDs, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	basePipeline := c.getBasePipeline()
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.M{
			"app_id": bson.M{"$exists": true},
			"owner":  owner,
		}}},
	}
	pipeline = append(pipeline, basePipeline...)
	pipeline = append(pipeline, bson.D{{Key: "$limit", Value: limit}})

	cur, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		logrus.Error("Aggregation failed: ", err)
		return nil, err
	}
	defer cur.Close(ctx)
	return c.processApps(cur, ctx)
}

func (c *appRepository) GetAppByName(appName string, ctx context.Context, page, limit int64, owner string, filters map[string]interface{}) (*model.PaginatedResponse, error) {
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	metaFilter := bson.D{
		{Key: "app_name", Value: appName},
		{Key: "owner", Value: owner},
	}

	// Check if the user is a team user
	teamUsersCollection := c.client.Database(c.config.Database).Collection("team_users")
	var teamUser model.TeamUser
	err := teamUsersCollection.FindOne(ctx, bson.M{"username": owner}).Decode(&teamUser)

	// If user is a team user, we need to check their permissions
	if err == nil {
		logrus.Debugf("User %s is a team user owned by %s", owner, teamUser.Owner)
		// Update the meta filter to use the team user's owner
		metaFilter = bson.D{
			{Key: "app_name", Value: appName},
			{Key: "owner", Value: teamUser.Owner},
		}

		// Check if the user has any allowed apps
		if len(teamUser.Permissions.Apps.Allowed) == 0 {
			return nil, errors.New("you don't have permission to access any apps")
		}
	}

	err = metaCollection.FindOne(ctx, metaFilter).Decode(&appMeta)
	if err != nil {
		return nil, errors.New("app_name not found in apps_meta collection")
	}

	// If user is a team user, verify the app is in their allowed list
	if teamUser.Username != "" {
		appID := appMeta.ID.Hex()
		appAllowed := false
		for _, allowedAppID := range teamUser.Permissions.Apps.Allowed {
			if allowedAppID == appID {
				appAllowed = true
				break
			}
		}

		if !appAllowed {
			return nil, errors.New("you don't have permission to access this app")
		}
	}

	collection := c.client.Database(c.config.Database).Collection("apps")

	// Determine the owner for the pipeline
	pipelineOwner := owner
	if teamUser.Username != "" {
		pipelineOwner = teamUser.Owner
	}

	// Build the match stage with filters
	matchStage := bson.M{
		"app_id": appMeta.ID,
		"owner":  pipelineOwner,
	}

	// Add filters to match stage if they exist
	for key, value := range filters {
		switch key {
		case "channel":
			// For channel, we need to get the channel_id from apps_meta
			var channelMeta struct {
				ID primitive.ObjectID `bson:"_id"`
			}
			err := metaCollection.FindOne(ctx, bson.M{
				"channel_name": value,
				"owner":        pipelineOwner,
			}).Decode(&channelMeta)
			if err != nil {
				return nil, fmt.Errorf("channel not found in apps_meta collection")
			}
			matchStage["channel_id"] = channelMeta.ID
		case "published", "critical":
			matchStage[key] = value
		case "platform", "arch":
			// For platform and arch, we need to get the ObjectID first
			var meta struct {
				ID primitive.ObjectID `bson:"_id"`
			}
			metaKey := "platform_name"
			if key == "arch" {
				metaKey = "arch_id"
			}
			err := metaCollection.FindOne(ctx, bson.M{
				metaKey: value,
				"owner": pipelineOwner,
			}).Decode(&meta)
			if err != nil {
				return nil, fmt.Errorf("%s not found in apps_meta collection", key)
			}

			// Add the filter to the artifacts array
			if matchStage["artifacts"] == nil {
				matchStage["artifacts"] = bson.M{
					"$elemMatch": bson.M{
						key: meta.ID,
					},
				}
			} else {
				// If we already have an $elemMatch, add to it
				elemMatch := matchStage["artifacts"].(bson.M)["$elemMatch"].(bson.M)
				elemMatch[key] = meta.ID
			}
		}
	}

	countPipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: matchStage}},
		bson.D{{Key: "$count", Value: "total"}},
	}
	countCursor, err := collection.Aggregate(ctx, countPipeline)
	if err != nil {
		logrus.Errorf("Error during count aggregation: %v", err)
		return nil, err
	}
	defer countCursor.Close(ctx)

	var countResult struct {
		Total int64 `bson:"total"`
	}
	if countCursor.Next(ctx) {
		if err := countCursor.Decode(&countResult); err != nil {
			logrus.Errorf("Error decoding count result: %v", err)
			return nil, err
		}
	}
	total := countResult.Total

	basePipeline := c.getBasePipeline()
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: matchStage}},
	}
	pipeline = append(pipeline, basePipeline...)
	pipeline = append(pipeline,
		bson.D{{Key: "$skip", Value: (page - 1) * limit}},
		bson.D{{Key: "$limit", Value: limit}},
	)

	cur, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		logrus.Errorf("Error during aggregation: %v", err)
		return nil, err
	}
	defer cur.Close(ctx)
	items, err := c.processApps(cur, ctx)
	if err != nil {
		logrus.Errorf("Error processing apps: %v", err)
		return nil, err
	}

	return &model.PaginatedResponse{
		Items: items,
		Total: total,
		Page:  page,
		Limit: limit,
	}, nil
}

func (c *appRepository) CheckRequiredMigrationStep(ctx context.Context, collection *mongo.Collection, appID primitive.ObjectID, currentVersion, latestVersion string, channelID, platformID, archID primitive.ObjectID) (string, error) {
	logrus.Debugf("Checking required migration step for app_id: %s, current_version: %s, latest_version: %s", appID, currentVersion, latestVersion)
	filter := bson.D{
		{Key: "app_id", Value: appID},
		{Key: "required_intermediate", Value: true},
		{Key: "published", Value: true},
		{Key: "channel_id", Value: channelID},
		{Key: "artifacts", Value: bson.D{
			{Key: "$elemMatch", Value: bson.D{
				{Key: "platform", Value: platformID},
				{Key: "arch", Value: archID},
			}},
		}},
	}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return "", err
	}
	defer cursor.Close(ctx)

	var requiredSteps []string
	latestVer := version.Must(version.NewVersion(latestVersion))
	currentVer := version.Must(version.NewVersion(currentVersion))

	for cursor.Next(ctx) {
		var v struct {
			Version string `bson:"version"`
		}
		if err := cursor.Decode(&v); err != nil {
			continue
		}
		stepVer := version.Must(version.NewVersion(v.Version))

		if stepVer.GreaterThan(currentVer) && !stepVer.GreaterThan(latestVer) {
			requiredSteps = append(requiredSteps, v.Version)
		}
	}

	if len(requiredSteps) > 0 {
		// Sort versions to get the first required intermediate version
		sort.Slice(requiredSteps, func(i, j int) bool {
			vi := version.Must(version.NewVersion(requiredSteps[i]))
			vj := version.Must(version.NewVersion(requiredSteps[j]))
			return vi.LessThan(vj)
		})
		return requiredSteps[0], nil
	}

	return "", nil
}

func (c *appRepository) CheckLatestVersion(appName, currentVersion, channelName, platformName, archName string, ctx context.Context, owner string) (CheckResult, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")

	var appMeta, channelMeta, platformMeta, archMeta struct {
		ID primitive.ObjectID `bson:"_id"`
	}

	// Find app_id from apps_meta by app_name
	err := c.getMeta(ctx, metaCollection, "app_name", appName, &appMeta, owner)
	if err != nil {
		return CheckResult{Found: false, Artifacts: []Artifact{}}, err
	}

	// Fetch channel_id
	if channelName != "" {
		err = c.getMeta(ctx, metaCollection, "channel_name", channelName, &channelMeta, owner)
		if err != nil {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, err
		}
		logrus.Debugf("Found channelMeta: %v", channelMeta)
	}

	// Fetch platform_id
	if platformName != "" {
		err = c.getMeta(ctx, metaCollection, "platform_name", platformName, &platformMeta, owner)
		if err != nil {
			return CheckResult{Found: false, Artifacts: []Artifact{}}, err
		}
		logrus.Debugf("Found platformMeta: %v", platformMeta)
	}

	// Fetch arch_id
	if archName != "" {
		err = c.getMeta(ctx, metaCollection, "arch_id", archName, &archMeta, owner)
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

		// Check for required migration steps
		requiredIntermediate, err := c.CheckRequiredMigrationStep(ctx, collection, appMeta.ID, currentVersion, latestApp.Version, channelMeta.ID, platformMeta.ID, archMeta.ID)
		if err != nil {
			logrus.Errorf("Error checking required migration steps: %v", err)
		}

		var artifacts []Artifact
		var changelog []Changelog
		logrus.Debugf("Required intermediate: %v", requiredIntermediate)
		// If there's a required intermediate, get its details
		if requiredIntermediate != "" {
			// Find the required intermediate version details
			var requiredApp model.SpecificApp
			err := collection.FindOne(ctx, bson.M{
				"app_id":    appMeta.ID,
				"version":   requiredIntermediate,
				"published": true,
			}).Decode(&requiredApp)

			if err == nil {
				// Convert requiredApp.Changelog to []Changelog
				changelog = make([]Changelog, len(requiredApp.Changelog))
				for i, entry := range requiredApp.Changelog {
					changelog[i] = Changelog{
						Changes: entry.Changes,
					}
				}
				// Get artifacts for required version
				for _, artifact := range requiredApp.Artifacts {
					artifacts = append(artifacts, Artifact{
						Link:    artifact.Link,
						Package: artifact.Package,
					})
				}
				return CheckResult{
					Found:                  true,
					Artifacts:              artifacts,
					Changelog:              changelog,
					Critical:               requiredApp.Critical,
					IsRequiredIntermediate: true,
				}, nil
			}
		}

		// If no required step or error getting required step details, proceed with normal flow
		// Convert latestApp.Changelog to []Changelog
		changelog = make([]Changelog, len(latestApp.Changelog))
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

func (c *appRepository) FetchLatestVersionOfApp(appName, channel string, ctx context.Context, owner string) ([]*model.SpecificAppWithoutIDs, error) {
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	metaFilter := bson.D{{Key: "app_name", Value: appName}, {Key: "owner", Value: owner}}
	err := metaCollection.FindOne(ctx, metaFilter).Decode(&appMeta)
	if err != nil {
		return nil, errors.New("app_name not found in apps_meta collection")
	}
	var channelMeta struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	if channel != "" {
		channelFilter := bson.D{{Key: "channel_name", Value: channel}, {Key: "owner", Value: owner}}
		err := metaCollection.FindOne(ctx, channelFilter).Decode(&channelMeta)
		if err != nil {
			return nil, errors.New("channel not found in apps_meta collection")
		}
	}
	collection := c.client.Database(c.config.Database).Collection("apps")
	matchFilter := bson.M{"app_id": appMeta.ID, "published": true, "owner": owner}

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

func (c *appRepository) getMeta(ctx context.Context, metaCollection *mongo.Collection, key, value string, result interface{}, owner string) error {
	filter := bson.D{{Key: key, Value: value}, {Key: "owner", Value: owner}}
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
			ID:           tempApp.ID,
			AppName:      tempApp.AppName,
			Version:      tempApp.Version,
			Channel:      tempApp.Channel,
			Published:    tempApp.Published,
			Critical:     tempApp.Critical,
			Intermediate: tempApp.Intermediate,
			Artifacts:    tempApp.Artifacts,
			Changelog:    tempApp.Changelog,
			UpdatedAt:    tempApp.UpdatedAt,
		}
		apps = append(apps, app)
	}
	return apps, nil
}
