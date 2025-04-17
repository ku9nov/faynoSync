package mongod

import (
	"context"
	"errors"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func (c *appRepository) CreateDocument(collectionName string, document bson.D, uniqueKey, keyType string, owner string, ctx context.Context) (interface{}, error) {
	collection := c.client.Database(c.config.Database).Collection(collectionName)

	// Set the updated_at field to the current time
	document = append(document, bson.E{Key: "updated_at", Value: time.Now()})
	// Add owner field
	document = append(document, bson.E{Key: "owner", Value: owner})
	logrus.Debugln("Document: ", document)
	uploadResult, err := collection.InsertOne(ctx, document)
	if err != nil {
		if mongoErr, ok := err.(mongo.WriteException); ok {
			for _, writeErr := range mongoErr.WriteErrors {
				if writeErr.Code == 11000 && strings.Contains(writeErr.Message, uniqueKey) {
					return nil, fmt.Errorf("%s with this name already exists", keyType)
				}
			}
		}
		logrus.Errorf("Error inserting document: %v", err)
		return nil, err
	}

	return uploadResult.InsertedID, nil
}

// Helper function to check if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// createMetaDocument is a helper function that handles the common logic for creating meta documents
// and updating team user permissions if needed
func (c *appRepository) createMetaDocument(
	document bson.D,
	uniqueKey string,
	keyType string,
	owner string,
	ctx context.Context,
	updateTeamUserPermissions func(teamUser model.TeamUser, result interface{}, teamUsername string) error,
) (interface{}, error) {
	// Check if the creator is a team user
	teamUsersCollection := c.client.Database(c.config.Database).Collection("team_users")
	var teamUser model.TeamUser
	err := teamUsersCollection.FindOne(ctx, bson.M{"username": owner}).Decode(&teamUser)
	teamUsername := owner // Store the original username for permission update
	if err == nil {
		// User is a team user, set owner to their admin
		owner = teamUser.Owner
	}

	result, err := c.CreateDocument("apps_meta", document, uniqueKey, keyType, owner, ctx)
	if err != nil {
		return nil, err
	}

	// If the creator is a team user and we have a permission update function, update their permissions
	if updateTeamUserPermissions != nil {
		err = updateTeamUserPermissions(teamUser, result, teamUsername)
		if err != nil {
			logrus.Errorf("Failed to update team user permissions: %v", err)
			// Don't return error here as the document was created successfully
		}
	}

	return result, nil
}

// CreateChannel creates a new channel document
func (c *appRepository) CreateChannel(channelName string, owner string, ctx context.Context) (interface{}, error) {
	document := bson.D{{Key: "channel_name", Value: channelName}}

	updateTeamUserPermissions := func(teamUser model.TeamUser, result interface{}, teamUsername string) error {
		// Add the channel ID to their allowed channels
		channelID := result.(primitive.ObjectID).Hex()
		if !contains(teamUser.Permissions.Channels.Allowed, channelID) {
			teamUser.Permissions.Channels.Allowed = append(teamUser.Permissions.Channels.Allowed, channelID)
			update := bson.M{"$set": bson.M{"permissions": teamUser.Permissions}}
			_, err := c.client.Database(c.config.Database).Collection("team_users").UpdateOne(
				ctx,
				bson.M{"username": teamUsername},
				update,
			)
			return err
		}
		return nil
	}

	return c.createMetaDocument(
		document,
		"channel_name_owner_sort_by_asc_created",
		"channel",
		owner,
		ctx,
		updateTeamUserPermissions,
	)
}

// CreatePlatform creates a new platform document
func (c *appRepository) CreatePlatform(platformName string, owner string, ctx context.Context) (interface{}, error) {
	document := bson.D{{Key: "platform_name", Value: platformName}}

	updateTeamUserPermissions := func(teamUser model.TeamUser, result interface{}, teamUsername string) error {
		// Add the platform ID to their allowed platforms
		platformID := result.(primitive.ObjectID).Hex()
		if !contains(teamUser.Permissions.Platforms.Allowed, platformID) {
			teamUser.Permissions.Platforms.Allowed = append(teamUser.Permissions.Platforms.Allowed, platformID)
			update := bson.M{"$set": bson.M{"permissions": teamUser.Permissions}}
			_, err := c.client.Database(c.config.Database).Collection("team_users").UpdateOne(
				ctx,
				bson.M{"username": teamUsername},
				update,
			)
			return err
		}
		return nil
	}

	return c.createMetaDocument(
		document,
		"platform_name_owner_sort_by_asc_created",
		"platform",
		owner,
		ctx,
		updateTeamUserPermissions,
	)
}

// CreateArch creates a new arch document
func (c *appRepository) CreateArch(archID string, owner string, ctx context.Context) (interface{}, error) {
	document := bson.D{{Key: "arch_id", Value: archID}}

	updateTeamUserPermissions := func(teamUser model.TeamUser, result interface{}, teamUsername string) error {
		// Add the arch ID to their allowed archs
		archID := result.(primitive.ObjectID).Hex()
		if !contains(teamUser.Permissions.Archs.Allowed, archID) {
			teamUser.Permissions.Archs.Allowed = append(teamUser.Permissions.Archs.Allowed, archID)
			update := bson.M{"$set": bson.M{"permissions": teamUser.Permissions}}
			_, err := c.client.Database(c.config.Database).Collection("team_users").UpdateOne(
				ctx,
				bson.M{"username": teamUsername},
				update,
			)
			return err
		}
		return nil
	}

	return c.createMetaDocument(
		document,
		"arch_id_owner_sort_by_asc_created",
		"arch",
		owner,
		ctx,
		updateTeamUserPermissions,
	)
}

// CreateApp creates a new app_name document
func (c *appRepository) CreateApp(appName string, logo string, description string, private bool, owner string, ctx context.Context) (interface{}, error) {
	document := bson.D{{Key: "app_name", Value: appName}}
	if logo != "" {
		document = append(document, bson.E{Key: "logo", Value: logo})
	}
	if description != "" {
		document = append(document, bson.E{Key: "description", Value: description})
	}
	if private == true {
		document = append(document, bson.E{Key: "private", Value: private})
	}

	updateTeamUserPermissions := func(teamUser model.TeamUser, result interface{}, teamUsername string) error {
		// Add the app ID to their allowed apps
		appID := result.(primitive.ObjectID).Hex()
		if !contains(teamUser.Permissions.Apps.Allowed, appID) {
			teamUser.Permissions.Apps.Allowed = append(teamUser.Permissions.Apps.Allowed, appID)
			update := bson.M{"$set": bson.M{"permissions": teamUser.Permissions}}
			_, err := c.client.Database(c.config.Database).Collection("team_users").UpdateOne(
				ctx,
				bson.M{"username": teamUsername},
				update,
			)
			return err
		}
		return nil
	}

	return c.createMetaDocument(
		document,
		"app_name_owner_sort_by_asc_created",
		"app",
		owner,
		ctx,
		updateTeamUserPermissions,
	)
}

func (c *appRepository) Upload(ctxQuery map[string]interface{}, appLink, extension string, owner string, ctx context.Context) (interface{}, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	var uploadResult interface{}
	var err error

	logrus.Debugf("Upload called with owner: %s, app_name: %s, version: %s",
		owner, ctxQuery["app_name"].(string), ctxQuery["version"].(string))

	// Check if the user is a team user
	teamUsersCollection := c.client.Database(c.config.Database).Collection("team_users")
	var teamUser model.TeamUser
	err = teamUsersCollection.FindOne(ctx, bson.M{"username": owner}).Decode(&teamUser)

	// If user is a team user, check permissions
	if err == nil {
		logrus.Debugf("User %s is a team user with owner: %s", owner, teamUser.Owner)

		// Check if the team user has permission to upload apps
		if !teamUser.Permissions.Apps.Upload {
			logrus.Debugf("Team user %s does not have permission to upload apps", owner)
			return nil, errors.New("you don't have permission to upload apps")
		}

		// Set owner to the team user's admin for database operations
		owner = teamUser.Owner
		logrus.Debugf("Using admin owner: %s for operations", owner)
	} else {
		logrus.Debugf("User %s is not a team user", owner)
	}

	// Find app_id from apps_meta by app_name and owner
	metaFilter := bson.D{
		{Key: "app_name", Value: ctxQuery["app_name"].(string)},
		{Key: "owner", Value: owner},
	}
	logrus.Debugf("Finding app meta with filter: %+v", metaFilter)
	err = metaCollection.FindOne(ctx, metaFilter).Decode(&appMeta)
	if err != nil {
		logrus.Debugf("Error finding app meta: %v", err)
		return nil, fmt.Errorf("app_name not found in apps_meta collection or you don't have permission to access it")
	}
	logrus.Debugf("Found app meta with ID: %s", appMeta.ID.Hex())

	// If user is a team user, check if they have access to this specific app
	if teamUser.ID != primitive.NilObjectID {
		appID := appMeta.ID.Hex()
		hasAccess := false
		logrus.Debugf("Checking if team user has access to app ID: %s", appID)
		logrus.Debugf("Team user allowed apps: %v", teamUser.Permissions.Apps.Allowed)

		for _, allowedAppID := range teamUser.Permissions.Apps.Allowed {
			if allowedAppID == appID {
				hasAccess = true
				break
			}
		}
		if !hasAccess {
			logrus.Debugf("Team user %s does not have access to app ID: %s", owner, appID)
			return nil, errors.New("you don't have access to this app")
		}
		logrus.Debugf("Team user has access to app ID: %s", appID)
	}

	// Fetch channel_id
	if channelName, ok := ctxQuery["channel"].(string); ok && channelName != "" {
		logrus.Debugf("Fetching channel meta for channel: %s", channelName)
		channelFilter := bson.D{
			{Key: "channel_name", Value: channelName},
			{Key: "owner", Value: owner},
		}
		err = metaCollection.FindOne(ctx, channelFilter).Decode(&channelMeta)
		if err != nil {
			logrus.Debugf("Error finding channel meta: %v", err)
			return nil, fmt.Errorf("channel not found in apps_meta collection or you don't have permission to access it")
		}
		logrus.Debugf("Found channel meta with ID: %s", channelMeta.ID.Hex())

		// If user is a team user, check if they have access to this specific channel
		if teamUser.ID != primitive.NilObjectID {
			channelID := channelMeta.ID.Hex()
			hasAccess := false
			logrus.Debugf("Checking if team user has access to channel ID: %s", channelID)
			logrus.Debugf("Team user allowed channels: %v", teamUser.Permissions.Channels.Allowed)

			for _, allowedChannelID := range teamUser.Permissions.Channels.Allowed {
				if allowedChannelID == channelID {
					hasAccess = true
					break
				}
			}
			if !hasAccess {
				logrus.Debugf("Team user %s does not have access to channel ID: %s", owner, channelID)
				return nil, errors.New("you don't have access to this channel")
			}
			logrus.Debugf("Team user has access to channel ID: %s", channelID)
		}
	}

	// Fetch platform_id
	if platformName, ok := ctxQuery["platform"].(string); ok && platformName != "" {
		logrus.Debugf("Fetching platform meta for platform: %s", platformName)
		platformFilter := bson.D{
			{Key: "platform_name", Value: platformName},
			{Key: "owner", Value: owner},
		}
		err = metaCollection.FindOne(ctx, platformFilter).Decode(&platformMeta)
		if err != nil {
			logrus.Debugf("Error finding platform meta: %v", err)
			return nil, fmt.Errorf("platform not found in apps_meta collection or you don't have permission to access it")
		}
		logrus.Debugf("Found platform meta with ID: %s", platformMeta.ID.Hex())

		// If user is a team user, check if they have access to this specific platform
		if teamUser.ID != primitive.NilObjectID {
			platformID := platformMeta.ID.Hex()
			hasAccess := false
			logrus.Debugf("Checking if team user has access to platform ID: %s", platformID)
			logrus.Debugf("Team user allowed platforms: %v", teamUser.Permissions.Platforms.Allowed)

			for _, allowedPlatformID := range teamUser.Permissions.Platforms.Allowed {
				if allowedPlatformID == platformID {
					hasAccess = true
					break
				}
			}
			if !hasAccess {
				logrus.Debugf("Team user %s does not have access to platform ID: %s", owner, platformID)
				return nil, errors.New("you don't have access to this platform")
			}
			logrus.Debugf("Team user has access to platform ID: %s", platformID)
		}
	}

	// Fetch arch_id
	if archName, ok := ctxQuery["arch"].(string); ok && archName != "" {
		logrus.Debugf("Fetching arch meta for arch: %s", archName)
		archFilter := bson.D{
			{Key: "arch_id", Value: archName},
			{Key: "owner", Value: owner},
		}
		err = metaCollection.FindOne(ctx, archFilter).Decode(&archMeta)
		if err != nil {
			logrus.Debugf("Error finding arch meta: %v", err)
			return nil, fmt.Errorf("arch not found in apps_meta collection or you don't have permission to access it")
		}
		logrus.Debugf("Found arch meta with ID: %s", archMeta.ID.Hex())

		// If user is a team user, check if they have access to this specific arch
		if teamUser.ID != primitive.NilObjectID {
			archID := archMeta.ID.Hex()
			hasAccess := false
			logrus.Debugf("Checking if team user has access to arch ID: %s", archID)
			logrus.Debugf("Team user allowed archs: %v", teamUser.Permissions.Archs.Allowed)

			for _, allowedArchID := range teamUser.Permissions.Archs.Allowed {
				if allowedArchID == archID {
					hasAccess = true
					break
				}
			}
			if !hasAccess {
				logrus.Debugf("Team user %s does not have access to arch ID: %s", owner, archID)
				return nil, errors.New("you don't have access to this architecture")
			}
			logrus.Debugf("Team user has access to arch ID: %s", archID)
		}
	}

	// Check if a document with the same "app_id" and "version" already exists
	logrus.Debugf("Checking if document exists with app_id: %s, version: %s, owner: %s",
		appMeta.ID.Hex(), ctxQuery["version"].(string), owner)

	existingDoc := collection.FindOne(ctx, bson.D{
		{Key: "app_id", Value: appMeta.ID},
		{Key: "version", Value: ctxQuery["version"].(string)},
		{Key: "owner", Value: owner},
	})

	if existingDoc.Err() == nil {
		logrus.Debugf("Document exists, updating it")
		var appData model.SpecificApp
		if err := existingDoc.Decode(&appData); err != nil {
			logrus.Debugf("Error decoding existing document: %v", err)
			return nil, err
		}

		for _, artifact := range appData.Artifacts {
			if artifact.Package == extension && artifact.Arch == archMeta.ID && artifact.Platform == platformMeta.ID {
				msg := "app with this name, version, platform, architecture and extension already exists"
				logrus.Debugf(msg)
				return msg, errors.New(msg)
			}
		}

		appData.Artifacts = append(appData.Artifacts, model.Artifact{
			Link:     appLink,
			Platform: platformMeta.ID,
			Arch:     archMeta.ID,
			Package:  extension,
		})
		logrus.Debugf("Adding new artifact to existing document")
		_, err = collection.UpdateOne(
			ctx,
			bson.D{{Key: "app_id", Value: appMeta.ID}, {Key: "version", Value: ctxQuery["version"].(string)}, {Key: "owner", Value: owner}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "artifacts", Value: appData.Artifacts}, {Key: "updated_at", Value: time.Now()}}}},
		)
		if err != nil {
			logrus.Debugf("Error updating document: %v", err)
			return nil, err
		}

		uploadResult = appData.ID
		logrus.Debugf("Document updated successfully, returning ID: %s", appData.ID.Hex())
	} else {
		// Handle the case when no document exists
		logrus.Debugf("Document does not exist, creating new one")
		publishParam, publishExists := ctxQuery["publish"]
		criticalParam, criticalExists := ctxQuery["critical"]

		publish := false
		if publishExists {
			publish = utils.GetBoolParam(publishParam)
			logrus.Debugf("Setting published to: %t", publish)
		}

		critical := false
		if criticalExists {
			critical = utils.GetBoolParam(criticalParam)
			logrus.Debugf("Setting critical to: %t", critical)
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
			{Key: "owner", Value: owner},
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
		logrus.Debugf("Document created successfully")
	}

	switch v := uploadResult.(type) {
	case *mongo.InsertOneResult:
		insertedID, ok := v.InsertedID.(primitive.ObjectID)
		if !ok {
			logrus.Debugf("Error extracting ID from InsertOneResult")
			return nil, errors.New("error extracting ID from InsertOneResult")
		}
		var appData model.SpecificApp
		err = collection.FindOne(ctx, bson.D{{Key: "_id", Value: insertedID}}).Decode(&appData)
		if err != nil {
			logrus.Debugf("Error finding inserted document: %v", err)
			return nil, err
		}
		logrus.Debugf("Uploaded result to mongo: %+v", appData)
		return appData, nil

	case primitive.ObjectID:
		var appData model.SpecificApp
		err = collection.FindOne(ctx, bson.D{{Key: "_id", Value: v}}).Decode(&appData)
		if err != nil {
			logrus.Debugf("Error finding updated document: %v", err)
			return nil, err
		}
		logrus.Debugf("Updated result in mongo: %+v", appData)
		return appData, nil

	default:
		logrus.Debugf("Unexpected return type: %T", uploadResult)
		return nil, errors.New("unexpected return type")
	}
}
