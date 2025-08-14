package mongod

import (
	"context"
	"errors"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func (c *appRepository) UpdateDocument(collectionName string, filter bson.D, update bson.D, uniqueKey, keyType string, owner string, ctx context.Context) (bool, error) {
	collection := c.client.Database(c.config.Database).Collection(collectionName)

	// Check if the document exists and belongs to the owner
	var existingDoc bson.M
	err := collection.FindOne(ctx, filter).Decode(&existingDoc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false, fmt.Errorf("%s not found", keyType)
		}
		return false, err
	}

	// Check if the user is a team user
	teamUsersCollection := c.client.Database(c.config.Database).Collection("team_users")
	var teamUser model.TeamUser
	err = teamUsersCollection.FindOne(ctx, bson.M{"username": owner}).Decode(&teamUser)

	// Get the document owner
	docOwner, ok := existingDoc["owner"].(string)
	if !ok {
		return false, fmt.Errorf("invalid owner field in document")
	}

	// If user is a team user, check if they have permission to update this resource
	if err == nil {
		// User is a team user, check if the document belongs to their admin
		if docOwner != teamUser.Owner {
			return false, fmt.Errorf("you don't have permission to update this %s", keyType)
		}

		// Check if the user has specific permissions for this resource type
		var hasPermission bool
		switch keyType {
		case "channel":
			hasPermission = teamUser.Permissions.Channels.Edit
			// Additional check for channels - verify if the channel is in allowed channels
			if hasPermission {
				// Get the channel ID from the document
				channelID, ok := existingDoc["_id"].(primitive.ObjectID)
				if !ok {
					return false, fmt.Errorf("invalid _id field in document")
				}

				// Check if the channel is in the allowed channels list
				channelAllowed := false
				for _, allowedChannelID := range teamUser.Permissions.Channels.Allowed {
					if allowedChannelID == channelID.Hex() {
						channelAllowed = true
						break
					}
				}

				if !channelAllowed {
					return false, fmt.Errorf("you don't have permission to update this channel as it's not in your allowed channels list")
				}
			}
		case "platform":
			hasPermission = teamUser.Permissions.Platforms.Edit
			// Additional check for platforms - verify if the platform is in allowed platforms
			if hasPermission {
				// Get the platform ID from the document
				platformID, ok := existingDoc["_id"].(primitive.ObjectID)
				if !ok {
					return false, fmt.Errorf("invalid _id field in document")
				}

				// Check if the platform is in the allowed platforms list
				platformAllowed := false
				for _, allowedPlatformID := range teamUser.Permissions.Platforms.Allowed {
					if allowedPlatformID == platformID.Hex() {
						platformAllowed = true
						break
					}
				}

				if !platformAllowed {
					return false, fmt.Errorf("you don't have permission to update this platform as it's not in your allowed platforms list")
				}
			}
		case "arch":
			hasPermission = teamUser.Permissions.Archs.Edit
			// Additional check for archs - verify if the arch is in allowed archs
			if hasPermission {
				// Get the arch ID from the document
				archID, ok := existingDoc["_id"].(primitive.ObjectID)
				if !ok {
					return false, fmt.Errorf("invalid _id field in document")
				}

				// Check if the arch is in the allowed archs list
				archAllowed := false
				for _, allowedArchID := range teamUser.Permissions.Archs.Allowed {
					if allowedArchID == archID.Hex() {
						archAllowed = true
						break
					}
				}

				if !archAllowed {
					return false, fmt.Errorf("you don't have permission to update this arch as it's not in your allowed archs list")
				}
			}
		case "app":
			hasPermission = teamUser.Permissions.Apps.Edit
			// Additional check for apps - verify if the app is in allowed apps
			if hasPermission {
				// Get the app ID from the document
				appID, ok := existingDoc["_id"].(primitive.ObjectID)
				if !ok {
					return false, fmt.Errorf("invalid _id field in document")
				}

				// Check if the app is in the allowed apps list
				appAllowed := false
				for _, allowedAppID := range teamUser.Permissions.Apps.Allowed {
					if allowedAppID == appID.Hex() {
						appAllowed = true
						break
					}
				}

				if !appAllowed {
					return false, fmt.Errorf("you don't have permission to update this app as it's not in your allowed apps list")
				}
			}
		}

		if !hasPermission {
			return false, fmt.Errorf("you don't have permission to update this %s", keyType)
		}
	} else {
		// User is not a team user, check if they own the document
		if docOwner != owner {
			return false, fmt.Errorf("you don't have permission to update this %s", keyType)
		}
	}

	// Set the updated_at field to the current time
	update = append(update, bson.E{Key: "$set", Value: bson.D{{Key: "updated_at", Value: time.Now()}}})
	logrus.Debugln("Update document: ", update)
	updateResult, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		logrus.Errorf("Error updating document: %v", err)
		return false, err
	}

	if updateResult.MatchedCount == 0 {
		return false, fmt.Errorf("%s not found", keyType)
	}

	return true, nil
}

// UpdateChannel updates an existing channel document
func (c *appRepository) UpdateChannel(id primitive.ObjectID, channelName string, owner string, ctx context.Context) (interface{}, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "channel_name", Value: channelName}}}}
	return c.UpdateDocument("apps_meta", filter, update, "channel_name_sort_by_asc_updated", "channel", owner, ctx)
}

// UpdatePlatform updates an existing platform document
func (c *appRepository) UpdatePlatform(id primitive.ObjectID, platformName string, updaters []model.Updater, owner string, ctx context.Context) (interface{}, error) {
	// Convert updaters to BSON format
	updatersBSON := make([]bson.M, len(updaters))
	for i, updater := range updaters {
		updatersBSON[i] = bson.M{
			"type":    updater.Type,
			"default": updater.Default,
		}
	}

	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{
		{Key: "platform_name", Value: platformName},
		{Key: "updaters", Value: updatersBSON},
	}}}
	return c.UpdateDocument("apps_meta", filter, update, "platform_name_sort_by_asc_updated", "platform", owner, ctx)
}

// UpdateArch updates an existing arch document
func (c *appRepository) UpdateArch(id primitive.ObjectID, archID string, owner string, ctx context.Context) (interface{}, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "arch_id", Value: archID}}}}
	return c.UpdateDocument("apps_meta", filter, update, "arch_id_sort_by_asc_updated", "arch", owner, ctx)
}

// UpdateApp updates an existing app_name document
func (c *appRepository) UpdateApp(id primitive.ObjectID, appName string, logo string, description string, owner string, ctx context.Context) (interface{}, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	updateFields := bson.D{{Key: "app_name", Value: appName}}
	if logo != "" {
		updateFields = append(updateFields, bson.E{Key: "logo", Value: logo})
	}
	if description != "" {
		updateFields = append(updateFields, bson.E{Key: "description", Value: description})
	}
	update := bson.D{{Key: "$set", Value: updateFields}}
	return c.UpdateDocument("apps_meta", filter, update, "app_name_sort_by_asc_updated", "app", owner, ctx)
}

func (c *appRepository) UpdateSpecificApp(objID primitive.ObjectID, owner string, ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (bool, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	var err error

	logrus.Debugf("UpdateSpecificApp called with owner: %s, app_name: %s, version: %s",
		owner, ctxQuery["app_name"].(string), ctxQuery["version"].(string))

	// Check if the user is a team user
	teamUsersCollection := c.client.Database(c.config.Database).Collection("team_users")
	var teamUser model.TeamUser
	err = teamUsersCollection.FindOne(ctx, bson.M{"username": owner}).Decode(&teamUser)

	// If user is a team user, check permissions
	if err == nil {
		logrus.Debugf("User %s, has id: %s, is a team user with owner: %s", owner, teamUser.ID, teamUser.Owner)

		// Check if the team user has permission to edit apps
		if !teamUser.Permissions.Apps.Edit {
			logrus.Debugf("Team user %s does not have permission to edit apps", teamUser.Username)
			return false, errors.New("you don't have permission to edit apps")
		}

		// Set owner to the team user's admin for database operations
		owner = teamUser.Owner
		logrus.Debugf("Using admin owner: %s for operations", owner)
	} else {
		logrus.Debugf("User %s is not a team user", owner)
	}

	// Find app_id from apps_meta by app_name
	err = c.getMeta(ctx, metaCollection, "app_name", ctxQuery["app_name"].(string), &appMeta, owner)
	if err != nil {
		logrus.Debugf("Error finding app meta: %v", err)
		return false, err
	}
	logrus.Debugf("Found app meta with ID: %s", appMeta.ID.Hex())
	logrus.Debugf("teamUserID: %+v, and primitive.NilObjectID: %+v", teamUser.ID, primitive.NilObjectID)

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
			logrus.Debugf("Team user %s does not have access to app ID: %s", teamUser.Username, appID)
			return false, errors.New("you don't have access to this app")
		}
		logrus.Debugf("Team user has access to app ID: %s", appID)
	}

	// Fetch channel_id
	if channelName, ok := ctxQuery["channel"].(string); ok && channelName != "" {
		logrus.Debugf("Fetching channel meta for channel: %s", channelName)
		err = c.getMeta(ctx, metaCollection, "channel_name", channelName, &channelMeta, owner)
		if err != nil {
			logrus.Debugf("Error finding channel meta: %v", err)
			return false, err
		}
		logrus.Debugf("Found channel meta with ID: %s", channelMeta.ID.Hex())

		// If user is a team user, check if they have access to this specific channel
		if teamUser.ID != primitive.NilObjectID {
			channelID := channelMeta.ID.Hex()
			if err := checkEntityAccess(teamUser, channelID, teamUser.Permissions.Channels.Allowed, "channel"); err != nil {
				return false, err
			}
		}
	}

	// Fetch platform_id
	if platformName, ok := ctxQuery["platform"].(string); ok && platformName != "" {
		logrus.Debugf("Fetching platform meta for platform: %s", platformName)
		err = c.getMeta(ctx, metaCollection, "platform_name", platformName, &platformMeta, owner)
		if err != nil {
			logrus.Debugf("Error finding platform meta: %v", err)
			return false, err
		}
		logrus.Debugf("Found platform meta with ID: %s", platformMeta.ID.Hex())

		// If user is a team user, check if they have access to this specific platform
		if teamUser.ID != primitive.NilObjectID {
			platformID := platformMeta.ID.Hex()
			if err := checkEntityAccess(teamUser, platformID, teamUser.Permissions.Platforms.Allowed, "platform"); err != nil {
				return false, err
			}
		}
	}

	// Fetch arch_id
	if archName, ok := ctxQuery["arch"].(string); ok && archName != "" {
		logrus.Debugf("Fetching arch meta for arch: %s", archName)
		err = c.getMeta(ctx, metaCollection, "arch_id", archName, &archMeta, owner)
		if err != nil {
			logrus.Debugf("Error finding arch meta: %v", err)
			return false, err
		}
		logrus.Debugf("Found arch meta with ID: %s", archMeta.ID.Hex())

		// If user is a team user, check if they have access to this specific arch
		if teamUser.ID != primitive.NilObjectID {
			archID := archMeta.ID.Hex()
			if err := checkEntityAccess(teamUser, archID, teamUser.Permissions.Archs.Allowed, "architecture"); err != nil {
				return false, err
			}
		}
	}

	// Check if a document with the same "app_id" and "version" already exists
	logrus.Debugf("Checking if document exists with app_id: %s, version: %s, owner: %s",
		appMeta.ID.Hex(), ctxQuery["version"].(string), owner)

	existingDoc := collection.FindOne(ctx, bson.D{
		{Key: "_id", Value: objID},
		{Key: "app_id", Value: appMeta.ID},
		{Key: "version", Value: ctxQuery["version"].(string)},
		{Key: "owner", Value: owner},
	})

	if existingDoc.Err() == nil {
		logrus.Debugf("Document exists, updating it")
		var appData model.SpecificApp
		if err := existingDoc.Decode(&appData); err != nil {
			logrus.Debugf("Error decoding existing document: %v", err)
			return false, err
		}

		if channelMeta.ID != appData.ChannelID {
			logrus.Debugf("Channel ID mismatch: %s != %s", channelMeta.ID.Hex(), appData.ChannelID.Hex())
			return false, errors.New("updating the channel is not allowed")
		}

		updateFields := bson.D{{Key: "updated_at", Value: time.Now()}}

		if publishParam, publishExists := ctxQuery["publish"]; publishExists {
			publish := utils.GetBoolParam(publishParam)
			updateFields = append(updateFields, bson.E{Key: "published", Value: publish})
			logrus.Debugf("Setting published to: %t", publish)
		}

		if criticalParam, criticalExists := ctxQuery["critical"]; criticalExists {
			critical := utils.GetBoolParam(criticalParam)
			updateFields = append(updateFields, bson.E{Key: "critical", Value: critical})
			logrus.Debugf("Setting critical to: %t", critical)
		}

		if intermediateParam, intermediateExists := ctxQuery["intermediate"]; intermediateExists {
			requiredIntermediate := utils.GetBoolParam(intermediateParam)
			updateFields = append(updateFields, bson.E{Key: "required_intermediate", Value: requiredIntermediate})
			logrus.Debugf("Setting required_intermediate to: %t", requiredIntermediate)
		}

		if appLink != "" {
			duplicateFound := false
			for _, artifact := range appData.Artifacts {
				if artifact.Link == appLink && artifact.Platform == platformMeta.ID && artifact.Arch == archMeta.ID && artifact.Package == extension {
					duplicateFound = true
					logrus.Debugf("Duplicate artifact found, skipping")
					break
				}
			}

			if !duplicateFound {
				newArtifact := model.Artifact{
					Link:     appLink,
					Platform: platformMeta.ID,
					Arch:     archMeta.ID,
					Package:  extension,
				}
				appData.Artifacts = append(appData.Artifacts, newArtifact)
				updateFields = append(updateFields, bson.E{Key: "artifacts", Value: appData.Artifacts})
				logrus.Debugf("Added new artifact: %+v", newArtifact)
			}
		}

		// Add or update changelog
		if changelog, exists := ctxQuery["changelog"].(string); exists && changelog != "" {
			changelogUpdated := false
			for i, log := range appData.Changelog {
				if log.Version == ctxQuery["version"].(string) {
					appData.Changelog[i].Changes = changelog
					appData.Changelog[i].Date = time.Now().Format("2006-01-02")
					changelogUpdated = true
					logrus.Debugf("Updated existing changelog for version: %s", log.Version)
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
				logrus.Debugf("Added new changelog for version: %s", newChangelog.Version)
			}
			updateFields = append(updateFields, bson.E{Key: "changelog", Value: appData.Changelog})
		}

		logrus.Debugf("Updating document with fields: %+v", updateFields)
		_, err = collection.UpdateOne(
			ctx,
			bson.D{{Key: "_id", Value: objID}},
			bson.D{{Key: "$set", Value: updateFields}},
		)
		if err != nil {
			logrus.Debugf("Error updating document: %v", err)
			return false, err
		}

		logrus.Debugf("Document updated successfully")
		return true, nil
	} else {
		logrus.Debugf("Document does not exist with app_id: %s, version: %s, owner: %s",
			appMeta.ID.Hex(), ctxQuery["version"].(string), owner)
		return false, errors.New("app with this parameters doesn't exist")
	}
}
