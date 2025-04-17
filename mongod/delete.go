package mongod

import (
	"context"
	"faynoSync/server/model"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func (c *appRepository) DeleteSpecificVersionOfApp(id primitive.ObjectID, owner string, ctx context.Context) ([]string, int64, string, error) {

	collection := c.client.Database(c.config.Database).Collection("apps")

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Retrieve the document before deletion
	var app *model.SpecificApp
	err := collection.FindOne(ctx, filter).Decode(&app)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, 0, "", fmt.Errorf("no app found with ID %s", id)
		}
		return nil, 0, "", fmt.Errorf("error retrieving app with ID %s: %s", id, err.Error())
	}
	// Check ownership
	var docMap bson.M
	err = collection.FindOne(ctx, filter).Decode(&docMap)
	if err != nil {
		return nil, 0, "", err
	}

	if docOwner, ok := docMap["owner"].(string); !ok || docOwner != owner {
		return nil, 0, "", fmt.Errorf("you don't have permission to delete this item")
	}

	appName, err := c.FetchAppByID(app.ID, ctx)

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		logrus.Fatal(err)

		return nil, 0, "", err
	}

	var links []string
	for _, artifact := range app.Artifacts {
		link := string(artifact.Link)
		links = append(links, link)
	}

	return links, deleteResult.DeletedCount, appName[0].AppName, nil
}

func (c *appRepository) DeleteSpecificArtifactOfApp(id primitive.ObjectID, ctxQuery map[string]interface{}, ctx context.Context, owner string) ([]string, bool, error) {
	var err error
	var links []string
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")

	err = c.getMeta(ctx, metaCollection, "app_name", ctxQuery["app_name"].(string), &appMeta, owner)
	if err != nil {
		logrus.Errorln("Error getting app_id in DeleteSpecificArtifactOfApp:", err)
	}
	existingDoc := collection.FindOne(ctx, bson.D{
		{Key: "_id", Value: id},
		{Key: "app_id", Value: appMeta.ID},
		{Key: "version", Value: ctxQuery["version"].(string)},
	})

	if existingDoc.Err() == nil {

		var appData model.SpecificApp
		if err := existingDoc.Decode(&appData); err != nil {
			logrus.Errorln("Error decoding appData in DeleteSpecificArtifactOfApp:", err)
		}

		updateFields := bson.D{{Key: "updated_at", Value: time.Now()}}
		var deletedLinks []string

		if artifactsToDelete, ok := ctxQuery["artifacts_to_delete"].([]string); ok {
			for _, index := range artifactsToDelete {
				if idx, err := strconv.Atoi(index); err == nil && idx < len(appData.Artifacts) {
					deletedLinks = append(deletedLinks, string(appData.Artifacts[idx].Link))
					appData.Artifacts = append(appData.Artifacts[:idx], appData.Artifacts[idx+1:]...)
				} else {
					logrus.Errorf("Invalid index in DeleteSpecificArtifactOfApp: %s\n", index)
					return nil, false, err
				}
			}
			updateFields = append(updateFields, bson.E{Key: "artifacts", Value: appData.Artifacts})
		}

		links = append(links, deletedLinks...)

		_, err = collection.UpdateOne(
			ctx,
			bson.D{{Key: "_id", Value: id}},
			bson.D{{Key: "$set", Value: updateFields}},
		)
		if err != nil {
			logrus.Fatal(err)

			return nil, false, err
		}

	}
	return links, true, nil
}

type Document interface{}

func (c *appRepository) DeleteDocument(collectionName string, id primitive.ObjectID, docType Document, owner string, ctx context.Context) (int64, error) {
	collection := c.client.Database(c.config.Database).Collection(collectionName)

	filter := bson.D{primitive.E{Key: "_id", Value: id}}

	// Check if the document exists and belongs to the owner
	var existingDoc bson.M
	err := collection.FindOne(ctx, filter).Decode(&existingDoc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, fmt.Errorf("no document found with ID %s", id)
		}
		return 0, fmt.Errorf("error retrieving document with ID %s: %s", id, err.Error())
	}

	// Get the document owner
	docOwner, ok := existingDoc["owner"].(string)
	if !ok {
		return 0, fmt.Errorf("invalid owner field in document")
	}

	// Check if the user is a team user
	teamUsersCollection := c.client.Database(c.config.Database).Collection("team_users")
	var teamUser model.TeamUser
	err = teamUsersCollection.FindOne(ctx, bson.M{"username": owner}).Decode(&teamUser)

	// Determine the keyType based on the document type
	var keyType string
	switch docType.(type) {
	case *model.App:
		keyType = "app"
	case *model.Channel:
		keyType = "channel"
	case *model.Platform:
		keyType = "platform"
	case *model.Arch:
		keyType = "arch"
	default:
		return 0, fmt.Errorf("unsupported document type")
	}

	// If user is a team user, check if they have permission to delete this resource
	if err == nil {
		// User is a team user, check if the document belongs to their admin
		if docOwner != teamUser.Owner {
			return 0, fmt.Errorf("you don't have permission to delete this %s", keyType)
		}

		// Check if the user has specific permissions for this resource type
		var hasPermission bool
		switch keyType {
		case "channel":
			hasPermission = teamUser.Permissions.Channels.Delete
			// Additional check for channels - verify if the channel is in allowed channels
			if hasPermission {
				// Get the channel ID from the document
				channelID := id.Hex()

				// Check if the channel is in the allowed channels list
				channelAllowed := false
				for _, allowedChannelID := range teamUser.Permissions.Channels.Allowed {
					if allowedChannelID == channelID {
						channelAllowed = true
						break
					}
				}

				if !channelAllowed {
					return 0, fmt.Errorf("you don't have permission to delete this channel as it's not in your allowed channels list")
				}
			}
		case "platform":
			hasPermission = teamUser.Permissions.Platforms.Delete
			// Additional check for platforms - verify if the platform is in allowed platforms
			if hasPermission {
				// Get the platform ID from the document
				platformID := id.Hex()

				// Check if the platform is in the allowed platforms list
				platformAllowed := false
				for _, allowedPlatformID := range teamUser.Permissions.Platforms.Allowed {
					if allowedPlatformID == platformID {
						platformAllowed = true
						break
					}
				}

				if !platformAllowed {
					return 0, fmt.Errorf("you don't have permission to delete this platform as it's not in your allowed platforms list")
				}
			}
		case "arch":
			hasPermission = teamUser.Permissions.Archs.Delete
			// Additional check for archs - verify if the arch is in allowed archs
			if hasPermission {
				// Get the arch ID from the document
				archID := id.Hex()

				// Check if the arch is in the allowed archs list
				archAllowed := false
				for _, allowedArchID := range teamUser.Permissions.Archs.Allowed {
					if allowedArchID == archID {
						archAllowed = true
						break
					}
				}

				if !archAllowed {
					return 0, fmt.Errorf("you don't have permission to delete this arch as it's not in your allowed archs list")
				}
			}
		case "app":
			hasPermission = teamUser.Permissions.Apps.Delete
			// Additional check for apps - verify if the app is in allowed apps
			if hasPermission {
				// Get the app ID from the document
				appID := id.Hex()

				// Check if the app is in the allowed apps list
				appAllowed := false
				for _, allowedAppID := range teamUser.Permissions.Apps.Allowed {
					if allowedAppID == appID {
						appAllowed = true
						break
					}
				}

				if !appAllowed {
					return 0, fmt.Errorf("you don't have permission to delete this app as it's not in your allowed apps list")
				}
			}
		}

		if !hasPermission {
			return 0, fmt.Errorf("you don't have permission to delete this %s", keyType)
		}
	} else {
		// User is not a team user, check if they own the document
		if docOwner != owner {
			return 0, fmt.Errorf("you don't have permission to delete this %s", keyType)
		}
	}

	// Retrieve the document before deletion for further processing
	err = collection.FindOne(ctx, filter).Decode(docType)
	if err != nil {
		return 0, fmt.Errorf("error retrieving document with ID %s: %s", id, err.Error())
	}

	var relatedFilter bson.D

	switch docType.(type) {
	case *model.App:
		relatedFilter = bson.D{primitive.E{Key: "app_id", Value: id}}
	case *model.Channel:
		relatedFilter = bson.D{primitive.E{Key: "channel_id", Value: id}}
	case *model.Platform:
		relatedFilter = bson.D{
			primitive.E{Key: "artifacts", Value: bson.D{
				primitive.E{Key: "$elemMatch", Value: bson.D{primitive.E{Key: "platform", Value: id}}},
			}},
		}
	case *model.Arch:
		relatedFilter = bson.D{
			primitive.E{Key: "artifacts", Value: bson.D{
				primitive.E{Key: "$elemMatch", Value: bson.D{primitive.E{Key: "arch", Value: id}}},
			}},
		}
	default:
		return 0, fmt.Errorf("unsupported document type")
	}

	checkRelatedApps := c.client.Database(c.config.Database).Collection("apps")

	var foundDoc bson.M

	err = checkRelatedApps.FindOne(ctx, relatedFilter).Decode(&foundDoc)
	if err == nil {
		return 0, fmt.Errorf("you can't delete this item because it is related to other items")
	}

	deleteResult, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		log.Fatalf("error deleting document with ID %s: %s", id, err.Error())
		return 0, err
	}

	// After successful deletion, remove the resource ID from all team users' allowed lists
	if deleteResult.DeletedCount > 0 {
		// Get the resource ID as a string
		resourceID := id.Hex()

		// Find all team users
		cursor, err := teamUsersCollection.Find(ctx, bson.M{})
		if err != nil {
			logrus.Errorf("Error finding team users: %v", err)
			return deleteResult.DeletedCount, nil // Continue with deletion success
		}
		defer cursor.Close(ctx)

		// Update each team user's permissions
		for cursor.Next(ctx) {
			var teamUser model.TeamUser
			if err := cursor.Decode(&teamUser); err != nil {
				logrus.Errorf("Error decoding team user: %v", err)
				continue
			}

			// Check if the team user has this resource in their allowed list
			var updated bool
			var updatedPermissions model.Permissions = teamUser.Permissions

			switch keyType {
			case "channel":
				// Remove the channel ID from the allowed channels list
				for i, allowedID := range teamUser.Permissions.Channels.Allowed {
					if allowedID == resourceID {
						// Remove the ID from the slice
						updatedPermissions.Channels.Allowed = append(
							teamUser.Permissions.Channels.Allowed[:i],
							teamUser.Permissions.Channels.Allowed[i+1:]...,
						)
						updated = true
						break
					}
				}
			case "platform":
				// Remove the platform ID from the allowed platforms list
				for i, allowedID := range teamUser.Permissions.Platforms.Allowed {
					if allowedID == resourceID {
						// Remove the ID from the slice
						updatedPermissions.Platforms.Allowed = append(
							teamUser.Permissions.Platforms.Allowed[:i],
							teamUser.Permissions.Platforms.Allowed[i+1:]...,
						)
						updated = true
						break
					}
				}
			case "arch":
				// Remove the arch ID from the allowed archs list
				for i, allowedID := range teamUser.Permissions.Archs.Allowed {
					if allowedID == resourceID {
						// Remove the ID from the slice
						updatedPermissions.Archs.Allowed = append(
							teamUser.Permissions.Archs.Allowed[:i],
							teamUser.Permissions.Archs.Allowed[i+1:]...,
						)
						updated = true
						break
					}
				}
			case "app":
				// Remove the app ID from the allowed apps list
				for i, allowedID := range teamUser.Permissions.Apps.Allowed {
					if allowedID == resourceID {
						// Remove the ID from the slice
						updatedPermissions.Apps.Allowed = append(
							teamUser.Permissions.Apps.Allowed[:i],
							teamUser.Permissions.Apps.Allowed[i+1:]...,
						)
						updated = true
						break
					}
				}
			}

			// If the permissions were updated, update the team user in the database
			if updated {
				update := bson.M{"$set": bson.M{"permissions": updatedPermissions}}
				_, err := teamUsersCollection.UpdateOne(
					ctx,
					bson.M{"_id": teamUser.ID},
					update,
				)
				if err != nil {
					logrus.Errorf("Error updating team user permissions: %v", err)
				}
			}
		}
	}

	return deleteResult.DeletedCount, nil
}

func (c *appRepository) DeleteChannel(id primitive.ObjectID, owner string, ctx context.Context) (int64, error) {
	var channel model.Channel
	return c.DeleteDocument("apps_meta", id, &channel, owner, ctx)
}

func (c *appRepository) DeletePlatform(id primitive.ObjectID, owner string, ctx context.Context) (int64, error) {
	var platform model.Platform
	return c.DeleteDocument("apps_meta", id, &platform, owner, ctx)
}

func (c *appRepository) DeleteArch(id primitive.ObjectID, owner string, ctx context.Context) (int64, error) {
	var arch model.Arch
	return c.DeleteDocument("apps_meta", id, &arch, owner, ctx)
}

func (c *appRepository) DeleteApp(id primitive.ObjectID, owner string, ctx context.Context) (int64, error) {
	var app model.App
	return c.DeleteDocument("apps_meta", id, &app, owner, ctx)
}
