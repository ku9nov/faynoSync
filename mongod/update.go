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
)

func (c *appRepository) UpdateDocument(collectionName string, filter bson.D, update bson.D, uniqueKey, keyType string, ctx context.Context) (bool, error) {
	collection := c.client.Database(c.config.Database).Collection(collectionName)

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
func (c *appRepository) UpdateChannel(id primitive.ObjectID, channelName string, ctx context.Context) (interface{}, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "channel_name", Value: channelName}}}}
	return c.UpdateDocument("apps_meta", filter, update, "channel_name_sort_by_asc_updated", "channel", ctx)
}

// UpdatePlatform updates an existing platform document
func (c *appRepository) UpdatePlatform(id primitive.ObjectID, platformName string, ctx context.Context) (interface{}, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "platform_name", Value: platformName}}}}
	return c.UpdateDocument("apps_meta", filter, update, "platform_name_sort_by_asc_updated", "platform", ctx)
}

// UpdateArch updates an existing arch document
func (c *appRepository) UpdateArch(id primitive.ObjectID, archID string, ctx context.Context) (interface{}, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "arch_id", Value: archID}}}}
	return c.UpdateDocument("apps_meta", filter, update, "arch_id_sort_by_asc_updated", "arch", ctx)
}

// UpdateApp updates an existing app_name document
func (c *appRepository) UpdateApp(id primitive.ObjectID, appName string, logo string, description string, ctx context.Context) (interface{}, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	updateFields := bson.D{{Key: "app_name", Value: appName}}
	if logo != "" {
		updateFields = append(updateFields, bson.E{Key: "logo", Value: logo})
	}
	if description != "" {
		updateFields = append(updateFields, bson.E{Key: "description", Value: description})
	}
	update := bson.D{{Key: "$set", Value: updateFields}}
	return c.UpdateDocument("apps_meta", filter, update, "app_name_sort_by_asc_updated", "app", ctx)
}

func (c *appRepository) UpdateSpecificApp(objID primitive.ObjectID, ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (bool, error) {
	collection := c.client.Database(c.config.Database).Collection("apps")
	metaCollection := c.client.Database(c.config.Database).Collection("apps_meta")
	var err error

	// Find app_id from apps_meta by app_name
	err = c.getMeta(ctx, metaCollection, "app_name", ctxQuery["app_name"].(string), &appMeta)
	if err != nil {
		return false, err
	}

	// Fetch channel_id
	if channelName, ok := ctxQuery["channel"].(string); ok && channelName != "" {
		err = c.getMeta(ctx, metaCollection, "channel_name", channelName, &channelMeta)
		if err != nil {
			return false, err
		}
		logrus.Debugf("Found channelMeta: %v", channelMeta)
	}

	// Fetch platform_id
	if platformName, ok := ctxQuery["platform"].(string); ok && platformName != "" {
		err = c.getMeta(ctx, metaCollection, "platform_name", platformName, &platformMeta)
		if err != nil {
			return false, err
		}
		logrus.Debugf("Found platformMeta: %v", platformMeta)
	}

	// Fetch arch_id
	if archName, ok := ctxQuery["arch"].(string); ok && archName != "" {
		err = c.getMeta(ctx, metaCollection, "arch_id", archName, &archMeta)
		if err != nil {
			return false, err
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

		if channelMeta.ID != appData.ChannelID {
			return false, errors.New("updating the channel is not allowed")
		}

		updateFields := bson.D{{Key: "updated_at", Value: time.Now()}}

		if publishParam, publishExists := ctxQuery["publish"]; publishExists {
			publish := utils.GetBoolParam(publishParam)
			updateFields = append(updateFields, bson.E{Key: "published", Value: publish})
		}

		if criticalParam, criticalExists := ctxQuery["critical"]; criticalExists {
			critical := utils.GetBoolParam(criticalParam)
			updateFields = append(updateFields, bson.E{Key: "critical", Value: critical})
		}

		if appLink != "" && extension != "" {
			duplicateFound := false
			for _, artifact := range appData.Artifacts {
				if artifact.Link == appLink && artifact.Platform == platformMeta.ID && artifact.Arch == archMeta.ID && artifact.Package == extension {
					duplicateFound = true
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
