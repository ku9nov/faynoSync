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
	"go.mongodb.org/mongo-driver/mongo/options"
)

// AccessDeniedError marks a refusal caused by the requester's permissions, so handlers can answer 403 instead of 500.
type AccessDeniedError struct {
	Message string
}

func (e *AccessDeniedError) Error() string {
	return e.Message
}

func accessDenied(format string, args ...interface{}) error {
	return &AccessDeniedError{Message: fmt.Sprintf(format, args...)}
}

func (c *appRepository) resolveOwnerAndTeamUser(ctx context.Context, requester string) (string, *model.TeamUser, error) {
	teamUsersCollection := c.client.Database(c.config.Database).Collection("team_users")
	var teamUser model.TeamUser
	err := teamUsersCollection.FindOne(ctx, bson.M{"username": requester}).Decode(&teamUser)
	if err == nil {
		return teamUser.Owner, &teamUser, nil
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return requester, nil, nil
	}
	return "", nil, err
}

func (c *appRepository) GetAppByID(id primitive.ObjectID, requester string, ctx context.Context) (*model.App, error) {
	owner, teamUser, err := c.resolveOwnerAndTeamUser(ctx, requester)
	if err != nil {
		return nil, err
	}
	if teamUser != nil {
		if !teamUser.Permissions.Apps.Edit {
			return nil, accessDenied("you don't have permission to edit apps")
		}

		appAllowed := false
		for _, allowedAppID := range teamUser.Permissions.Apps.Allowed {
			if allowedAppID == id.Hex() {
				appAllowed = true
				break
			}
		}
		if !appAllowed {
			return nil, accessDenied("you don't have access to this app")
		}
	}

	collection := c.client.Database(c.config.Database).Collection("apps_meta")
	filter := bson.M{
		"_id":      id,
		"owner":    owner,
		"app_name": bson.M{"$exists": true},
	}

	var app model.App
	if err := collection.FindOne(ctx, filter).Decode(&app); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, utils.ErrAppNotFound
		}
		return nil, err
	}

	return &app, nil
}

func (c *appRepository) CreateReportKey(appID primitive.ObjectID, requester string, ctx context.Context) (string, error) {
	app, err := c.GetAppByID(appID, requester, ctx)
	if err != nil {
		return "", err
	}
	if !app.Reports {
		return "", errors.New("reports are disabled for this app")
	}

	keyValue, err := utils.GenerateReportKey()
	if err != nil {
		return "", err
	}

	now := primitive.NewDateTimeFromTime(time.Now())
	reportKeyDoc := model.ReportKey{
		ID:        primitive.NewObjectID(),
		AppID:     appID,
		Owner:     app.Owner,
		KeyValue:  keyValue,
		CreatedAt: now,
		UpdatedAt: now,
	}

	collection := c.client.Database(c.config.Database).Collection("report_keys")
	if _, err := collection.InsertOne(ctx, reportKeyDoc); err != nil {
		if mongoErr, ok := err.(mongo.WriteException); ok {
			for _, writeErr := range mongoErr.WriteErrors {
				if writeErr.Code == 11000 {
					return "", errors.New("report key for this app already exists")
				}
			}
		}
		return "", err
	}

	return keyValue, nil
}

func (c *appRepository) DeleteReportKey(appID primitive.ObjectID, requester string, ctx context.Context) (bool, error) {
	app, err := c.GetAppByID(appID, requester, ctx)
	if err != nil {
		return false, err
	}

	collection := c.client.Database(c.config.Database).Collection("report_keys")
	result, err := collection.DeleteOne(ctx, bson.M{
		"app_id": appID,
		"owner":  app.Owner,
	})
	if err != nil {
		return false, err
	}

	return result.DeletedCount > 0, nil
}

// editableAppsFilter scopes per-app key collections to apps the requester may edit; ok is false when that set is empty.
func (c *appRepository) editableAppsFilter(ctx context.Context, requester string) (bson.M, bool, error) {
	owner, teamUser, err := c.resolveOwnerAndTeamUser(ctx, requester)
	if err != nil {
		return nil, false, err
	}

	filter := bson.M{"owner": owner}
	if teamUser != nil {
		if !teamUser.Permissions.Apps.Edit {
			return nil, false, accessDenied("you don't have permission to edit apps")
		}

		allowedObjectIDs := make([]primitive.ObjectID, 0, len(teamUser.Permissions.Apps.Allowed))
		for _, appID := range teamUser.Permissions.Apps.Allowed {
			objectID, err := primitive.ObjectIDFromHex(appID)
			if err != nil {
				continue
			}
			allowedObjectIDs = append(allowedObjectIDs, objectID)
		}
		if len(allowedObjectIDs) == 0 {
			return nil, false, nil
		}

		filter["app_id"] = bson.M{"$in": allowedObjectIDs}
	}

	return filter, true, nil
}

func (c *appRepository) ListReportKeys(requester string, ctx context.Context) ([]*model.ReportKeyListItem, error) {
	filter, ok, err := c.editableAppsFilter(ctx, requester)
	if err != nil {
		return nil, err
	}
	if !ok {
		return []*model.ReportKeyListItem{}, nil
	}

	collection := c.client.Database(c.config.Database).Collection("report_keys")
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: filter}},
		{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "app_id",
			"foreignField": "_id",
			"as":           "app_meta",
		}}},
		{{Key: "$unwind", Value: "$app_meta"}},
		{{Key: "$project", Value: bson.M{
			"_id":        1,
			"app_id":     1,
			"app_name":   "$app_meta.app_name",
			"key_value":  1,
			"updated_at": 1,
		}}},
		{{Key: "$sort", Value: bson.D{{Key: "updated_at", Value: -1}}}},
	}

	cursor, err := collection.Aggregate(ctx, pipeline, options.Aggregate())
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var reportKeys []*model.ReportKeyListItem
	if err := cursor.All(ctx, &reportKeys); err != nil {
		return nil, err
	}

	return reportKeys, nil
}

func (c *appRepository) RegenerateReportKey(appID primitive.ObjectID, requester string, ctx context.Context) (string, error) {
	app, err := c.GetAppByID(appID, requester, ctx)
	if err != nil {
		return "", err
	}
	if !app.Reports {
		return "", errors.New("reports are disabled for this app")
	}

	newKeyValue, err := utils.GenerateReportKey()
	if err != nil {
		return "", err
	}

	collection := c.client.Database(c.config.Database).Collection("report_keys")
	result, err := collection.UpdateOne(ctx, bson.M{
		"app_id": appID,
		"owner":  app.Owner,
	}, bson.M{
		"$set": bson.M{
			"key_value":  newKeyValue,
			"updated_at": primitive.NewDateTimeFromTime(time.Now()),
		},
	})
	if err != nil {
		return "", err
	}
	if result.MatchedCount == 0 {
		return "", fmt.Errorf("report key for app %s not found", appID.Hex())
	}

	return newKeyValue, nil
}

// deleteReportKeys drops the key of a deleted app: report keys are scoped to an app only.
func (c *appRepository) deleteReportKeys(ctx context.Context, keyType string, id primitive.ObjectID) error {
	if keyType != "app" {
		return nil
	}

	result, err := c.client.Database(c.config.Database).Collection("report_keys").DeleteMany(ctx, bson.M{"app_id": id})
	if err != nil {
		return err
	}
	logrus.Debugf("Deleted %d report keys of app %s", result.DeletedCount, id.Hex())
	return nil
}
