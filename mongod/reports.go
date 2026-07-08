package mongod

import (
	"context"
	"errors"
	"faynoSync/server/model"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var ErrReportKeyNotFound = errors.New("report key not found")

func (c *appRepository) GetReportContextByKey(ctx context.Context, keyValue string) (*model.ReportContext, error) {
	collection := c.client.Database(c.config.Database).Collection("report_keys")
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"key_value": keyValue}}},
		{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "app_id",
			"foreignField": "_id",
			"as":           "app_meta",
		}}},
		{{Key: "$unwind", Value: "$app_meta"}},
		{{Key: "$project", Value: bson.M{
			"app_id":   1,
			"owner":    1,
			"app_name": "$app_meta.app_name",
			"reports":  "$app_meta.reports",
		}}},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if !cursor.Next(ctx) {
		if err := cursor.Err(); err != nil {
			return nil, err
		}
		return nil, ErrReportKeyNotFound
	}

	var reportContext model.ReportContext
	if err := cursor.Decode(&reportContext); err != nil {
		return nil, err
	}

	return &reportContext, nil
}

func (c *appRepository) IncrementReportGroup(ctx context.Context, appID primitive.ObjectID, owner, hash string, app model.ReportApplication, system model.ReportSystem, event model.ReportEvent, now time.Time) error {
	dt := primitive.NewDateTimeFromTime(now)
	collection := c.client.Database(c.config.Database).Collection("report_groups")

	update := bson.M{
		"$inc": bson.M{"stats.count": 1},
		"$set": bson.M{
			"stats.lastSeen": dt,
			"updatedAt":      dt,
		},
		"$setOnInsert": bson.M{
			"groupHash":             hash,
			"app_id":                appID,
			"owner":                 owner,
			"application":           app,
			"system":                system,
			"event":                 event,
			"status":                model.ReportGroupStatusOpen,
			"stats.firstSeen":       dt,
			"stats.detailsStored":   0,
			"stats.detailsRejected": 0,
			"createdAt":             dt,
		},
	}

	filter := bson.M{"app_id": appID, "groupHash": hash}
	opts := options.Update().SetUpsert(true)

	_, err := collection.UpdateOne(ctx, filter, update, opts)
	if mongo.IsDuplicateKeyError(err) {
		// A concurrent insert won the upsert race; retry once. The document now
		// exists, so this becomes a plain $inc update with no insert.
		_, err = collection.UpdateOne(ctx, filter, update, opts)
	}
	if err != nil {
		return err
	}

	// A new event on a resolved group reopens it (regression). The filter matches
	// only resolved groups, so muted groups stay suppressed and open groups are
	// untouched.
	reopen := bson.M{
		"$set":   bson.M{"status": model.ReportGroupStatusOpen, "updatedAt": dt},
		"$unset": bson.M{"resolvedAt": "", "resolvedBy": ""},
	}
	reopenFilter := bson.M{"app_id": appID, "groupHash": hash, "status": model.ReportGroupStatusResolved}
	_, err = collection.UpdateOne(ctx, reopenFilter, reopen)
	return err
}

func (c *appRepository) IncrementReportGroupDetails(ctx context.Context, appID primitive.ObjectID, hash string, storedDelta, rejectedDelta int, now time.Time) error {
	dt := primitive.NewDateTimeFromTime(now)
	collection := c.client.Database(c.config.Database).Collection("report_groups")

	update := bson.M{
		"$inc": bson.M{
			"stats.detailsStored":   storedDelta,
			"stats.detailsRejected": rejectedDelta,
		},
		"$set": bson.M{"updatedAt": dt},
	}

	_, err := collection.UpdateOne(ctx, bson.M{"app_id": appID, "groupHash": hash}, update)
	return err
}

func (c *appRepository) InsertReportBlob(ctx context.Context, blob model.ReportBlob) error {
	collection := c.client.Database(c.config.Database).Collection("report_blobs")
	_, err := collection.InsertOne(ctx, blob)
	return err
}

// FindExcessReportBlobs returns the blobs beyond the newest keepN for a group
// (the oldest ones, ordered for deletion), with only _id and storage.key populated.
func (c *appRepository) FindExcessReportBlobs(ctx context.Context, appID primitive.ObjectID, hash string, keepN int64) ([]model.ReportBlob, error) {
	collection := c.client.Database(c.config.Database).Collection("report_blobs")
	opts := options.Find().
		SetSort(bson.D{{Key: "createdAt", Value: -1}, {Key: "_id", Value: -1}}).
		SetSkip(keepN).
		SetProjection(bson.M{"_id": 1, "storage.key": 1})

	cursor, err := collection.Find(ctx, bson.M{"app_id": appID, "groupHash": hash}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var blobs []model.ReportBlob
	if err := cursor.All(ctx, &blobs); err != nil {
		return nil, err
	}
	return blobs, nil
}

func (c *appRepository) DeleteReportBlobsByIDs(ctx context.Context, ids []primitive.ObjectID) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	collection := c.client.Database(c.config.Database).Collection("report_blobs")
	res, err := collection.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

// resolveAccessibleAppIDs returns the app ids whose reports the requester may read
func (c *appRepository) resolveAccessibleAppIDs(ctx context.Context, requester string) ([]primitive.ObjectID, error) {
	owner, teamUser, err := c.resolveOwnerAndTeamUser(ctx, requester)
	if err != nil {
		return nil, err
	}

	metaFilter := bson.M{"owner": owner, "app_name": bson.M{"$exists": true}}

	if teamUser != nil {
		allowedIDs := make([]primitive.ObjectID, 0, len(teamUser.Permissions.Apps.Allowed))
		for _, id := range teamUser.Permissions.Apps.Allowed {
			oid, err := primitive.ObjectIDFromHex(id)
			if err != nil {
				continue
			}
			allowedIDs = append(allowedIDs, oid)
		}
		if len(allowedIDs) == 0 {
			return nil, nil
		}
		metaFilter["_id"] = bson.M{"$in": allowedIDs}
	}

	collection := c.client.Database(c.config.Database).Collection("apps_meta")
	cursor, err := collection.Find(ctx, metaFilter, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var docs []struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	if err := cursor.All(ctx, &docs); err != nil {
		return nil, err
	}

	ids := make([]primitive.ObjectID, 0, len(docs))
	for _, d := range docs {
		ids = append(ids, d.ID)
	}
	return ids, nil
}

func applyReportGroupFilters(filter bson.M, filters map[string]string) {
	dims := map[string]string{
		"app":      "application.name",
		"version":  "application.version",
		"channel":  "application.channel",
		"platform": "system.platform",
		"arch":     "system.arch",
		"type":     "event.type",
		"reason":   "event.reason",
	}
	for key, field := range dims {
		if v := filters[key]; v != "" {
			filter[field] = v
		}
	}

	if v := filters["status"]; v != "" && v != "all" {
		if v == model.ReportGroupStatusOpen {
			filter["$or"] = []bson.M{{"status": v}, {"status": bson.M{"$exists": false}}}
		} else {
			filter["status"] = v
		}
	}

	lastSeen := bson.M{}
	if v := filters["from"]; v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			lastSeen["$gte"] = primitive.NewDateTimeFromTime(t)
		}
	}
	if v := filters["to"]; v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			lastSeen["$lte"] = primitive.NewDateTimeFromTime(t)
		}
	}
	if len(lastSeen) > 0 {
		filter["stats.lastSeen"] = lastSeen
	}
}

func (c *appRepository) GetReportGroups(ctx context.Context, requester string, filters map[string]string, page, limit int64) (*model.PaginatedReportGroups, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}

	result := &model.PaginatedReportGroups{Items: []*model.ReportGroup{}, Page: page, Limit: limit}

	appIDs, err := c.resolveAccessibleAppIDs(ctx, requester)
	if err != nil {
		return nil, err
	}
	if len(appIDs) == 0 {
		return result, nil
	}

	filter := bson.M{"app_id": bson.M{"$in": appIDs}}
	applyReportGroupFilters(filter, filters)

	collection := c.client.Database(c.config.Database).Collection("report_groups")
	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, err
	}
	result.Total = total

	opts := options.Find().
		SetSort(bson.D{{Key: "stats.lastSeen", Value: -1}}).
		SetSkip((page - 1) * limit).
		SetLimit(limit)

	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &result.Items); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *appRepository) UpdateReportGroup(ctx context.Context, requester, groupHash string, status *string, tags *[]string, note *string, resolvedBy string, now time.Time) (bool, error) {
	appIDs, err := c.resolveAccessibleAppIDs(ctx, requester)
	if err != nil {
		return false, err
	}
	if len(appIDs) == 0 {
		return false, nil
	}

	dt := primitive.NewDateTimeFromTime(now)
	set := bson.M{"updatedAt": dt}
	unset := bson.M{}

	if status != nil {
		set["status"] = *status
		if *status == model.ReportGroupStatusResolved {
			set["resolvedAt"] = dt
			set["resolvedBy"] = resolvedBy
		} else {
			unset["resolvedAt"] = ""
			unset["resolvedBy"] = ""
		}
	}
	if tags != nil {
		if len(*tags) == 0 {
			unset["tags"] = ""
		} else {
			set["tags"] = *tags
		}
	}
	if note != nil {
		if *note == "" {
			unset["note"] = ""
		} else {
			set["note"] = *note
		}
	}

	update := bson.M{"$set": set}
	if len(unset) > 0 {
		update["$unset"] = unset
	}

	collection := c.client.Database(c.config.Database).Collection("report_groups")
	res, err := collection.UpdateOne(ctx, bson.M{"app_id": bson.M{"$in": appIDs}, "groupHash": groupHash}, update)
	if err != nil {
		return false, err
	}
	return res.MatchedCount > 0, nil
}

func (c *appRepository) DeleteReportGroup(ctx context.Context, requester, groupHash string) (bool, []string, error) {
	appIDs, err := c.resolveAccessibleAppIDs(ctx, requester)
	if err != nil {
		return false, nil, err
	}
	if len(appIDs) == 0 {
		return false, nil, nil
	}

	scope := bson.M{"app_id": bson.M{"$in": appIDs}, "groupHash": groupHash}

	blobColl := c.client.Database(c.config.Database).Collection("report_blobs")
	cursor, err := blobColl.Find(ctx, scope, options.Find().SetProjection(bson.M{"storage.key": 1}))
	if err != nil {
		return false, nil, err
	}
	var blobs []model.ReportBlob
	if err := cursor.All(ctx, &blobs); err != nil {
		return false, nil, err
	}
	keys := make([]string, 0, len(blobs))
	for _, b := range blobs {
		if b.Storage.Key != "" {
			keys = append(keys, b.Storage.Key)
		}
	}

	if _, err := blobColl.DeleteMany(ctx, scope); err != nil {
		return false, nil, err
	}

	groupColl := c.client.Database(c.config.Database).Collection("report_groups")
	res, err := groupColl.DeleteOne(ctx, scope)
	if err != nil {
		return false, nil, err
	}
	return res.DeletedCount > 0, keys, nil
}

func (c *appRepository) GetReportBlobsByGroupHash(ctx context.Context, requester, groupHash string, limit int64) ([]*model.ReportBlob, error) {
	if limit < 1 {
		limit = 50
	}

	appIDs, err := c.resolveAccessibleAppIDs(ctx, requester)
	if err != nil {
		return nil, err
	}
	if len(appIDs) == 0 {
		return []*model.ReportBlob{}, nil
	}

	collection := c.client.Database(c.config.Database).Collection("report_blobs")
	filter := bson.M{"app_id": bson.M{"$in": appIDs}, "groupHash": groupHash}
	opts := options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}).SetLimit(limit)

	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	blobs := []*model.ReportBlob{}
	if err := cursor.All(ctx, &blobs); err != nil {
		return nil, err
	}
	return blobs, nil
}
