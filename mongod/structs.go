package mongod

import (
	"context"

	"faynoSync/server/model"

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
	FetchLatestVersionOfApp(appName, channel string, ctx context.Context) ([]*model.SpecificAppWithoutIDs, error)
	FetchAppByID(appID primitive.ObjectID, ctx context.Context) ([]*model.SpecificAppWithoutIDs, error)
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
			{Key: "version", Value: 1},
		}}},
		bson.D{{Key: "$limit", Value: 100}},
	}
}
func (c *appRepository) sortVersionPipeline() mongo.Pipeline {
	return mongo.Pipeline{
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
			{Key: "build_v", Value: bson.D{
				{Key: "$toInt", Value: bson.D{
					{Key: "$arrayElemAt", Value: bson.A{"$versions_arr", 3}},
				}},
			}},
		}}},
		{{Key: "$sort", Value: bson.D{
			{Key: "major_v", Value: -1},
			{Key: "minor_v", Value: -1},
			{Key: "patch_v", Value: -1},
			{Key: "build_v", Value: -1},
		}}},
		{{Key: "$limit", Value: 1}},
	}
}
