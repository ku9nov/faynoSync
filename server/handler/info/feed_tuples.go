package info

import (
	"context"
	"faynoSync/server/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type FeedTuple struct {
	Channel  string
	Platform string
	Arch     string
}

func TupleFromContext(ctxQueryMap map[string]interface{}) []FeedTuple {
	channel, _ := ctxQueryMap["channel"].(string)
	platform, _ := ctxQueryMap["platform"].(string)
	arch, _ := ctxQueryMap["arch"].(string)
	if channel == "" || platform == "" || arch == "" {
		return nil
	}
	return []FeedTuple{{Channel: channel, Platform: platform, Arch: arch}}
}

// versionTuples returns the tuples a single version's artifacts belong to
func versionTuples(ctx context.Context, database *mongo.Database, versionID primitive.ObjectID, selects func(model.Artifact) bool) ([]FeedTuple, error) {
	var v model.SpecificApp
	if err := database.Collection("apps").FindOne(ctx, bson.D{{Key: "_id", Value: versionID}}).Decode(&v); err != nil {
		return nil, err
	}
	resolver, err := buildMetaNameResolver(ctx, database.Collection("apps_meta"), []model.SpecificApp{v})
	if err != nil {
		return nil, err
	}
	channel := resolver[v.ChannelID]
	seen := make(map[FeedTuple]struct{})
	var tuples []FeedTuple
	for _, a := range v.Artifacts {
		if !selects(a) {
			continue
		}
		t := FeedTuple{Channel: channel, Platform: resolver[a.Platform], Arch: resolver[a.Arch]}
		if t.Channel == "" || t.Platform == "" || t.Arch == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		tuples = append(tuples, t)
	}
	return tuples, nil
}

// SparkleVersionTuples returns every (channel, platform, arch) whose feed can be
// affected by a version-level change to this version's sparkle artifacts.
func SparkleVersionTuples(ctx context.Context, database *mongo.Database, versionID primitive.ObjectID) ([]FeedTuple, error) {
	return versionTuples(ctx, database, versionID, func(a model.Artifact) bool { return a.Sparkle != nil })
}

// VelopackVersionTuples is the velopack counterpart of SparkleVersionTuples.
func VelopackVersionTuples(ctx context.Context, database *mongo.Database, versionID primitive.ObjectID) ([]FeedTuple, error) {
	return versionTuples(ctx, database, versionID, func(a model.Artifact) bool { return a.Velopack != nil })
}
