package info

import (
	"context"
	"faynoSync/server/model"
	"faynoSync/server/utils/updaters/velopack"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func resolveMetaID(ctx context.Context, metaCollection *mongo.Collection, field, value, owner string) (primitive.ObjectID, error) {
	var meta struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	err := metaCollection.FindOne(ctx, bson.D{{Key: field, Value: value}, {Key: "owner", Value: owner}}).Decode(&meta)
	if err != nil {
		return primitive.NilObjectID, fmt.Errorf("%s %q not found in apps_meta: %w", field, value, err)
	}
	return meta.ID, nil
}

// resolveVelopackPackageLink finds the public storage link of a velopack package
// by exact file name for the given (owner, app, platform, arch)
// Required for dynamic API working.
func resolveVelopackPackageLink(ctx context.Context, database *mongo.Database, owner, app, platform, arch, fileName string) (string, error) {
	metaCollection := database.Collection("apps_meta")

	appID, err := resolveMetaID(ctx, metaCollection, "app_name", app, owner)
	if err != nil {
		return "", err
	}
	platformID, err := resolveMetaID(ctx, metaCollection, "platform_name", platform, owner)
	if err != nil {
		return "", err
	}
	archID, err := resolveMetaID(ctx, metaCollection, "arch_id", arch, owner)
	if err != nil {
		return "", err
	}

	filter := bson.D{
		{Key: "app_id", Value: appID},
		{Key: "owner", Value: owner},
		{Key: "published", Value: true},
		{Key: "artifacts", Value: bson.D{{Key: "$elemMatch", Value: bson.D{
			{Key: "platform", Value: platformID},
			{Key: "arch", Value: archID},
			{Key: "velopack.file_name", Value: fileName},
		}}}},
	}

	var version model.SpecificApp
	if err := database.Collection("apps").FindOne(ctx, filter).Decode(&version); err != nil {
		return "", fmt.Errorf("velopack package %q not found: %w", fileName, err)
	}

	for _, a := range version.Artifacts {
		if a.Platform == platformID && a.Arch == archID && a.Velopack != nil && a.Velopack.FileName == fileName {
			if a.Link == "" {
				return "", fmt.Errorf("velopack package %q has empty link", fileName)
			}
			return a.Link, nil
		}
	}

	return "", fmt.Errorf("velopack package %q not found", fileName)
}

func loadVelopackReleases(ctx context.Context, database *mongo.Database, owner, app, channel, platform, arch string) ([]velopack.Release, error) {
	metaCollection := database.Collection("apps_meta")

	appID, err := resolveMetaID(ctx, metaCollection, "app_name", app, owner)
	if err != nil {
		return nil, err
	}
	channelID, err := resolveMetaID(ctx, metaCollection, "channel_name", channel, owner)
	if err != nil {
		return nil, err
	}
	platformID, err := resolveMetaID(ctx, metaCollection, "platform_name", platform, owner)
	if err != nil {
		return nil, err
	}
	archID, err := resolveMetaID(ctx, metaCollection, "arch_id", arch, owner)
	if err != nil {
		return nil, err
	}

	filter := bson.D{
		{Key: "app_id", Value: appID},
		{Key: "owner", Value: owner},
		{Key: "channel_id", Value: channelID},
		{Key: "artifacts", Value: bson.D{{Key: "$elemMatch", Value: bson.D{
			{Key: "platform", Value: platformID},
			{Key: "arch", Value: archID},
			{Key: "velopack", Value: bson.D{{Key: "$exists", Value: true}}},
		}}}},
	}

	cursor, err := database.Collection("apps").Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query velopack versions: %w", err)
	}
	defer cursor.Close(ctx)

	var versions []model.SpecificApp
	if err := cursor.All(ctx, &versions); err != nil {
		return nil, fmt.Errorf("failed to decode velopack versions: %w", err)
	}

	releases := make([]velopack.Release, 0, len(versions))
	for _, v := range versions {
		release := velopack.Release{
			Version:       v.Version,
			Published:     v.Published,
			Intermediate:  v.Intermediate,
			NotesMarkdown: velopackNotesForVersion(v),
		}
		for _, a := range v.Artifacts {
			if a.Velopack == nil || a.Velopack.FileName == "" || a.Platform != platformID || a.Arch != archID {
				continue
			}
			asset := &velopack.FeedAsset{
				Version:  v.Version,
				Type:     a.Velopack.Type,
				FileName: a.Velopack.FileName,
				SHA1:     a.Velopack.SHA1,
				SHA256:   a.Velopack.SHA256,
				Size:     a.Velopack.Size,
			}
			switch a.Velopack.Type {
			case "Full":
				release.Full = asset
			case "Delta":
				release.Delta = asset
			}
		}
		if release.Full == nil && release.Delta == nil {
			continue
		}
		releases = append(releases, release)
	}

	return releases, nil
}
