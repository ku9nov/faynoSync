package info

import (
	"context"
	"faynoSync/server/model"
	"faynoSync/server/utils/updaters/sparkle"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func loadSparkleReleases(ctx context.Context, database *mongo.Database, owner, app, channel, platform, arch string) ([]sparkle.Release, error) {
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
			{Key: "sparkle", Value: bson.D{{Key: "$exists", Value: true}}},
		}}}},
	}

	cursor, err := database.Collection("apps").Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query sparkle versions: %w", err)
	}
	defer cursor.Close(ctx)

	var versions []model.SpecificApp
	if err := cursor.All(ctx, &versions); err != nil {
		return nil, fmt.Errorf("failed to decode sparkle versions: %w", err)
	}

	releases := make([]sparkle.Release, 0, len(versions))
	for _, v := range versions {
		release := sparkle.Release{
			Version:       v.Version,
			Published:     v.Published,
			Critical:      v.Critical,
			NotesMarkdown: velopackNotesForVersion(v),
			PubDate:       sparklePubDate(v.Updated_at),
		}
		for _, a := range v.Artifacts {
			if a.Sparkle == nil || a.Platform != platformID || a.Arch != archID {
				continue
			}
			asset := sparkle.Asset{Meta: *a.Sparkle, Link: a.Link}
			switch a.Sparkle.Kind {
			case sparkle.KindFull:
				full := asset
				release.Full = &full
			case sparkle.KindDelta:
				release.Deltas = append(release.Deltas, asset)
			}
		}
		if release.Full == nil && len(release.Deltas) == 0 {
			continue
		}
		releases = append(releases, release)
	}

	return releases, nil
}

func sparklePubDate(dt primitive.DateTime) string {
	if dt == 0 {
		return ""
	}
	return dt.Time().Format(time.RFC1123Z)
}
