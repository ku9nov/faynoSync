package info

import (
	"context"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type telemetryAllowListOwner struct {
	Apps map[string]*telemetryAllowListApp
}

type telemetryAllowListApp struct {
	Channels map[string]*telemetryAllowListChannel
	Versions map[string]struct{}
}

type telemetryAllowListChannel struct {
	Platforms map[string]*telemetryAllowListPlatform
}

type telemetryAllowListPlatform struct {
	Archs map[string]struct{}
}

type TelemetryAllowList struct {
	Owners        map[string]*telemetryAllowListOwner
	OwnerCount    int
	AppCount      int
	ChannelCount  int
	PlatformCount int
	ArchCount     int
	VersionCount  int
	TupleCount    int
	apps          map[string]struct{}
	channels      map[string]struct{}
	platforms     map[string]struct{}
	architectures map[string]struct{}
	versions      map[string]struct{}
}

type telemetryAllowListRow struct {
	Owner    string `bson:"owner"`
	AppName  string `bson:"app_name"`
	Channel  string `bson:"channel"`
	Platform string `bson:"platform"`
	Arch     string `bson:"arch"`
	Version  string `bson:"version"`
}

var telemetryAllowList atomic.Pointer[TelemetryAllowList]

func NewTelemetryAllowList() *TelemetryAllowList {
	return &TelemetryAllowList{
		Owners:        make(map[string]*telemetryAllowListOwner),
		apps:          make(map[string]struct{}),
		channels:      make(map[string]struct{}),
		platforms:     make(map[string]struct{}),
		architectures: make(map[string]struct{}),
		versions:      make(map[string]struct{}),
	}
}

func (idx *TelemetryAllowList) Add(owner, appName, channel, platform, arch, version string) {
	if owner == "" || appName == "" || channel == "" || platform == "" || arch == "" {
		return
	}

	ownerEntry, ok := idx.Owners[owner]
	if !ok {
		ownerEntry = &telemetryAllowListOwner{Apps: make(map[string]*telemetryAllowListApp)}
		idx.Owners[owner] = ownerEntry
		idx.OwnerCount++
	}

	appEntry, ok := ownerEntry.Apps[appName]
	if !ok {
		appEntry = &telemetryAllowListApp{
			Channels: make(map[string]*telemetryAllowListChannel),
			Versions: make(map[string]struct{}),
		}
		ownerEntry.Apps[appName] = appEntry
	}
	if _, ok := idx.apps[appName]; !ok {
		idx.apps[appName] = struct{}{}
		idx.AppCount++
	}

	if version != "" {
		if _, ok := appEntry.Versions[version]; !ok {
			appEntry.Versions[version] = struct{}{}
		}
		if _, ok := idx.versions[version]; !ok {
			idx.versions[version] = struct{}{}
			idx.VersionCount++
		}
	}

	channelEntry, ok := appEntry.Channels[channel]
	if !ok {
		channelEntry = &telemetryAllowListChannel{Platforms: make(map[string]*telemetryAllowListPlatform)}
		appEntry.Channels[channel] = channelEntry
	}
	if _, ok := idx.channels[channel]; !ok {
		idx.channels[channel] = struct{}{}
		idx.ChannelCount++
	}

	platformEntry, ok := channelEntry.Platforms[platform]
	if !ok {
		platformEntry = &telemetryAllowListPlatform{Archs: make(map[string]struct{})}
		channelEntry.Platforms[platform] = platformEntry
	}
	if _, ok := idx.platforms[platform]; !ok {
		idx.platforms[platform] = struct{}{}
		idx.PlatformCount++
	}

	if _, ok := platformEntry.Archs[arch]; !ok {
		platformEntry.Archs[arch] = struct{}{}
		idx.TupleCount++
	}
	if _, ok := idx.architectures[arch]; !ok {
		idx.architectures[arch] = struct{}{}
		idx.ArchCount++
	}
}

func (idx *TelemetryAllowList) Valid(owner, appName, channel, platform, arch string) bool {
	if idx == nil {
		return false
	}

	ownerEntry, ok := idx.Owners[owner]
	if !ok {
		return false
	}

	appEntry, ok := ownerEntry.Apps[appName]
	if !ok {
		return false
	}

	channelEntry, ok := appEntry.Channels[channel]
	if !ok {
		return false
	}

	platformEntry, ok := channelEntry.Platforms[platform]
	if !ok {
		return false
	}

	_, ok = platformEntry.Archs[arch]
	return ok
}

func LoadTelemetryAllowList() *TelemetryAllowList {
	return telemetryAllowList.Load()
}

func ReloadTelemetryAllowList(ctx context.Context, database *mongo.Database) error {
	if database == nil {
		logrus.Debug("Telemetry allow-list reload skipped because Mongo database is nil")
		return nil
	}

	logrus.Debug("Reloading telemetry allow-list from MongoDB")
	next, err := BuildTelemetryAllowListFromDB(ctx, database)
	if err != nil {
		return err
	}

	telemetryAllowList.Store(next)
	logrus.Debugf(
		"Telemetry allow-list swapped: owners=%d apps=%d channels=%d platforms=%d architectures=%d versions=%d tuples=%d",
		next.OwnerCount,
		next.AppCount,
		next.ChannelCount,
		next.PlatformCount,
		next.ArchCount,
		next.VersionCount,
		next.TupleCount,
	)
	return nil
}

func BuildTelemetryAllowListFromDB(ctx context.Context, database *mongo.Database) (*TelemetryAllowList, error) {
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.M{"published": true}}},
		bson.D{{Key: "$unwind", Value: "$artifacts"}},
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
		bson.D{{Key: "$unwind", Value: "$channel_meta"}},
		bson.D{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "artifacts.platform",
			"foreignField": "_id",
			"as":           "platform_meta",
		}}},
		bson.D{{Key: "$unwind", Value: "$platform_meta"}},
		bson.D{{Key: "$lookup", Value: bson.M{
			"from":         "apps_meta",
			"localField":   "artifacts.arch",
			"foreignField": "_id",
			"as":           "arch_meta",
		}}},
		bson.D{{Key: "$unwind", Value: "$arch_meta"}},
		bson.D{{Key: "$project", Value: bson.M{
			"_id":      0,
			"owner":    1,
			"version":  1,
			"app_name": "$app_meta.app_name",
			"channel":  "$channel_meta.channel_name",
			"platform": "$platform_meta.platform_name",
			"arch":     "$arch_meta.arch_id",
		}}},
	}

	cursor, err := database.Collection("apps").Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	next := NewTelemetryAllowList()
	rowCount := 0
	for cursor.Next(ctx) {
		var row telemetryAllowListRow
		if err := cursor.Decode(&row); err != nil {
			return nil, err
		}
		rowCount++
		logrus.Debugf("Telemetry allow-list row: owner=%s app=%s channel=%s platform=%s arch=%s version=%s", row.Owner, row.AppName, row.Channel, row.Platform, row.Arch, row.Version)
		next.Add(row.Owner, row.AppName, row.Channel, row.Platform, row.Arch, row.Version)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}

	logrus.Debugf("Telemetry allow-list build completed from %d projected rows", rowCount)
	return next, nil
}
