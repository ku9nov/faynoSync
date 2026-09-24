package create

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/handler/info"
	"faynoSync/server/utils"
	"faynoSync/server/utils/updaters/sparkle"
	"faynoSync/server/utils/updaters/velopack"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// FinalizeUpload runs the steps that follow a stored artifact: cache invalidation and
// the feed regeneration for the tuple it belongs to. It needs the file names, not the
// files, so a flow that never holds the bytes can finish an upload the same way.
func FinalizeUpload(
	ctx context.Context,
	database *mongo.Database,
	rdb *redis.Client,
	performanceMode bool,
	ctxQueryMap map[string]interface{},
	owner string,
	appName string,
	fileNames []string,
	checkAppVisibility bool,
	env *viper.Viper,
) {
	InvalidatePublishCaches(
		ctx,
		ctxQueryMap,
		database,
		rdb,
		performanceMode,
		owner,
		appName,
		env,
		"Uploaded app",
	)

	// An upload adds one artifact for one (channel, platform, arch), so only that
	// tuple's feed changes - regenerate just it, not every feed of the app.
	uploadTuples := info.TupleFromContext(ctxQueryMap)

	if updater, _ := ctxQueryMap["updater"].(string); updater == velopack.UpdaterType {
		CopyVelopackInstallersToDefault(ctx, ctxQueryMap, owner, fileNames, checkAppVisibility, env)
		info.MaterializeVelopackForTuplesOrFull(ctx, database, env, owner, appName, uploadTuples, checkAppVisibility)
	}

	if updater, _ := ctxQueryMap["updater"].(string); updater == sparkle.UpdaterType {
		info.MaterializeSparkleForTuplesOrFull(ctx, database, env, owner, appName, uploadTuples, checkAppVisibility)
	}
}

// NotifySlackForApp reports a stored version to Slack in the background. It reads the
// version back so the message describes what was persisted, not what was requested.
func NotifySlackForApp(repository db.AppRepository, appID primitive.ObjectID, owner string, rdb *redis.Client, env *viper.Viper) {
	if !env.GetBool("SLACK_ENABLE") {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		humanReadableData, err := repository.FetchAppByID(appID, ctx)
		if err != nil {
			logrus.Error("Error fetching human-readable data for Slack notification: ", err)
			return
		}
		if len(humanReadableData) == 0 {
			logrus.Warn("No app data found for Slack notification, app ID: ", appID.Hex())
			return
		}

		slackData := humanReadableData[0]

		var platforms, arches, artifacts, pkgs []string
		for _, artifact := range slackData.Artifacts {
			platforms = append(platforms, artifact.Platform)
			arches = append(arches, artifact.Arch)
			artifacts = append(artifacts, artifact.Link)
			pkgs = append(pkgs, artifact.Package)
		}

		var changelog []string
		for _, change := range slackData.Changelog {
			if strings.TrimSpace(change.Changes) == "" {
				continue
			}
			changelog = append(changelog, change.Changes)
		}

		utils.SendSlackNotification(
			owner,
			slackData.AppName,
			slackData.Channel,
			slackData.Version,
			platforms,
			arches,
			artifacts,
			changelog,
			pkgs,
			env,
			rdb,
			slackData.Published,
			slackData.Critical,
		)
	}()
}
