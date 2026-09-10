package delete

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/handler/create"
	"faynoSync/server/handler/info"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const defaultMaxBulkDeleteVersions = 10

func hasVelopackLink(links []string) bool {
	for _, l := range links {
		if strings.Contains(l, "velopack/") {
			return true
		}
	}
	return false
}

func hasSparkleLink(links []string) bool {
	for _, l := range links {
		if strings.Contains(l, "sparkle/") || strings.Contains(l, "sparkle%2F") {
			return true
		}
	}
	return false
}

func deleteLinksFromStorage(links []string, private bool, env *viper.Viper) []string {
	var failed []string
	keys := make([]string, 0, len(links))
	linksByKey := make(map[string]string, len(links))

	for _, link := range links {
		subLink, err := utils.ExtractS3Key(link, private, env)
		if err != nil {
			logrus.Errorf("Failed to extract storage key from link '%s': %v", link, err)
			failed = append(failed, link)
			continue
		}
		keys = append(keys, subLink)
		linksByKey[subLink] = link
	}

	for _, failedKey := range utils.DeleteManyFromS3(keys, env, private) {
		failed = append(failed, linksByKey[failedKey])
	}

	return failed
}

func maxBulkDeleteVersions(env *viper.Viper) int {
	limit := env.GetInt("MAX_BULK_DELETE_VERSIONS")
	if limit <= 0 {
		return defaultMaxBulkDeleteVersions
	}
	return limit
}

// parseVersionIDs keeps the request order and drops repeated ids, so the same
// version is never counted twice. On failure it also returns the offending id.
func parseVersionIDs(rawIDs []string) ([]primitive.ObjectID, string, error) {
	ids := make([]primitive.ObjectID, 0, len(rawIDs))
	seen := make(map[primitive.ObjectID]struct{}, len(rawIDs))

	for _, rawID := range rawIDs {
		objID, err := primitive.ObjectIDFromHex(rawID)
		if err != nil {
			return nil, rawID, err
		}
		if _, duplicate := seen[objID]; duplicate {
			continue
		}
		seen[objID] = struct{}{}
		ids = append(ids, objID)
	}

	return ids, "", nil
}

// respondOnMissingVersions answers a request that names at least one version the
// owner cannot delete. Nothing is deleted in that case, not even the valid ids.
func respondOnMissingVersions(
	c *gin.Context,
	ctx context.Context,
	repository db.AppRepository,
	ids []primitive.ObjectID,
	versions []*model.SpecificAppWithoutIDs,
	singleMode bool,
) {
	found := make(map[primitive.ObjectID]struct{}, len(versions))
	for _, version := range versions {
		found[version.ID] = struct{}{}
	}

	var missing []primitive.ObjectID
	for _, id := range ids {
		if _, ok := found[id]; !ok {
			missing = append(missing, id)
		}
	}

	owners, err := repository.FetchVersionOwners(missing, ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check versions of app", "details": err.Error()})
		return
	}

	var notFound, forbidden []string
	for _, id := range missing {
		if _, exists := owners[id]; exists {
			forbidden = append(forbidden, id.Hex())
			continue
		}
		notFound = append(notFound, id.Hex())
	}

	if singleMode {
		details := fmt.Sprintf("no app found with ID %s", missing[0])
		if len(forbidden) > 0 {
			details = "you don't have permission to delete this item"
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete specific version of app", "details": details})
		return
	}

	if len(forbidden) > 0 {
		response := gin.H{"error": "you don't have permission to delete these items", "forbidden": forbidden}
		if len(notFound) > 0 {
			response["not_found"] = notFound
		}
		c.JSON(http.StatusForbidden, response)
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "some of the requested versions do not exist", "not_found": notFound})
}

func DeleteSpecificVersionOfApp(c *gin.Context, repository db.AppRepository, db *mongo.Database, rdb *redis.Client, performanceMode bool) {
	env := viper.GetViper()
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	rawIDs := c.QueryArray("id")
	if len(rawIDs) == 0 {
		// Keeps the answer to a request without an id what it always was.
		rawIDs = []string{c.Query("id")}
	}
	// A single id keeps the original response and error contract of this endpoint.
	singleMode := len(rawIDs) == 1

	if limit := maxBulkDeleteVersions(env); len(rawIDs) > limit {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many versions requested", "limit": limit, "requested": len(rawIDs)})
		return
	}

	ids, invalidID, err := parseVersionIDs(rawIDs)
	if err != nil {
		if singleMode {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid version id", "id": invalidID, "details": err.Error()})
		return
	}

	// App, channel, version and artifact links are only resolvable while the
	// documents are still there, and they are what the cleanup below runs on.
	versions, err := repository.FetchVersionsByIDs(ids, owner, ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch versions of app", "details": err.Error()})
		return
	}

	if len(versions) != len(ids) {
		respondOnMissingVersions(c, ctx, repository, ids, versions, singleMode)
		return
	}

	var appNames, channels, links []string
	seenAppNames := make(map[string]struct{}, 1)
	seenChannels := make(map[string]struct{}, len(versions))
	for _, version := range versions {
		if _, ok := seenAppNames[version.AppName]; !ok {
			seenAppNames[version.AppName] = struct{}{}
			appNames = append(appNames, version.AppName)
		}
		if _, ok := seenChannels[version.Channel]; !ok {
			seenChannels[version.Channel] = struct{}{}
			channels = append(channels, version.Channel)
		}
		for _, artifact := range version.Artifacts {
			if artifact.Link == "" {
				continue
			}
			links = append(links, artifact.Link)
		}
	}

	// One application per request: visibility, feeds and cache invalidation are
	// all per application, and a mixed request hides what is really being erased.
	if len(appNames) > 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "all versions must belong to the same application", "apps": appNames})
		return
	}
	appName := appNames[0]

	//request on repository
	result, err := repository.DeleteVersionsByIDs(ids, owner, ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete specific version of app", "details": err.Error()})
		return
	}
	logrus.Infof("Deleted %d version(s) of app %s requested by %s", result, appName, owner)

	checkAppVisibility, err := utils.CheckPrivate(appName, db, c)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check private"})
		return
	}

	// The documents are already gone, so storage failures must not abort the rest
	// of the cleanup - report the leftovers instead.
	failedLinks := deleteLinksFromStorage(links, checkAppVisibility, env)

	if viper.GetBool("SLACK_ENABLE") && rdb != nil {
		for _, version := range versions {
			if version.Version == "" {
				continue
			}
			if err := utils.DeleteSlackNotificationState(owner, version.Channel, appName, version.Version, rdb); err != nil {
				logrus.Error("Error cleaning Slack notification state after version deletion: ", err)
			}
		}
	}

	create.InvalidateAppCaches(ctx, db, rdb, performanceMode, owner, appName, channels, env)

	if hasVelopackLink(links) {
		info.MaterializeVelopackForApp(c.Request.Context(), db, env, owner, appName)
	}

	if hasSparkleLink(links) {
		info.MaterializeSparkleForApp(c.Request.Context(), db, env, owner, appName)
	}

	response := gin.H{"deleteSpecificAppResult.DeletedCount": result}
	if !singleMode {
		deleted := make([]gin.H, 0, len(versions))
		for _, version := range versions {
			deleted = append(deleted, gin.H{"id": version.ID.Hex(), "version": version.Version, "channel": version.Channel})
		}
		response["app_name"] = appName
		response["deleted"] = deleted
	}
	if len(failedLinks) > 0 {
		logrus.Errorf("Failed to delete %d artifact(s) from storage after removing %d version(s) of %s", len(failedLinks), result, appName)
		response["orphaned_links"] = failedLinks
	}
	c.JSON(http.StatusOK, response)
}

func DeleteSpecificArtifactOfApp(c *gin.Context, repository db.AppRepository, db *mongo.Database, rdb *redis.Client) {
	env := viper.GetViper()
	ctxQueryMap, err := utils.ValidateUpdateParams(c, db)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(ctxQueryMap["id"].(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	delete(ctxQueryMap, "id")
	links, result, err := repository.DeleteSpecificArtifactOfApp(objID, ctxQueryMap, c.Request.Context(), owner)
	if err != nil {
		logrus.Error(err)
	}
	checkAppVisibility, err := utils.CheckPrivate(ctxQueryMap["app_name"].(string), db, c)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check private"})
		return
	}

	failedLinks := deleteLinksFromStorage(links, checkAppVisibility, env)

	// Deleting one artifact only changes its own (channel, platform, arch) feed.
	deleteTuples := info.TupleFromContext(ctxQueryMap)

	if hasVelopackLink(links) {
		info.MaterializeVelopackForTuplesOrFull(c.Request.Context(), db, env, owner, ctxQueryMap["app_name"].(string), deleteTuples)
	}

	if hasSparkleLink(links) {
		info.MaterializeSparkleForTuplesOrFull(c.Request.Context(), db, env, owner, ctxQueryMap["app_name"].(string), deleteTuples)
	}

	if result && len(links) > 0 && viper.GetBool("SLACK_ENABLE") && rdb != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			humanReadableData, err := repository.FetchAppByID(objID, ctx)
			if err != nil || len(humanReadableData) == 0 {
				logrus.Error("Error fetching human-readable data for Slack notification: ", err)
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

			utils.UpdateSlackNotificationIfExists(
				owner,
				slackData.AppName,
				slackData.Channel,
				slackData.Version,
				platforms,
				arches,
				artifacts,
				changelog,
				pkgs,
				viper.GetViper(),
				rdb,
				slackData.Published,
				slackData.Critical,
			)
		}()
	}

	artifactResponse := gin.H{"deleteSpecificArtifactResult": result}
	if len(failedLinks) > 0 {
		logrus.Errorf("Failed to delete %d artifact(s) from storage for app %s", len(failedLinks), ctxQueryMap["app_name"].(string))
		artifactResponse["orphaned_links"] = failedLinks
	}
	c.JSON(http.StatusOK, artifactResponse)
}

func DeleteApp(c *gin.Context, repository db.AppRepository) {
	deleteEntity(c, repository, "app")
}

func DeleteChannel(c *gin.Context, repository db.AppRepository) {
	deleteEntity(c, repository, "channel")
}

func DeleteArch(c *gin.Context, repository db.AppRepository) {
	deleteEntity(c, repository, "arch")
}

func DeletePlatform(c *gin.Context, repository db.AppRepository) {
	deleteEntity(c, repository, "platform")
}

func deleteEntity(c *gin.Context, repository db.AppRepository, itemType string) {
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var result interface{}
	switch itemType {
	case "channel":
		result, err = repository.DeleteChannel(objID, owner, ctx)
	case "platform":
		result, err = repository.DeletePlatform(objID, owner, ctx)
	case "arch":
		result, err = repository.DeleteArch(objID, owner, ctx)
	case "app":
		result, err = repository.DeleteApp(objID, owner, ctx)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item type"})
		return
	}
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete " + itemType, "details": err.Error()})
		return
	}
	var tag language.Tag
	titleCase := cases.Title(tag)

	capitalizedItemType := titleCase.String(itemType)
	c.JSON(http.StatusOK, gin.H{"delete" + capitalizedItemType + "Result.DeletedCount": result})
}
