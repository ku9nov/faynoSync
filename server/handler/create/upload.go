package create

import (
	"context"
	"errors"
	db "faynoSync/mongod"
	"faynoSync/server/handler/info"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"faynoSync/server/utils/updaters"
	"faynoSync/server/utils/updaters/sparkle"
	"faynoSync/server/utils/updaters/velopack"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func ParseVelopackFeed(files []*multipart.FileHeader) (map[string]velopack.VelopackMeta, error) {
	for _, file := range files {
		name := strings.ToLower(file.Filename)
		if strings.HasPrefix(name, "releases.") && strings.HasSuffix(name, ".json") {
			f, err := file.Open()
			if err != nil {
				return nil, err
			}
			defer f.Close()
			content, err := io.ReadAll(f)
			if err != nil {
				return nil, err
			}
			return velopack.ParseFeed(content)
		}
	}
	return nil, fmt.Errorf("velopack updater requires a releases.*.json feed file")
}

func ParseSparkleAppcast(files []*multipart.FileHeader) (map[string]sparkle.SparkleMeta, error) {
	for _, file := range files {
		name := strings.ToLower(file.Filename)
		if strings.HasPrefix(name, "appcast") && strings.HasSuffix(name, ".xml") {
			f, err := file.Open()
			if err != nil {
				return nil, err
			}
			defer f.Close()
			content, err := io.ReadAll(f)
			if err != nil {
				return nil, err
			}
			return sparkle.ParseAppcast(content)
		}
	}
	return nil, fmt.Errorf("sparkle updater requires an appcast.*.xml feed file")
}

// CopyVelopackInstallersToDefault materializes the flat, fixed-name installer
// so the persisted artifact link points at the per-version installers/ object
// while the default name keeps pointing at the newest upload. It self-gates on
// the velopack updater, since only that path routes installers to versioned keys.
func CopyVelopackInstallersToDefault(ctx context.Context, ctxQuery map[string]interface{}, owner string, files []*multipart.FileHeader, checkAppVisibility bool, env *viper.Viper) {
	if updater, _ := ctxQuery["updater"].(string); updater != velopack.UpdaterType {
		return
	}

	hasInstaller := false
	for _, file := range files {
		if velopack.IsInstallerFile(file.Filename) {
			hasInstaller = true
			break
		}
	}
	if !hasInstaller {
		return
	}

	factory := utils.NewStorageFactory(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		logrus.Errorf("Failed to create storage client for velopack installer copy: %v", err)
		return
	}

	bucketName := env.GetString("S3_BUCKET_NAME")
	public := true
	if checkAppVisibility {
		bucketName = env.GetString("S3_BUCKET_NAME_PRIVATE")
		public = false
	}

	for _, file := range files {
		if !velopack.IsInstallerFile(file.Filename) {
			continue
		}
		srcKey := velopack.InstallerVersionedKey(ctxQuery, owner, file.Filename)
		dstKey := velopack.InstallerDefaultKey(ctxQuery, owner, file.Filename)
		if err := storageClient.CopyObject(ctx, bucketName, srcKey, dstKey, public); err != nil {
			logrus.Errorf("Failed to copy velopack installer %s -> %s: %v", srcKey, dstKey, err)
			continue
		}
		logrus.Debugf("Materialized default velopack installer: %s/%s", bucketName, dstKey)
	}
}

func InvalidateCache(ctx context.Context, params map[string]interface{}, rdb *redis.Client) error {

	appName, _ := params["app_name"].(string)
	channel, _ := params["channel"].(string)

	pattern := fmt.Sprintf("app_name=%s&version=*&channel=%s&platform=*&arch=*",
		appName, channel)
	logrus.Debugf("Redis pattern %s will be invalidated.", pattern)

	keys, err := rdb.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to fetch keys for invalidation: %w", err)
	}

	if len(keys) == 0 {
		logrus.Debug("No keys found to invalidate.")
		return nil
	}

	for _, key := range keys {
		logrus.Debugf("Invalidating key: %s", key)
		if err := rdb.Del(ctx, key).Err(); err != nil {
			logrus.Errorf("Failed to invalidate key: %s, error: %v", key, err)
		}
	}

	return nil
}

func IsCdnEdgeEnabled(ctx context.Context, database *mongo.Database, owner, appName string) (bool, error) {
	var appMeta struct {
		CdnEdge bool `bson:"cdn_edge"`
	}

	err := database.Collection("apps_meta").FindOne(ctx, bson.M{
		"app_name": appName,
		"owner":    owner,
	}).Decode(&appMeta)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check cdn_edge flag: %w", err)
	}

	return appMeta.CdnEdge, nil
}

func InvalidateCDNResponseCache(ctx context.Context, owner, appName string, env *viper.Viper) error {
	bucketName := env.GetString("S3_BUCKET_NAME_CDN")
	if bucketName == "" {
		logrus.Debug("S3_BUCKET_NAME_CDN is not configured, skipping CDN response invalidation")
		return nil
	}

	factory := utils.NewStorageFactory(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		return fmt.Errorf("failed to create storage client for CDN response invalidation: %w", err)
	}

	prefix := fmt.Sprintf("responses/%s/%s/", owner, appName)
	logrus.Debugf("CDN response prefix %s will be invalidated.", prefix)

	objectKeys, err := storageClient.ListObjects(ctx, bucketName, prefix)
	if err != nil {
		return fmt.Errorf("failed to list CDN response objects for invalidation: %w", err)
	}

	if len(objectKeys) == 0 {
		logrus.Debug("No CDN response objects found to invalidate.")
		return nil
	}

	logrus.Debugf("Invalidating %d CDN response objects by prefix.", len(objectKeys))
	if err := storageClient.DeleteObjects(ctx, bucketName, objectKeys); err != nil {
		return fmt.Errorf("failed to invalidate CDN response objects: %w", err)
	}

	return nil
}

func InvalidatePublishCaches(
	ctx context.Context,
	params map[string]interface{},
	database *mongo.Database,
	rdb *redis.Client,
	performanceMode bool,
	owner string,
	appName string,
	env *viper.Viper,
	logPrefix string,
) {
	publishValue, hasPublishValue := params["publish"].(string)
	publishValue = strings.TrimSpace(strings.ToLower(publishValue))
	hasExplicitPublish := hasPublishValue && (publishValue == "true" || publishValue == "false")

	logrus.Debugf("%s publish=%q (explicit=%t), invalidation check for caches.", logPrefix, publishValue, hasExplicitPublish)
	if !hasExplicitPublish {
		return
	}

	if performanceMode && rdb != nil {
		if err := InvalidateCache(ctx, params, rdb); err != nil {
			logrus.Error("Error invalidating cache:", err)
		}
	}

	isCdnEdgeEnabled, err := IsCdnEdgeEnabled(ctx, database, owner, appName)
	if err != nil {
		logrus.Error("Error checking cdn_edge flag:", err)
		return
	}
	if isCdnEdgeEnabled {
		if err := InvalidateCDNResponseCache(ctx, owner, appName, env); err != nil {
			logrus.Error("Error invalidating CDN response cache:", err)
		}
	}
}

func UploadApp(c *gin.Context, repository db.AppRepository, db *mongo.Database, rdb *redis.Client, performanceMode bool) {
	// Debug received request (make sense for using only on localhost)
	// utils.DumpRequest(c)

	// Get username from JWT token
	username, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Check if the user is a team user
	teamUsersCollection := db.Collection("team_users")
	var teamUser model.TeamUser
	err = teamUsersCollection.FindOne(c.Request.Context(), bson.M{"username": username}).Decode(&teamUser)

	// Determine the actual owner to use for operations
	owner := username
	if err == nil {
		// User is a team user, use their admin as the owner
		owner = teamUser.Owner
	}

	ctxQueryMap, err := utils.ValidateParams(c, db)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Add intermediate field to ctxQueryMap if it exists in the request
	if intermediate := c.PostForm("intermediate"); intermediate != "" {
		ctxQueryMap["intermediate"] = intermediate
	}

	appName, ok := ctxQueryMap["app_name"].(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app_name is required"})
		return
	}
	if err := validateAPITokenAppScope(c, db, owner, appName); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "multipart form data is required",
		})
		return
	}

	files := form.File["file"] // Assuming the field name is "file" not "files"

	// Validate updater requirements
	if updater, exists := ctxQueryMap["updater"]; exists && updater != "" {
		updaterStr := updater.(string)

		// Validate files for updaters that require specific file types
		if err := updaters.ValidateFiles(files, updaterStr); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate parameters for updaters that require specific parameters
		if err := updaters.ValidateParams(ctxQueryMap, updaterStr); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Ingest velopack metadata from the releases.*.json feed (verbatim hashes)
		if updaterStr == velopack.UpdaterType {
			velopackMeta, err := ParseVelopackFeed(files)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			ctxQueryMap["velopack_meta"] = velopackMeta
		}

		// Ingest sparkle metadata from the appcast.*.xml feed (verbatim edSignature)
		if updaterStr == sparkle.UpdaterType {
			sparkleMeta, err := ParseSparkleAppcast(files)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			if err := sparkle.ValidateArchivesInAppcast(files, sparkleMeta); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			ctxQueryMap["sparkle_meta"] = sparkleMeta
		}
	}
	checkAppVisibility, err := utils.CheckPrivate(ctxQueryMap["app_name"].(string), db, c)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check private"})
		return
	}
	var links []string
	var extensions []string
	var fileHashes []map[string]string
	var fileLengths []int64
	for _, file := range files {
		// Calculate hashes and length before uploading to S3
		hashes, length, err := utils.CalculateFileHashes(file)
		if err != nil {
			logrus.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to calculate file hashes"})
			return
		}
		fileHashes = append(fileHashes, hashes)
		fileLengths = append(fileLengths, length)

		link, ext, err := utils.UploadToS3(ctxQueryMap, owner, file, c, viper.GetViper(), checkAppVisibility)
		if err != nil {
			logrus.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file to S3"})
			return
		}
		links = append(links, link)
		extensions = append(extensions, ext)
	}
	var results []interface{}
	for i, link := range links {
		// Add hashes and length to ctxQueryMap for this specific file
		fileCtxQuery := make(map[string]interface{})
		for k, v := range ctxQueryMap {
			fileCtxQuery[k] = v
		}
		fileCtxQuery["hashes"] = fileHashes[i]
		fileCtxQuery["length"] = fileLengths[i]
		if _, ok := ctxQueryMap["velopack_meta"]; ok {
			fileCtxQuery["file_name"] = files[i].Filename
		}
		if _, ok := ctxQueryMap["sparkle_meta"]; ok {
			fileCtxQuery["file_name"] = files[i].Filename
		}

		result, err := repository.Upload(fileCtxQuery, link, extensions[i], owner, c.Request.Context(), rdb, viper.GetViper(), checkAppVisibility)
		if err != nil {
			logrus.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, result)
	}

	InvalidatePublishCaches(
		c.Request.Context(),
		ctxQueryMap,
		db,
		rdb,
		performanceMode,
		owner,
		appName,
		viper.GetViper(),
		"Uploaded app",
	)

	// An upload adds one artifact for one (channel, platform, arch), so only that
	// tuple's feed changes — regenerate just it, not every feed of the app.
	uploadTuples := info.TupleFromContext(ctxQueryMap)

	if updater, _ := ctxQueryMap["updater"].(string); updater == velopack.UpdaterType {
		CopyVelopackInstallersToDefault(c.Request.Context(), ctxQueryMap, owner, files, checkAppVisibility, viper.GetViper())
		info.MaterializeVelopackForTuplesOrFull(c.Request.Context(), db, viper.GetViper(), owner, appName, uploadTuples)
	}

	if updater, _ := ctxQueryMap["updater"].(string); updater == sparkle.UpdaterType {
		info.MaterializeSparkleForTuplesOrFull(c.Request.Context(), db, viper.GetViper(), owner, appName, uploadTuples)
	}

	if len(results) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no results found. Please check your files."})
		return
	}

	if appData, ok := results[0].(model.SpecificApp); ok {
		c.JSON(http.StatusOK, gin.H{"uploadResult.Uploaded": appData.ID.Hex()})

		go func() {
			if viper.GetBool("SLACK_ENABLE") {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				humanReadableData, err := repository.FetchAppByID(appData.ID, ctx)
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
					viper.GetViper(),
					rdb,
					slackData.Published,
					slackData.Critical,
				)
			}
		}()
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid result type"})
	}
}

func validateAPITokenAppScope(c *gin.Context, database *mongo.Database, owner, appName string) error {
	isAPIToken, exists := c.Get("is_api_token")
	if !exists {
		return nil
	}

	apiTokenBool, ok := isAPIToken.(bool)
	if !ok || !apiTokenBool {
		return nil
	}

	allowedAppsRaw, exists := c.Get("allowed_apps")
	if !exists {
		return fmt.Errorf("api token scope is missing")
	}

	allowedApps, ok := allowedAppsRaw.([]string)
	if !ok || len(allowedApps) == 0 {
		return fmt.Errorf("api token has no allowed applications")
	}

	allowedSet := make(map[string]struct{}, len(allowedApps))
	for _, appID := range allowedApps {
		allowedSet[appID] = struct{}{}
	}

	var appMeta struct {
		ID primitive.ObjectID `bson:"_id"`
	}

	metaCollection := database.Collection("apps_meta")
	if err := metaCollection.FindOne(
		c.Request.Context(),
		bson.M{"app_name": appName, "owner": owner},
	).Decode(&appMeta); err != nil {
		return fmt.Errorf("app_name not found in apps_meta collection or you don't have permission to access it")
	}

	if _, hasAccess := allowedSet[appMeta.ID.Hex()]; !hasAccess {
		return fmt.Errorf("api token has no access to this app")
	}

	return nil
}
