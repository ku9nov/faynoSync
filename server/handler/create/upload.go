package create

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"faynoSync/server/utils/updaters"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

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
	}
	checkAppVisibility, err := utils.CheckPrivate(ctxQueryMap["app_name"].(string), db, c)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check private"})
		return
	}
	var links []string
	var extensions []string
	for _, file := range files {
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
		result, err := repository.Upload(ctxQueryMap, link, extensions[i], owner, c.Request.Context())
		if err != nil {
			logrus.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, result)
	}

	if performanceMode && rdb != nil {

		publish := utils.GetBoolParam(ctxQueryMap["publish"])

		logrus.Debugf("Uploaded app has publish: %t, invalidation of redis cache is starting.", publish)

		if publish {
			if err := InvalidateCache(c.Request.Context(), ctxQueryMap, rdb); err != nil {
				logrus.Error("Error invalidating cache:", err)
			}
		}
	}

	if len(results) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no results found. Please check your files."})
		return
	}

	if appData, ok := results[0].(model.SpecificApp); ok {
		c.JSON(http.StatusOK, gin.H{"uploadResult.Uploaded": appData.ID.Hex()})
		artifacts := utils.ExtractArtifactLinks(results)
		changelog := utils.ExtractChangelog(results)

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

				var platforms, arches, pkgs []string
				for _, artifact := range slackData.Artifacts {
					platforms = append(platforms, artifact.Platform)
					arches = append(arches, artifact.Arch)
					pkgs = append(pkgs, artifact.Package)
				}
				utils.SendSlackNotification(
					slackData.AppName,
					slackData.Channel,
					slackData.Version,
					platforms,
					arches,
					artifacts,
					changelog,
					pkgs,
					viper.GetViper(),
					slackData.Published,
					slackData.Critical,
				)
			}
		}()
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid result type"})
	}
}
