package delete

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/utils"
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

func DeleteSpecificVersionOfApp(c *gin.Context, repository db.AppRepository, db *mongo.Database, rdb *redis.Client) {
	env := viper.GetViper()
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()
	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var slackAppName, slackVersion string
	if viper.GetBool("SLACK_ENABLE") && rdb != nil {
		humanReadableData, fetchErr := repository.FetchAppByID(objID, ctx)
		if fetchErr != nil {
			logrus.Error("Error fetching app data before version deletion for Slack cleanup: ", fetchErr)
		} else if len(humanReadableData) > 0 {
			slackAppName = humanReadableData[0].AppName
			slackVersion = humanReadableData[0].Version
		}
	}

	//request on repository
	links, result, appName, err := repository.DeleteSpecificVersionOfApp(objID, owner, ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete specific version of app", "details": err.Error()})
		return
	}

	checkAppVisibility, err := utils.CheckPrivate(appName, db, c)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check private"})
		return
	}

	for _, link := range links {
		subLink, err := utils.ExtractS3Key(link, checkAppVisibility, env)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		utils.DeleteFromS3(subLink, c, viper.GetViper(), checkAppVisibility)
	}

	if slackAppName != "" && slackVersion != "" {
		if err := utils.DeleteSlackNotificationState(slackAppName, slackVersion, rdb); err != nil {
			logrus.Error("Error cleaning Slack notification state after version deletion: ", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"deleteSpecificAppResult.DeletedCount": result})
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

	for _, link := range links {
		subLink, err := utils.ExtractS3Key(link, checkAppVisibility, env)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		utils.DeleteFromS3(subLink, c, viper.GetViper(), checkAppVisibility)
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

	c.JSON(http.StatusOK, gin.H{"deleteSpecificArtifactResult": result})
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
