package delete

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func DeleteSpecificVersionOfApp(c *gin.Context, repository db.AppRepository, db *mongo.Database) {
	env := viper.GetViper()
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//request on repository
	links, result, appName, err := repository.DeleteSpecificVersionOfApp(objID, ctx)
	if err != nil {
		logrus.Error(err)
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
	c.JSON(http.StatusOK, gin.H{"deleteSpecificAppResult.DeletedCount": result})
}

func DeleteSpecificArtifactOfApp(c *gin.Context, repository db.AppRepository, db *mongo.Database) {
	env := viper.GetViper()
	ctxQueryMap, err := utils.ValidateUpdateParams(c, db)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(ctxQueryMap["id"].(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	delete(ctxQueryMap, "id")
	links, result, err := repository.DeleteSpecificArtifactOfApp(objID, ctxQueryMap, c.Request.Context())
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
	var result interface{}
	switch itemType {
	case "channel":
		result, err = repository.DeleteChannel(objID, ctx)
	case "platform":
		result, err = repository.DeletePlatform(objID, ctx)
	case "arch":
		result, err = repository.DeleteArch(objID, ctx)
	case "app":
		result, err = repository.DeleteApp(objID, ctx)
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
