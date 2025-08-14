package update

import (
	"context"
	"encoding/json"
	db "faynoSync/mongod"
	"faynoSync/server/handler/create"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"faynoSync/server/utils/updaters"
	"net/http"
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

func UpdateItem(c *gin.Context, repository db.AppRepository, itemType string) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Get username from JWT token
	owner, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var result interface{}
	var resultError error
	switch itemType {
	case "channel":
		var req model.UpdateChannelRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		if err := utils.ValidateItemName(itemType, req.ChannelName); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		objectID, err := primitive.ObjectIDFromHex(req.ID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
			return
		}
		result, resultError = repository.UpdateChannel(objectID, req.ChannelName, owner, ctx)
	case "platform":
		var req model.UpdatePlatformRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		if err := utils.ValidateItemName(itemType, req.PlatformName); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Validate updaters
		if err := updaters.ValidateUpdaters(req.Updaters); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		objectID, err := primitive.ObjectIDFromHex(req.ID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
			return
		}
		result, resultError = repository.UpdatePlatform(objectID, req.PlatformName, req.Updaters, owner, ctx)
	case "arch":
		var req model.UpdateArchRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		if err := utils.ValidateItemName(itemType, req.ArchID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		objectID, err := primitive.ObjectIDFromHex(req.ID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
			return
		}
		result, resultError = repository.UpdateArch(objectID, req.ArchID, owner, ctx)
	case "app":
		jsonData := c.PostForm("data")
		if jsonData == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No JSON data provided"})
			return
		}

		var params map[string]string
		if err := json.Unmarshal([]byte(jsonData), &params); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
			return
		}

		id, idExists := params["id"]
		if !idExists || id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
			return
		}

		paramName := itemType
		paramValue, exists := params[paramName]
		if !exists || paramValue == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": paramName + " is required"})
			return
		}
		objectID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
			return
		}
		var logoLink string
		form, _ := c.MultipartForm()
		if form != nil {
			files := form.File["file"]
			if len(files) > 0 {
				file := files[0]
				logoLink, err = utils.UploadLogo(paramValue, owner, file, c, viper.GetViper())
				if err != nil {
					logrus.Error(err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload logo to S3"})
					return
				}
			}
		}
		description := params["description"]
		result, resultError = repository.UpdateApp(objectID, paramValue, logoLink, description, owner, ctx)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item type"})
		return
	}
	if resultError != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": resultError.Error()})
		return
	}
	var tag language.Tag
	titleCase := cases.Title(tag)

	capitalizedItemType := titleCase.String(itemType)
	c.JSON(http.StatusOK, gin.H{"update" + capitalizedItemType + "Result.Updated": result})
}

func UpdateChannel(c *gin.Context, repository db.AppRepository) {
	UpdateItem(c, repository, "channel")
}

func UpdatePlatform(c *gin.Context, repository db.AppRepository) {
	UpdateItem(c, repository, "platform")
}

func UpdateArch(c *gin.Context, repository db.AppRepository) {
	UpdateItem(c, repository, "arch")
}

func UpdateApp(c *gin.Context, repository db.AppRepository) {
	UpdateItem(c, repository, "app")
}

func UpdateSpecificApp(c *gin.Context, repository db.AppRepository, db *mongo.Database, rdb *redis.Client, performanceMode bool) {
	ctxQueryMap, err := utils.ValidateUpdateParams(c, db)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Add intermediate field to ctxQueryMap if it exists in the request
	if intermediate := c.PostForm("intermediate"); intermediate != "" {
		ctxQueryMap["intermediate"] = intermediate
	}

	// Get username from JWT token
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

	form, _ := c.MultipartForm()
	checkAppVisibility, err := utils.CheckPrivate(ctxQueryMap["app_name"].(string), db, c)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check private"})
		return
	}
	var links []string
	var extensions []string
	var result bool
	if form != nil {
		files := form.File["file"] // Assuming the field name is "file" not "files"

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
	}

	if len(links) > 0 {
		for i, link := range links {
			result, err = repository.UpdateSpecificApp(objID, owner, ctxQueryMap, link, extensions[i], c.Request.Context())
			if err != nil {
				logrus.Errorf("Error updating link %d: %v", i, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}
	} else {
		// Handle the case when there are no files to upload
		result, err = repository.UpdateSpecificApp(objID, owner, ctxQueryMap, "", "", c.Request.Context())
		if err != nil {
			logrus.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	if performanceMode && rdb != nil {
		publish := utils.GetBoolParam(ctxQueryMap["publish"])
		logrus.Debugf("Updating app has publish: %t, invalidation of redis cache is starting.", publish)

		if publish {
			if err := create.InvalidateCache(c.Request.Context(), ctxQueryMap, rdb); err != nil {
				logrus.Error("Error invalidating cache:", err)
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"updatedResult.Updated": result})
}
