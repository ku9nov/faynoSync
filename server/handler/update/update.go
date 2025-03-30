package update

import (
	"context"
	"encoding/json"
	db "faynoSync/mongod"
	"faynoSync/server/handler/create"
	"faynoSync/server/utils"
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
	if err := utils.ValidateItemName(itemType, paramValue); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var result interface{}
	var err error
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
		return
	}
	switch itemType {
	case "channel":
		result, err = repository.UpdateChannel(objectID, paramValue, ctx)
	case "platform":
		result, err = repository.UpdatePlatform(objectID, paramValue, ctx)
	case "arch":
		result, err = repository.UpdateArch(objectID, paramValue, ctx)
	case "app":
		var logoLink string
		form, _ := c.MultipartForm()
		if form != nil {
			files := form.File["file"]
			if len(files) > 0 {
				file := files[0]
				logoLink, err = utils.UploadLogo(paramValue, file, c, viper.GetViper())
				if err != nil {
					logrus.Error(err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload logo to S3"})
					return
				}
			}
		}
		description := params["description"]
		result, err = repository.UpdateApp(objectID, paramValue, logoLink, description, ctx)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item type"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(ctxQueryMap["id"].(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	delete(ctxQueryMap, "id")

	form, _ := c.MultipartForm()
	var links []string
	var extensions []string
	var result bool
	if form != nil {
		files := form.File["file"] // Assuming the field name is "file" not "files"

		for _, file := range files {
			link, ext, err := utils.UploadToS3(ctxQueryMap, file, c, viper.GetViper())
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
			result, err = repository.UpdateSpecificApp(objID, ctxQueryMap, link, extensions[i], c.Request.Context())
			if err != nil {
				logrus.Errorf("Error updating link %d: %v", i, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}
	} else {
		// Handle the case when there are no files to upload
		result, err = repository.UpdateSpecificApp(objID, ctxQueryMap, "", "", c.Request.Context())
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
