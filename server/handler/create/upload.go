package create

import (
	db "faynoSync/mongod"
	"faynoSync/server/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func UploadApp(c *gin.Context, repository db.AppRepository, db *mongo.Database) {
	ctxQueryMap, err := utils.ValidateParams(c, db)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

	var links []string
	var extensions []string
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

	var results []interface{}
	for i, link := range links {
		result, err := repository.Upload(ctxQueryMap, link, extensions[i], c.Request.Context())
		if err != nil {
			logrus.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, result)
	}

	c.JSON(http.StatusOK, gin.H{"uploadResult.Uploaded": results[0]})
}

func UpdateApp(c *gin.Context, repository db.AppRepository, db *mongo.Database) {
	ctxQueryMap, err := utils.ValidateParams(c, db)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Convert string to ObjectID
	objID, err := primitive.ObjectIDFromHex(c.Query("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
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
			result, err = repository.Update(objID, ctxQueryMap, link, extensions[i], c.Request.Context())
			if err != nil {
				logrus.Error(err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}
	} else {
		// Handle the case when there are no files to upload
		result, err = repository.Update(objID, ctxQueryMap, "", "", c.Request.Context())
		if err != nil {
			logrus.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"updatedResult.Updated": result})
}
