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

// Just for changelog feature
// type UploadRequest struct {
// 	AppName   string `json:"app_name"`
// 	Version   string `json:"version"`
// 	Channel   string `json:"channel"`
// 	Publish   bool   `json:"publish"`
// 	Platform  string `json:"platform"`
// 	Arch      string `json:"arch"`
// 	Changelog string `json:"changelog"`
// }

// func UploadApp(c *gin.Context, repository db.AppRepository, db *mongo.Database) {
// 	requestDump, err := httputil.DumpRequest(c.Request, true)
// 	if err != nil {
// 		fmt.Println("Error dumping request:", err)
// 	}
// 	fmt.Println("Request data:", string(requestDump))

// 	jsonData := c.PostForm("data")
// 	fmt.Println("Received JSON data:", jsonData)

// 	if jsonData == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "No JSON data provided"})
// 		return
// 	}

// 	var uploadReq UploadRequest
// 	if err := json.Unmarshal([]byte(jsonData), &uploadReq); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		fmt.Println("Error unmarshaling JSON:", err)
// 		return
// 	}

// 	publishStr := strconv.FormatBool(uploadReq.Publish)
// 	ctxQueryMap := map[string]interface{}{
// 		"app_name":  uploadReq.AppName,
// 		"version":   uploadReq.Version,
// 		"channel":   uploadReq.Channel,
// 		"publish":   publishStr,
// 		"platform":  uploadReq.Platform,
// 		"arch":      uploadReq.Arch,
// 		"changelog": uploadReq.Changelog,
// 	}

// 	// Обробка файлів
// 	form, err := c.MultipartForm()
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{
// 			"error": "multipart form data is required",
// 		})
// 		return
// 	}

// 	files := form.File["file"] // Assuming the field name is "file" not "files"

// 	var links []string
// 	var extensions []string
// 	for _, file := range files {
// 		link, ext, err := utils.UploadToS3(ctxQueryMap, file, c, viper.GetViper())
// 		if err != nil {
// 			logrus.Error(err)
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file to S3"})
// 			return
// 		}
// 		links = append(links, link)
// 		extensions = append(extensions, ext)
// 	}
// 	var results []interface{}
// 	for i, link := range links {
// 		result, err := repository.Upload(ctxQueryMap, link, extensions[i], c.Request.Context())
// 		if err != nil {
// 			logrus.Error(err)
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 			return
// 		}
// 		results = append(results, result)
// 	}

// 	c.JSON(http.StatusOK, gin.H{"uploadResult.Uploaded": results[0]})
// }

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
