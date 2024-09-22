package create

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/utils"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
)

func InvalidateCache(ctx context.Context, params map[string]interface{}, rdb *redis.Client) error {

	appName, _ := params["app_name"].(string)
	channel, _ := params["channel"].(string)
	platform, _ := params["platform"].(string)
	arch, _ := params["arch"].(string)

	pattern := fmt.Sprintf("app_name=%s&version=*&channel=%s&platform=%s&arch=%s",
		appName, channel, platform, arch)
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
	utils.DumpRequest(c)

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
	c.JSON(http.StatusOK, gin.H{"uploadResult.Uploaded": results[0]})
}
