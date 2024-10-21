package info

import (
	"context"
	"encoding/json"
	db "faynoSync/mongod"
	"faynoSync/server/utils"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

func CreateCacheKey(params map[string]interface{}) string {
	return fmt.Sprintf("app_name=%s&version=%s&channel=%s&platform=%s&arch=%s",
		params["app_name"], params["version"], params["channel"], params["platform"], params["arch"])
}

func cacheResponse(ctx context.Context, rdb *redis.Client, cacheKey string, response gin.H) {
	cachedData, err := json.Marshal(response)
	if err != nil {
		logrus.Error("Error marshalling response:", err)
		return
	}
	err = rdb.Set(ctx, cacheKey, cachedData, time.Hour*24).Err()
	if err != nil {
		logrus.Error("Error setting data to Redis:", err)
	} else {
		logrus.Debugln("Successfully set data to cache:", cachedData)
	}
}

func FindLatestVersion(c *gin.Context, repository db.AppRepository, db *mongo.Database, rdb *redis.Client, performanceMode bool) {
	validatedParams, err := utils.ValidateParamsLatest(c, db)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logrus.Debugf("Validated parameters: %+v", validatedParams)
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	cacheKey := CreateCacheKey(validatedParams)
	logrus.Debugf("Generated cache key: %s", cacheKey)
	// Check Redis only if PERFORMANCE_MODE is true and Redis client is not nil
	if performanceMode && rdb != nil {
		cachedResponse, err := rdb.Get(ctx, cacheKey).Result()
		if err == nil {
			// If cache exists, return the cached response
			var cachedData map[string]interface{}
			if json.Unmarshal([]byte(cachedResponse), &cachedData) == nil {
				logrus.Debugln("Return cached data: ", cachedData)
				c.JSON(http.StatusOK, cachedData)
				return
			}
		}
	}

	// Request on repository
	checkResult, err := repository.CheckLatestVersion(validatedParams["app_name"].(string), validatedParams["version"].(string), validatedParams["channel"].(string), validatedParams["platform"].(string), validatedParams["arch"].(string), ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !checkResult.Found {
		if len(checkResult.Artifacts) == 0 {
			c.JSON(http.StatusOK, gin.H{"update_available": false, "error": "Not found"})
		} else {
			logrus.Infoln(checkResult)
			response := gin.H{"update_available": false}
			for _, artifact := range checkResult.Artifacts {
				if artifact.Package != "" && artifact.Link != "" {
					key := "update_url_" + strings.TrimPrefix(artifact.Package, ".")
					response[key] = artifact.Link
				}
			}
			if performanceMode && rdb != nil {
				cacheResponse(ctx, rdb, cacheKey, response)
			}
			c.JSON(http.StatusOK, response)
		}

		return
	}
	logrus.Debug("Check latest version response: ", checkResult)
	response := gin.H{"update_available": true, "critical": checkResult.Critical}

	// Add update URLs to the response
	for _, artifact := range checkResult.Artifacts {
		if artifact.Package != "" && artifact.Link != "" {
			key := "update_url_" + strings.TrimPrefix(artifact.Package, ".")
			response[key] = artifact.Link
		}
	}
	// Add changelog to the response last
	if len(checkResult.Changelog) > 0 {
		var changelogBuilder strings.Builder
		for _, changelog := range checkResult.Changelog {
			if changelog.Changes != "" {
				changelogBuilder.WriteString(changelog.Changes)
				changelogBuilder.WriteString("\n")
			}
		}
		// Only add to response if there was any changelog to include
		if changelogBuilder.Len() > 0 {
			response["changelog"] = changelogBuilder.String()
		}
	}
	if performanceMode && rdb != nil {
		cacheResponse(ctx, rdb, cacheKey, response)
	}
	c.JSON(http.StatusOK, response)
}

func FetchLatestVersionOfApp(c *gin.Context, repository db.AppRepository, rdb *redis.Client, performanceMode bool) {
	params := map[string]interface{}{
		"app_name": c.Query("app_name"),
		"channel":  c.Query("channel"),
		"platform": c.Query("platform"),
		"arch":     c.Query("arch"),
	}
	ctx, ctxErr := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer ctxErr()

	cacheKey := CreateCacheKey(params)
	logrus.Debugf("Generated cache key: %s", cacheKey)

	if performanceMode && rdb != nil {
		cachedResponse, err := rdb.Get(ctx, cacheKey).Result()
		if err == nil {
			var cachedData map[string]interface{}
			if json.Unmarshal([]byte(cachedResponse), &cachedData) == nil {
				logrus.Debugln("Returning cached data: ", cachedData)
				c.JSON(http.StatusOK, cachedData)
				return
			}
		}
	}

	checkResult, err := repository.FetchLatestVersionOfApp(params["app_name"].(string), params["channel"].(string), ctx)
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	jsonData, err := json.MarshalIndent(checkResult, "", "  ")
	if err != nil {
		logrus.Errorf("Error marshaling checkResult: %v", err)
	} else {
		logrus.Debugf("Fetched latest version response: %s", string(jsonData))
	}

	downloadUrls := make(map[string]string)

	if len(checkResult) > 0 {
		latestApp := checkResult[0]
		for _, artifact := range latestApp.Artifacts {

			if params["channel"] != "" && params["channel"] != latestApp.Channel {
				continue
			}
			if params["platform"] != "" && params["platform"] != artifact.Platform {
				continue
			}
			if params["arch"] != "" && params["arch"] != artifact.Arch {
				continue
			}

			urlKeyParts := []string{"download_url"}

			if latestApp.Channel != "" {
				urlKeyParts = append(urlKeyParts, latestApp.Channel)
			}
			if artifact.Platform != "" {
				urlKeyParts = append(urlKeyParts, artifact.Platform)
			}
			if artifact.Arch != "" {
				urlKeyParts = append(urlKeyParts, artifact.Arch)
			}
			if artifact.Package != "" {
				urlKeyParts = append(urlKeyParts, strings.TrimPrefix(artifact.Package, "."))
			}

			urlKey := strings.Join(urlKeyParts, "_")
			downloadUrls[urlKey] = artifact.Link
		}
	}
	if len(downloadUrls) == 0 {
		logrus.Warnf("No results found for parameters: %v", params)
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching data found for the provided parameters"})
		return
	}

	if len(downloadUrls) == 1 {
		for _, url := range downloadUrls {
			logrus.Debugf("Redirecting to the single download URL: %v", url)
			c.Redirect(http.StatusFound, url)
			return
		}
	}

	logrus.Debugf("Generated download URLs: %v", downloadUrls)

	c.JSON(http.StatusOK, downloadUrls)

	if performanceMode && rdb != nil {
		jsonResponse, _ := json.Marshal(downloadUrls)
		rdb.Set(ctx, cacheKey, jsonResponse, 0)
	}
}
