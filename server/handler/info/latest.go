package info

import (
	"context"
	"encoding/json"
	db "faynoSync/mongod"
	"faynoSync/server/utils"
	"faynoSync/server/utils/updaters"
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
	var httpStatus int
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
	checkResult, err := repository.CheckLatestVersion(validatedParams["app_name"].(string), validatedParams["version"].(string), validatedParams["channel"].(string), validatedParams["platform"].(string), validatedParams["arch"].(string), ctx, validatedParams["owner"].(string))
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Log stats for the request
	deviceID := c.GetHeader("X-Device-ID")
	logrus.Debugf("X-Device-ID: %s", deviceID)
	// Update stats with actual update status
	logStatsToRedis(ctx, rdb, validatedParams, checkResult.Found, deviceID)

	if !checkResult.Found {
		if len(checkResult.Artifacts) == 0 {
			c.JSON(http.StatusOK, gin.H{"update_available": false, "error": "Not found"})
		} else {
			logrus.Infoln(checkResult)
			response := gin.H{"update_available": false}
			for _, artifact := range checkResult.Artifacts {
				var key string
				if artifact.Package == "" {
					key = "update_url"
				} else if artifact.Package != "" && artifact.Link != "" {
					key = "update_url_" + strings.TrimPrefix(artifact.Package, ".")
				}
				if artifact.Link != "" && strings.Contains(artifact.Link, validatedParams["platform"].(string)) && strings.Contains(artifact.Link, validatedParams["arch"].(string)) {
					response[key] = artifact.Link
				}
			}
			if performanceMode && rdb != nil {
				cacheResponse(ctx, rdb, cacheKey, response)
			}
			response, httpStatus = updaters.BuildResponse(response, checkResult.Found, validatedParams["updater"].(string))
			c.JSON(httpStatus, response)
		}
		return
	}
	logrus.Debug("Check latest version response: ", checkResult)
	response := gin.H{"update_available": true, "critical": checkResult.Critical}

	// Add is_intermediate_required to response if it's true
	if checkResult.IsRequiredIntermediate {
		response["is_intermediate_required"] = true
	}

	// Add update URLs to the response
	for _, artifact := range checkResult.Artifacts {
		var key string
		if artifact.Package == "" {
			key = "update_url"
		} else if artifact.Package != "" && artifact.Link != "" {
			key = "update_url_" + strings.TrimPrefix(artifact.Package, ".")
		}
		if artifact.Link != "" && strings.Contains(artifact.Link, validatedParams["platform"].(string)) && strings.Contains(artifact.Link, validatedParams["arch"].(string)) {
			logrus.Debugf("Adding link for key %s: %s", key, artifact.Link)
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
	response, httpStatus = updaters.BuildResponse(response, checkResult.Found, validatedParams["updater"].(string))

	if httpStatus == 302 {
		if redirectURL, exists := response["url"]; exists {
			c.Redirect(http.StatusFound, redirectURL.(string))
			return
		}
	}

	c.JSON(httpStatus, response)
}

func FetchLatestVersionOfApp(c *gin.Context, repository db.AppRepository, rdb *redis.Client, performanceMode bool) {
	if c.Query("app_name") == "" || c.Query("channel") == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Parameters 'app_name' and 'channel' are required",
		})
		return
	}
	params := map[string]interface{}{
		"app_name": c.Query("app_name"),
		"channel":  c.Query("channel"),
		"platform": c.Query("platform"),
		"arch":     c.Query("arch"),
		"package":  c.Query("package"),
		"owner":    c.Query("owner"),
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

	checkResult, err := repository.FetchLatestVersionOfApp(params["app_name"].(string), params["channel"].(string), ctx, params["owner"].(string))
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

	downloadUrls := make(map[string]map[string]map[string]map[string]map[string]string)

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

			packageType := strings.TrimPrefix(artifact.Package, ".")
			if packageType == "" {
				packageType = "no-extension"
			}

			if params["package"] != "" && params["package"] != packageType {
				continue
			}

			if _, exists := downloadUrls[latestApp.Channel]; !exists {
				downloadUrls[latestApp.Channel] = make(map[string]map[string]map[string]map[string]string)
			}

			if _, exists := downloadUrls[latestApp.Channel][artifact.Platform]; !exists {
				downloadUrls[latestApp.Channel][artifact.Platform] = make(map[string]map[string]map[string]string)
			}

			if _, exists := downloadUrls[latestApp.Channel][artifact.Platform][artifact.Arch]; !exists {
				downloadUrls[latestApp.Channel][artifact.Platform][artifact.Arch] = make(map[string]map[string]string)
			}

			downloadUrls[latestApp.Channel][artifact.Platform][artifact.Arch][packageType] = map[string]string{
				"url": artifact.Link,
			}
		}
	}

	if len(downloadUrls) == 0 {
		logrus.Warnf("No results found for parameters: %v", params)
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching data found for the provided parameters"})
		return
	}

	urlCount, singleUrl := utils.CountUrls(downloadUrls)

	if urlCount == 1 {
		logrus.Debugf("Redirecting to the single download URL: %v", singleUrl)
		c.Redirect(http.StatusFound, singleUrl)
		return
	}

	logrus.Debugf("Generated download URLs: %v", downloadUrls)

	c.JSON(http.StatusOK, downloadUrls)

	if performanceMode && rdb != nil {
		jsonResponse, _ := json.Marshal(downloadUrls)
		rdb.Set(ctx, cacheKey, jsonResponse, 0)
	}
}

// trackClientTelemetry handles analytics collection for version check requests using Redis Sets
func trackClientTelemetry(ctx context.Context, rdb *redis.Client, params map[string]interface{}, hasUpdate bool, deviceID string) {
	if rdb == nil || deviceID == "" {
		logrus.Debug("Redis client is not set or deviceID is empty, skipping analytics collection")
		return
	}

	now := time.Now().UTC()
	dateStr := now.Format("2006-01-02")

	owner := params["owner"].(string)
	appName := params["app_name"].(string)
	version := params["version"].(string)
	platform := params["platform"].(string)
	arch := params["arch"].(string)
	channel := params["channel"].(string)

	logrus.Debugf("Collecting analytics for app: %s, owner: %s, date: %s", appName, owner, dateStr)

	baseKey := fmt.Sprintf("stats:%s:%s", owner, appName)

	requestsKey := fmt.Sprintf("%s:requests:%s", baseKey, dateStr)
	rdb.Incr(ctx, requestsKey)
	rdb.Expire(ctx, requestsKey, time.Hour*24*30)

	clientsKey := fmt.Sprintf("%s:unique_clients:%s", baseKey, dateStr)
	rdb.SAdd(ctx, clientsKey, deviceID)
	rdb.Expire(ctx, clientsKey, time.Hour*24*30)

	if channel != "" {
		channelKey := fmt.Sprintf("%s:channels:%s:%s", baseKey, dateStr, channel)
		rdb.SAdd(ctx, channelKey, deviceID)
		rdb.Expire(ctx, channelKey, time.Hour*24*30)
	}

	if platform != "" {
		platformKey := fmt.Sprintf("%s:platforms:%s:%s", baseKey, dateStr, platform)
		rdb.SAdd(ctx, platformKey, deviceID)
		rdb.Expire(ctx, platformKey, time.Hour*24*30)
	}

	if arch != "" {
		archKey := fmt.Sprintf("%s:architectures:%s:%s", baseKey, dateStr, arch)
		rdb.SAdd(ctx, archKey, deviceID)
		rdb.Expire(ctx, archKey, time.Hour*24*30)
	}

	if version != "" {
		// Get known versions for this app
		knownVersionsKey := fmt.Sprintf("%s:known_versions", baseKey)

		// Add current version to known versions set
		rdb.SAdd(ctx, knownVersionsKey, version)
		rdb.Expire(ctx, knownVersionsKey, time.Hour*24*30)

		// Get all known versions
		knownVersions, err := rdb.SMembers(ctx, knownVersionsKey).Result()
		if err != nil {
			logrus.Errorf("Error getting known versions: %v", err)
			return
		}

		// Remove device from all version sets for this day
		for _, knownVersion := range knownVersions {
			if knownVersion != version {
				oldVersionKey := fmt.Sprintf("%s:version_usage:%s:%s", baseKey, dateStr, knownVersion)
				rdb.SRem(ctx, oldVersionKey, deviceID)
				rdb.Expire(ctx, oldVersionKey, time.Hour*24*30)
			}
		}

		// Add device to current version set
		versionKey := fmt.Sprintf("%s:version_usage:%s:%s", baseKey, dateStr, version)
		rdb.SAdd(ctx, versionKey, deviceID)
		rdb.Expire(ctx, versionKey, time.Hour*24*30)

		// Track if client is using latest version
		if hasUpdate {
			// Remove from latest version set if present
			latestVersionKey := fmt.Sprintf("%s:clients_using_latest_version:%s", baseKey, dateStr)
			rdb.SRem(ctx, latestVersionKey, deviceID)
			rdb.Expire(ctx, latestVersionKey, time.Hour*24*30)

			// Add to outdated set
			outdatedKey := fmt.Sprintf("%s:clients_outdated:%s", baseKey, dateStr)
			rdb.SAdd(ctx, outdatedKey, deviceID)
			rdb.Expire(ctx, outdatedKey, time.Hour*24*30)
		} else {
			// Remove from outdated set if present
			outdatedKey := fmt.Sprintf("%s:clients_outdated:%s", baseKey, dateStr)
			rdb.SRem(ctx, outdatedKey, deviceID)
			rdb.Expire(ctx, outdatedKey, time.Hour*24*30)

			// Add to latest version set
			latestVersionKey := fmt.Sprintf("%s:clients_using_latest_version:%s", baseKey, dateStr)
			rdb.SAdd(ctx, latestVersionKey, deviceID)
			rdb.Expire(ctx, latestVersionKey, time.Hour*24*30)
		}
	}
}

func logStatsToRedis(ctx context.Context, rdb *redis.Client, params map[string]interface{}, hasUpdate bool, deviceID string) {
	trackClientTelemetry(ctx, rdb, params, hasUpdate, deviceID)
}
