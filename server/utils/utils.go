package utils

import (
	"encoding/json"
	"errors"
	"faynoSync/server/model"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Configuration struct {
	Database DatabaseSetting
	Server   ServerSettings
}
type DatabaseSetting struct {
	Url        string
	DbName     string
	Collection string
}

type ServerSettings struct {
	Port string
}

// GenerateJWT generates a new JWT token for the given username
func GenerateJWT(username string) (string, error) {
	env := viper.GetViper()
	// Define JWT claims
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(), // Token expiration time (24 hours)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(env.GetString("JWT_SECRET")))
}

func extractParamsFromPost(c *gin.Context) (map[string]interface{}, error) {
	jsonData := c.PostForm("data")
	if jsonData == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No JSON data provided"})
		return nil, errors.New("no JSON data provided")
	}
	logrus.Debug("JSON data: ", jsonData)
	var upReq model.UpRequest
	if err := json.Unmarshal([]byte(jsonData), &upReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return nil, errors.New("invalid JSON data")
	}

	upReq.Version = strings.ReplaceAll(upReq.Version, "-", ".")

	publishStr := strconv.FormatBool(upReq.Publish)
	criticalStr := strconv.FormatBool(upReq.Critical)
	return map[string]interface{}{
		"id":        upReq.Id,
		"app_name":  upReq.AppName,
		"version":   upReq.Version,
		"channel":   upReq.Channel,
		"publish":   publishStr,
		"critical":  criticalStr,
		"platform":  upReq.Platform,
		"arch":      upReq.Arch,
		"changelog": upReq.Changelog,
	}, nil
}

func extractParamsFromGetOrDelete(c *gin.Context) (map[string]interface{}, error) {
	version := c.Query("version")
	version = strings.ReplaceAll(version, "-", ".")
	return map[string]interface{}{
		"app_name": c.Query("app_name"),
		"version":  version,
		"channel":  c.Query("channel"),
		"publish":  c.Query("publish"),
		"platform": c.Query("platform"),
		"arch":     c.Query("arch"),
	}, nil
}

func GetStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""
}

func GetBoolParam(param interface{}) bool {
	switch v := param.(type) {
	case bool:
		return v
	case string:
		return v == "true"
	default:
		return false
	}
}

func CountUrls(downloadUrls map[string]map[string]map[string]map[string]map[string]string) (int, string) {
	count := 0
	var singleUrl string
	for _, platformMap := range downloadUrls {
		for _, archMap := range platformMap {
			for _, packageMap := range archMap {
				for _, urlMap := range packageMap {
					if url, exists := urlMap["url"]; exists {
						count++
						singleUrl = url
					}
				}
			}
		}
	}

	return count, singleUrl
}
