package utils

import (
	"encoding/json"
	"errors"
	"faynoSync/server/model"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
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

// ValidateJWT parses and validates the JWT token
func ValidateJWT(tokenString string) (*jwt.Token, error) {
	env := viper.GetViper()
	// Parse the token with the secret key
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrInvalidKey
		}
		return []byte(env.GetString("JWT_SECRET")), nil
	})
}

func GetStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""
}

func ValidateParamsLatest(c *gin.Context, database *mongo.Database) (map[string]interface{}, error) {
	ctxQueryMap := map[string]interface{}{
		"app_name": c.Query("app_name"),
		"version":  c.Query("version"),
		"channel":  c.Query("channel"),
		"publish":  c.Query("publish"),
		"platform": c.Query("platform"),
		"arch":     c.Query("arch"),
	}

	if !IsValidAppName(ctxQueryMap["app_name"].(string)) {
		return nil, errors.New("invalid app_name parameter")
	}
	if !IsValidVersion(ctxQueryMap["version"].(string)) {
		return nil, errors.New("invalid version parameter")
	}
	if !IsValidChannelName(ctxQueryMap["channel"].(string)) {
		return nil, errors.New("invalid channel parameter")
	}

	if !IsValidPlatformName(ctxQueryMap["platform"].(string)) {
		return nil, errors.New("invalid platform parameter")
	}

	if !IsValidArchName(ctxQueryMap["arch"].(string)) {
		return nil, errors.New("invalid platform parameter")
	}

	errChannels := CheckChannels(ctxQueryMap["channel"].(string), database, c)
	if errChannels != nil {
		return nil, errChannels
	}

	updatedPlatform, errPlatforms := CheckPlatformsLatest(ctxQueryMap["platform"].(string), database, c)
	if errPlatforms != nil {
		return nil, errPlatforms
	}
	ctxQueryMap["platform"] = updatedPlatform
	updatedArch, errArchs := CheckArchsLatest(ctxQueryMap["arch"].(string), database, c)
	if errArchs != nil {
		return nil, errArchs
	}
	ctxQueryMap["arch"] = updatedArch
	return ctxQueryMap, nil
}

func ValidateParams(c *gin.Context, database *mongo.Database) (map[string]interface{}, error) {
	var ctxQueryMap map[string]interface{}
	var err error

	if c.Request.Method == http.MethodPost {
		ctxQueryMap, err = extractParamsFromPost(c)
	} else if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodDelete {
		ctxQueryMap, err = extractParamsFromGetOrDelete(c)
	} else {
		return nil, errors.New("unsupported request method")
	}

	if err != nil {
		return nil, err
	}

	return validateCommonParams(ctxQueryMap, database, c)
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

func validateCommonParams(ctxQueryMap map[string]interface{}, database *mongo.Database, c *gin.Context) (map[string]interface{}, error) {
	if !IsValidAppName(ctxQueryMap["app_name"].(string)) {
		return nil, errors.New("invalid app_name parameter")
	}
	if !IsValidVersion(ctxQueryMap["version"].(string)) {
		return nil, errors.New("invalid version parameter")
	}
	if !IsValidChannelName(ctxQueryMap["channel"].(string)) {
		return nil, errors.New("invalid channel parameter")
	}
	if !IsValidPlatformName(ctxQueryMap["platform"].(string)) {
		return nil, errors.New("invalid platform parameter")
	}
	if !IsValidArchName(ctxQueryMap["arch"].(string)) {
		return nil, errors.New("invalid arch parameter")
	}

	if err := CheckChannels(ctxQueryMap["channel"].(string), database, c); err != nil {
		return nil, err
	}
	if err := CheckPlatforms(ctxQueryMap["platform"].(string), database, c); err != nil {
		return nil, err
	}
	if err := CheckArchs(ctxQueryMap["arch"].(string), database, c); err != nil {
		return nil, err
	}

	return ctxQueryMap, nil
}

func IsValidAppName(input string) bool {
	// Only allow letters and numbers, no special characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9\- ]+$`)
	return validName.MatchString(input)
}
func IsValidVersion(input string) bool {
	// Only allow numbers and dots, no spaces or special characters
	validVersion := regexp.MustCompile(`^[0-9.-]+$`)
	return validVersion.MatchString(input)
}

func IsValidChannelName(input string) bool {
	// Allow empty input or only letters, numbers, and hyphens, no spaces or other special characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9-]*$`)
	return validName.MatchString(input)
}

func IsValidPlatformName(input string) bool {
	// Allow empty input or only letters and numbers, no spaces or special characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9]*$`)
	return validName.MatchString(input)
}

func IsValidArchName(input string) bool {
	// Allow empty input or only letters and numbers, no spaces or special characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9]*$`)
	return validName.MatchString(input)
}
