package utils

import (
	"errors"
	"regexp"

	"github.com/gin-gonic/gin"
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
		return nil, errors.New("Invalid app_name parameter")
	}
	if !IsValidVersion(ctxQueryMap["version"].(string)) {
		return nil, errors.New("Invalid version parameter")
	}
	if !IsValidChannelName(ctxQueryMap["channel"].(string)) {
		return nil, errors.New("Invalid channel parameter")
	}

	if !IsValidPlatformName(ctxQueryMap["platform"].(string)) {
		return nil, errors.New("Invalid platform parameter")
	}

	if !IsValidArchName(ctxQueryMap["arch"].(string)) {
		return nil, errors.New("Invalid platform parameter")
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
	ctxQueryMap := map[string]interface{}{
		"app_name": c.Query("app_name"),
		"version":  c.Query("version"),
		"channel":  c.Query("channel"),
		"publish":  c.Query("publish"),
		"platform": c.Query("platform"),
		"arch":     c.Query("arch"),
	}

	if !IsValidAppName(ctxQueryMap["app_name"].(string)) {
		return nil, errors.New("Invalid app_name parameter")
	}
	if !IsValidVersion(ctxQueryMap["version"].(string)) {
		return nil, errors.New("Invalid version parameter")
	}
	if !IsValidChannelName(ctxQueryMap["channel"].(string)) {
		return nil, errors.New("Invalid channel parameter")
	}

	if !IsValidPlatformName(ctxQueryMap["platform"].(string)) {
		return nil, errors.New("Invalid platform parameter")
	}

	if !IsValidArchName(ctxQueryMap["arch"].(string)) {
		return nil, errors.New("Invalid platform parameter")
	}

	errChannels := CheckChannels(ctxQueryMap["channel"].(string), database, c)
	if errChannels != nil {
		return nil, errChannels
	}

	errPlatforms := CheckPlatforms(ctxQueryMap["platform"].(string), database, c)
	if errPlatforms != nil {
		return nil, errPlatforms
	}

	errArchs := CheckArchs(ctxQueryMap["arch"].(string), database, c)
	if errArchs != nil {
		return nil, errArchs
	}

	return ctxQueryMap, nil
}

func IsValidAppName(input string) bool {
	// Only allow letters and numbers, no spaces or special characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	return validName.MatchString(input)
}
func IsValidVersion(input string) bool {
	// Only allow numbers and dots, no spaces or special characters
	validVersion := regexp.MustCompile(`^[0-9.-]+$`)
	return validVersion.MatchString(input)
}

func IsValidChannelName(input string) bool {
	// Allow empty input or only letters and numbers, no spaces or special characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9]*$`)
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
