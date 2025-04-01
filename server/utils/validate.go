package utils

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
)

// ValidateJWT parses and validates the JWT token
func ValidateJWT(tokenString string) (*jwt.Token, error) {
	env := viper.GetViper()

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrInvalidKey
		}
		return []byte(env.GetString("JWT_SECRET")), nil
	})

	if err != nil {
		// Check for specific error cases
		switch {
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, fmt.Errorf("invalid signature: %w", err)
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, fmt.Errorf("malformed token: %w", err)
		case errors.Is(err, jwt.ErrTokenUnverifiable):
			return nil, fmt.Errorf("unverifiable token: %w", err)
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, fmt.Errorf("token expired: %w", err)
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, fmt.Errorf("token not active yet: %w", err)
		default:
			return nil, fmt.Errorf("token validation error: %w", err)
		}
	}

	return token, nil
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
		return nil, errors.New("invalid arch parameter")
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

func ValidateItemName(itemType, paramValue string) error {
	switch itemType {
	case "channel":
		if !IsValidChannelName(paramValue) {
			return errors.New("invalid channel name")
		}
	case "platform":
		if !IsValidPlatformName(paramValue) {
			return errors.New("invalid platform name")
		}
	case "arch":
		if !IsValidArchName(paramValue) {
			return errors.New("invalid architecture name")
		}
	case "app":
		if !IsValidAppName(paramValue) {
			return errors.New("invalid app name")
		}
	default:
		return errors.New("invalid item type")
	}
	return nil
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
	// Allow empty input or only letters and numbers, no spaces or special characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9]*$`)
	return validName.MatchString(input)
}

func IsValidPlatformName(input string) bool {
	// Allow empty input or only letters, numbers, and hyphens, no spaces or other special characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9-]*$`)
	return validName.MatchString(input)
}

func IsValidArchName(input string) bool {
	// Allow empty input or only letters and numbers, no spaces or special characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9]*$`)
	return validName.MatchString(input)
}

func ValidateUpdateParams(c *gin.Context, database *mongo.Database) (map[string]interface{}, error) {
	var ctxQueryMap map[string]interface{}
	var err error

	if c.Request.Method == http.MethodPost {
		ctxQueryMap, err = extractParamsFromPost(c)
	} else {
		return nil, errors.New("unsupported request method")
	}

	if err != nil {
		return nil, err
	}

	return validateUpdateCommonParams(ctxQueryMap, database, c)
}

func validateUpdateCommonParams(ctxQueryMap map[string]interface{}, database *mongo.Database, c *gin.Context) (map[string]interface{}, error) {

	form, _ := c.MultipartForm()
	hasFile := form != nil && len(form.File["file"]) > 0

	if hasFile {
		platform, _ := ctxQueryMap["platform"].(string)
		if !IsValidPlatformName(platform) {
			return nil, errors.New("invalid platform parameter")
		}
		if err := CheckPlatforms(platform, database, c); err != nil {
			return nil, err
		}

		arch, _ := ctxQueryMap["arch"].(string)
		if !IsValidArchName(arch) {
			return nil, errors.New("invalid arch parameter")
		}
		if err := CheckArchs(arch, database, c); err != nil {
			return nil, err
		}
	}

	return ctxQueryMap, nil
}
