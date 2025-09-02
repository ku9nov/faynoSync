package utils

import (
	"encoding/json"
	"errors"
	"faynoSync/server/model"
	"fmt"
	"net/http"
	"net/url"
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
	intermediateStr := strconv.FormatBool(upReq.Intermediate)
	return map[string]interface{}{
		"id":                  upReq.Id,
		"app_name":            upReq.AppName,
		"version":             upReq.Version,
		"channel":             upReq.Channel,
		"publish":             publishStr,
		"critical":            criticalStr,
		"intermediate":        intermediateStr,
		"platform":            upReq.Platform,
		"arch":                upReq.Arch,
		"changelog":           upReq.Changelog,
		"artifacts_to_delete": upReq.ArtifactsToDelete,
		"updater":             upReq.Updater,
		"signature":           upReq.Signature,
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

func ExtractArtifactLinks(results []interface{}) []string {
	var artifacts []string
	uniqueArtifacts := make(map[string]struct{})

	for _, result := range results {
		if appData, ok := result.(model.SpecificApp); ok {
			for _, artifact := range appData.Artifacts {
				key := fmt.Sprintf("%s|%s", artifact.Link, artifact.Package)
				if _, exists := uniqueArtifacts[key]; !exists {
					uniqueArtifacts[key] = struct{}{}
					artifacts = append(artifacts, artifact.Link)
				}
			}
		}
	}
	return artifacts
}

func ExtractChangelog(results []interface{}) []string {
	var changelog []string
	if appData, ok := results[0].(model.SpecificApp); ok {
		for _, change := range appData.Changelog {
			if change.Changes != "" {
				changelog = append(changelog, change.Changes)
			}
		}
	}
	return changelog
}

func parsePublicURL(linkWithoutScheme string, publicEndpoint, publicBucket string) (string, error) {
	publicEndpointWithoutScheme := strings.TrimPrefix(strings.TrimPrefix(publicEndpoint, "http://"), "https://")

	logrus.Debugf("Parsing URL: %s", linkWithoutScheme)
	logrus.Debugf("Public endpoint: %s", publicEndpoint)
	logrus.Debugf("Public bucket: %s", publicBucket)

	// 1. DigitalOcean Spaces: bucket-name.region.digitaloceanspaces.com/object-key
	if strings.Contains(linkWithoutScheme, ".digitaloceanspaces.com/") {
		logrus.Debugf("Detected DigitalOcean Spaces format")
		parts := strings.Split(linkWithoutScheme, ".digitaloceanspaces.com/")
		if len(parts) > 1 {
			key := parts[1]
			logrus.Debugf("Extracted DigitalOcean key: %s", key)
			return key, nil
		}
		return "", fmt.Errorf("invalid DigitalOcean Spaces URL format")
	}

	// 2. Google Cloud Storage: storage.googleapis.com/bucket-name/object-key
	if strings.Contains(linkWithoutScheme, "storage.googleapis.com/") {
		logrus.Debugf("Detected Google Cloud Storage format")
		parts := strings.Split(linkWithoutScheme, "storage.googleapis.com/")
		if len(parts) > 1 {
			// Remove bucket name from the path
			pathParts := strings.SplitN(parts[1], "/", 2)
			if len(pathParts) > 1 {
				key := pathParts[1]
				logrus.Debugf("Extracted GCS key: %s", key)
				return key, nil
			}
		}
		return "", fmt.Errorf("invalid Google Cloud Storage URL format")
	}

	// 3. AWS S3 virtual-hosted style: bucket-name.s3.region.amazonaws.com/object-key
	// Check this BEFORE legacy format to avoid conflicts
	if strings.Contains(linkWithoutScheme, ".s3.") && strings.Contains(linkWithoutScheme, ".amazonaws.com/") {
		logrus.Debugf("Detected AWS S3 format (virtual-hosted)")
		// For virtual-hosted style, extract everything after .amazonaws.com/
		parts := strings.Split(linkWithoutScheme, ".amazonaws.com/")
		if len(parts) > 1 {
			key := parts[1]
			logrus.Debugf("Extracted AWS S3 key (virtual-hosted): %s", key)
			return key, nil
		}
		return "", fmt.Errorf("invalid AWS S3 virtual-hosted URL format")
	}

	// 4. AWS S3 legacy format: s3.amazonaws.com/bucket-name/object-key
	if strings.Contains(linkWithoutScheme, "s3.amazonaws.com/") {
		logrus.Debugf("Detected AWS S3 format (legacy)")
		parts := strings.Split(linkWithoutScheme, "s3.amazonaws.com/")
		if len(parts) > 1 {
			// Remove bucket name from the path
			pathParts := strings.SplitN(parts[1], "/", 2)
			if len(pathParts) > 1 {
				key := pathParts[1]
				logrus.Debugf("Extracted AWS S3 key: %s", key)
				return key, nil
			}
		}
		return "", fmt.Errorf("invalid AWS S3 URL format")
	}

	// 5. MinIO: endpoint/bucket-name/object-key
	bucketPath := fmt.Sprintf("%s/%s/", publicEndpointWithoutScheme, publicBucket)
	logrus.Debugf("Looking for MinIO pattern: %s", bucketPath)

	if strings.Contains(linkWithoutScheme, bucketPath) {
		logrus.Debugf("Detected MinIO format")
		parts := strings.Split(linkWithoutScheme, bucketPath)
		if len(parts) > 1 {
			key := parts[1]
			logrus.Debugf("Extracted MinIO key: %s", key)
			return key, nil
		}
		return "", fmt.Errorf("invalid MinIO URL format")
	}

	logrus.Debugf("Using generic fallback format")
	key := strings.TrimPrefix(linkWithoutScheme, fmt.Sprintf("%s/", publicEndpointWithoutScheme))
	logrus.Debugf("Extracted generic key: %s", key)
	return key, nil
}

// extractS3Key extracts the S3 key from either a private or public URL
func ExtractS3Key(link string, checkAppVisibility bool, env *viper.Viper) (string, error) {
	logrus.Debugf("ExtractS3Key called with URL: %s, checkAppVisibility: %v", link, checkAppVisibility)

	var subLink string

	if checkAppVisibility {
		// Handle private bucket URLs (through our API)
		apiURL := env.GetString("API_URL")
		prefix := fmt.Sprintf("%s/download?key=", apiURL)
		logrus.Debugf("Private bucket - API URL: %s, prefix: %s", apiURL, prefix)

		subLink = strings.TrimPrefix(link, prefix)
		logrus.Debugf("Private bucket key (before decoding): %s", subLink)
	} else {
		// Handle public bucket URLs
		linkWithoutScheme := strings.TrimPrefix(strings.TrimPrefix(link, "http://"), "https://")
		logrus.Debugf("Public bucket - URL without scheme: %s", linkWithoutScheme)

		// Get the public bucket endpoint and name
		publicEndpoint := env.GetString("S3_ENDPOINT")
		publicBucket := env.GetString("S3_BUCKET_NAME")

		var err error
		subLink, err = parsePublicURL(linkWithoutScheme, publicEndpoint, publicBucket)
		if err != nil {
			logrus.Errorf("Failed to parse public URL: %v", err)
			return "", err
		}
		logrus.Debugf("Public bucket key (before decoding): %s", subLink)
	}

	// URL decode the key to handle special characters
	decodedKey, err := url.QueryUnescape(subLink)
	if err != nil {
		logrus.Errorf("Failed to decode URL: %v", err)
		return "", fmt.Errorf("invalid URL encoding: %w", err)
	}
	logrus.Debugf("Final decoded key: %s", decodedKey)

	return decodedKey, nil
}

func GetUsernameFromContext(c *gin.Context) (string, error) {
	username, exists := c.Get("username")
	if !exists {
		return "", errors.New("username not found in token")
	}
	return username.(string), nil
}
