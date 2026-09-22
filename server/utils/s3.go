package utils

import (
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"faynoSync/server/utils/updaters"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func getContentType(fileName string) string {
	fileName = strings.ToLower(fileName)

	if fileName == "releases" {
		return "text/plain"
	}

	if strings.HasSuffix(fileName, ".yaml") || strings.HasSuffix(fileName, ".yml") {
		return "text/yaml"
	}

	if strings.HasSuffix(fileName, ".json") {
		return "application/json"
	}

	return ""
}

// getStorageClient creates and returns a storage client using the factory pattern
func getStorageClient(env *viper.Viper) (StorageClient, error) {
	factory := NewStorageFactory(env)
	return factory.CreateStorageClient()
}

func UploadLogo(appName string, owner string, file *multipart.FileHeader, c *gin.Context, env *viper.Viper) (string, error) {
	logoLink, _, err := UploadToS3(map[string]interface{}{
		"app_name": appName,
		"version":  "0.0.0",
		"type":     "logo",
		"channel":  "",
		"platform": "",
		"arch":     "",
	}, owner, file, c, env, true)
	return logoLink, err
}

type ObjectPlacement struct {
	Key         string
	Extension   string
	Bucket      string
	Public      bool
	ContentType string
	// DownloadLink is the API_URL/download?key= link. It is the artifact link for
	// objects in the private bucket; a public object is served under the URL the
	// storage client returns after the upload instead.
	DownloadLink string
}

func BuildObjectPlacement(ctxQuery map[string]interface{}, owner string, fileName string, env *viper.Viper, checkAppVisibility bool) ObjectPlacement {
	var extension string
	// Extract base filename and extension
	lastDotIndex := strings.LastIndex(fileName, ".")
	if lastDotIndex > -1 {
		extension = fileName[lastDotIndex:]
	}
	// Generate new file name
	var newFileName string
	if ctxQuery["type"] == "logo" {
		newFileName = fmt.Sprintf("%s-logo%s", ctxQuery["app_name"].(string), extension)
	} else {
		newFileName = fmt.Sprintf("%s-%s%s", ctxQuery["app_name"].(string), ctxQuery["version"].(string), extension)
	}

	// Add API_URL to ctxQuery for BuildS3Key function
	ctxQuery["api_url"] = env.GetString("API_URL")

	// Get updater type from context or use default
	updaterType := "default"
	if updaterTypeVal, exists := ctxQuery["updater"]; exists {
		updaterType = updaterTypeVal.(string)
	}

	// Build S3 key using updaters package
	link, s3Key := updaters.BuildS3Key(ctxQuery, owner, newFileName, fileName, updaterType)

	placement := ObjectPlacement{
		Key:          s3Key,
		Extension:    extension,
		Public:       ctxQuery["type"] == "logo" || checkAppVisibility == false,
		ContentType:  getContentType(fileName),
		DownloadLink: link,
	}
	if placement.Public {
		placement.Bucket = env.GetString("S3_BUCKET_NAME")
	} else {
		// Use private bucket for regular uploads
		placement.Bucket = env.GetString("S3_BUCKET_NAME_PRIVATE")
	}

	return placement
}

func UploadToS3(ctxQuery map[string]interface{}, owner string, file *multipart.FileHeader, c *gin.Context, env *viper.Viper, checkAppVisibility bool) (string, string, error) {

	storageClient, err := getStorageClient(env)
	if err != nil {
		logrus.Errorf("failed to create storage client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create storage client"})
		return "", "", err
	}

	placement := BuildObjectPlacement(ctxQuery, owner, file.Filename, env, checkAppVisibility)
	link := placement.DownloadLink

	// Open the file for reading
	fileReader, err := file.Open()
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open file for reading"})
		return "", "", err
	}
	defer fileReader.Close()

	logrus.Debugf("Uploading file: key=%s, type=%s",
		placement.Key, ctxQuery["type"])

	logrus.Debugf("Determined ContentType: %s for file: %s", placement.ContentType, file.Filename)

	if placement.Public {
		logrus.Debugf("Uploading file to public bucket: %s", placement.Bucket)
		publicLink, err := storageClient.UploadPublicObject(c.Request.Context(), placement.Bucket, placement.Key, fileReader, placement.ContentType)
		if err != nil {
			logrus.Errorf("Failed to upload file to storage: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file to storage"})
			return "", "", err
		}
		logrus.Debugf("File uploaded successfully, public link: %s", publicLink)
		link = publicLink
	} else {
		logrus.Debugf("Uploading to private bucket: %s", placement.Bucket)
		err = storageClient.UploadObject(c.Request.Context(), placement.Bucket, placement.Key, fileReader, placement.ContentType)
		if err != nil {
			logrus.Errorf("Failed to upload to private storage: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file to storage"})
			return "", "", err
		}
		logrus.Debugf("File uploaded successfully to private bucket")
	}

	return link, placement.Extension, nil
}

func DeleteFromS3(objectKey string, env *viper.Viper, private bool) error {
	logrus.Debugf("DeleteFromS3 called with objectKey: %s, private: %v", objectKey, private)

	storageClient, err := getStorageClient(env)
	if err != nil {
		logrus.Errorf("failed to create storage client: %v", err)
		return fmt.Errorf("failed to create storage client: %w", err)
	}

	objectKey = strings.TrimPrefix(objectKey, "/")
	decodedKey, err := url.QueryUnescape(objectKey)
	if err != nil {
		logrus.Error("Failed to decode object key: ", err)
		return fmt.Errorf("failed to decode object key: %w", err)
	}

	logrus.Debugf("decodedKey in delete from s3: %s", decodedKey)

	var bucketName string
	if private {
		bucketName = env.GetString("S3_BUCKET_NAME_PRIVATE")
		logrus.Debugf("Using private bucket: %s", bucketName)
	} else {
		bucketName = env.GetString("S3_BUCKET_NAME")
		logrus.Debugf("Using public bucket: %s", bucketName)
	}

	logrus.Debugf("Attempting to delete object '%s' from bucket '%s'", decodedKey, bucketName)
	err = storageClient.DeleteObject(context.Background(), bucketName, decodedKey)
	if err != nil {
		logrus.Errorf("Failed to delete object '%s' from bucket '%s': %v", decodedKey, bucketName, err)
		return fmt.Errorf("failed to delete file from storage: %w", err)
	}

	logrus.Infof("Object '%s' deleted from bucket '%s'", decodedKey, bucketName)
	return nil
}

// DeleteManyFromS3 removes several objects with a single storage call.
func DeleteManyFromS3(objectKeys []string, env *viper.Viper, private bool) []string {
	if len(objectKeys) == 0 {
		return nil
	}

	logrus.Debugf("DeleteManyFromS3 called with %d object(s), private: %v", len(objectKeys), private)

	storageClient, err := getStorageClient(env)
	if err != nil {
		logrus.Errorf("failed to create storage client: %v", err)
		return objectKeys
	}

	var bucketName string
	if private {
		bucketName = env.GetString("S3_BUCKET_NAME_PRIVATE")
		logrus.Debugf("Using private bucket: %s", bucketName)
	} else {
		bucketName = env.GetString("S3_BUCKET_NAME")
		logrus.Debugf("Using public bucket: %s", bucketName)
	}

	var failed []string
	decodedKeys := make([]string, 0, len(objectKeys))
	originalKeys := make(map[string]string, len(objectKeys))
	for _, objectKey := range objectKeys {
		decodedKey, err := url.QueryUnescape(strings.TrimPrefix(objectKey, "/"))
		if err != nil {
			logrus.Error("Failed to decode object key: ", err)
			failed = append(failed, objectKey)
			continue
		}
		logrus.Debugf("decodedKey in delete from s3: %s", decodedKey)
		decodedKeys = append(decodedKeys, decodedKey)
		originalKeys[decodedKey] = objectKey
	}

	if len(decodedKeys) == 0 {
		return failed
	}

	logrus.Debugf("Attempting to delete %d object(s) from bucket '%s'", len(decodedKeys), bucketName)
	if err := storageClient.DeleteObjects(context.Background(), bucketName, decodedKeys); err != nil {
		logrus.Errorf("Failed to delete %d object(s) from bucket '%s': %v. Falling back to deleting them one by one.", len(decodedKeys), bucketName, err)

		for _, decodedKey := range decodedKeys {
			if err := storageClient.DeleteObject(context.Background(), bucketName, decodedKey); err != nil {
				logrus.Errorf("Failed to delete object '%s' from bucket '%s': %v", decodedKey, bucketName, err)
				failed = append(failed, originalKeys[decodedKey])
				continue
			}
			logrus.Infof("Object '%s' deleted from bucket '%s'", decodedKey, bucketName)
		}

		return failed
	}

	logrus.Infof("%d object(s) deleted from bucket '%s'", len(decodedKeys), bucketName)
	return failed
}

func GeneratePresignedURL(c *gin.Context, objectKey string, expiration time.Duration) (string, error) {
	env := viper.GetViper()

	storageClient, err := getStorageClient(env)
	if err != nil {
		logrus.Errorf("failed to create storage client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create storage client"})
		return "", err
	}

	// Generate presigned URL
	url, err := storageClient.GeneratePresignedURL(c.Request.Context(), env.GetString("S3_BUCKET_NAME_PRIVATE"), objectKey, expiration)
	if err != nil {
		return "", err
	}

	return url, nil
}
