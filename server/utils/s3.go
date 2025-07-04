package utils

import (
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

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

func UploadToS3(ctxQuery map[string]interface{}, owner string, file *multipart.FileHeader, c *gin.Context, env *viper.Viper, checkAppVisibility bool) (string, string, error) {

	storageClient, err := getStorageClient(env)
	if err != nil {
		logrus.Errorf("failed to create storage client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create storage client"})
		return "", "", err
	}

	var extension string
	// Extract base filename and extension
	baseFileName := file.Filename
	lastDotIndex := strings.LastIndex(baseFileName, ".")
	if lastDotIndex > -1 {
		extension = baseFileName[lastDotIndex:]
	}
	// Generate new file name
	var newFileName string
	if ctxQuery["type"] == "logo" {
		newFileName = fmt.Sprintf("%s-logo%s", ctxQuery["app_name"].(string), extension)
	} else {
		newFileName = fmt.Sprintf("%s-%s%s", ctxQuery["app_name"].(string), ctxQuery["version"].(string), extension)
	}

	var link string
	var s3Key string
	s3PathSegments := []string{fmt.Sprintf("%s-%s", ctxQuery["app_name"].(string), owner)}
	if ctxQuery["channel"].(string) == "" && ctxQuery["platform"].(string) == "" && ctxQuery["arch"].(string) == "" {

		s3PathSegments = append(s3PathSegments, newFileName)

	} else {

		if ctxQuery["channel"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["channel"].(string))
		}

		if ctxQuery["platform"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["platform"].(string))
		}

		if ctxQuery["arch"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["arch"].(string))
		}

		s3PathSegments = append(s3PathSegments, newFileName)
	}

	encodedPath := url.PathEscape(strings.Join(s3PathSegments, "/"))
	link = fmt.Sprintf("%s/download?key=%s", env.GetString("API_URL"), encodedPath)
	s3Key = strings.Join(s3PathSegments, "/")

	// Open the file for reading
	fileReader, err := file.Open()
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open file for reading"})
		return "", "", err
	}
	defer fileReader.Close()

	logrus.Debugf("Uploading file: key=%s, type=%s",
		s3Key, ctxQuery["type"])

	var bucketName string
	if ctxQuery["type"] == "logo" || checkAppVisibility == false {
		bucketName = env.GetString("S3_BUCKET_NAME")
		logrus.Debugf("Uploading logo to public bucket: %s", bucketName)
		publicLink, err := storageClient.UploadPublicObject(c.Request.Context(), bucketName, s3Key, fileReader)
		if err != nil {
			logrus.Errorf("Failed to upload logo to storage: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file to storage"})
			return "", "", err
		}
		logrus.Debugf("Logo uploaded successfully, public link: %s", publicLink)
		link = publicLink
	} else {
		// Use private bucket for regular uploads
		bucketName = env.GetString("S3_BUCKET_NAME_PRIVATE")
		logrus.Debugf("Uploading to private bucket: %s", bucketName)
		err = storageClient.UploadObject(c.Request.Context(), bucketName, s3Key, fileReader)
		if err != nil {
			logrus.Errorf("Failed to upload to private storage: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file to storage"})
			return "", "", err
		}
		logrus.Debugf("File uploaded successfully to private bucket")
	}

	return link, extension, nil
}

func DeleteFromS3(objectKey string, c *gin.Context, env *viper.Viper, private bool) {
	logrus.Debugf("DeleteFromS3 called with objectKey: %s, private: %v", objectKey, private)

	storageClient, err := getStorageClient(env)
	if err != nil {
		logrus.Errorf("failed to create storage client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create storage client"})
		return
	}

	objectKey = strings.TrimPrefix(objectKey, "/")
	decodedKey, err := url.QueryUnescape(objectKey)
	if err != nil {
		logrus.Error("Failed to decode object key: ", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode object key"})
		return
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete file from storage"})
		return
	}

	logrus.Infof("Object '%s' deleted from bucket '%s'", decodedKey, bucketName)
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
