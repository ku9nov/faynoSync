package info

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"faynoSync/server/utils"
	"fmt"
	"mime/multipart"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type memoryFile struct {
	*bytes.Reader
}

type cdnObjectStatClient interface {
	GetObjectETag(ctx context.Context, bucketName, objectKey string) (etag string, exists bool, err error)
}

type cdnPublicUploaderWithCacheControl interface {
	UploadPublicObjectWithCacheControl(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType, cacheControl string) (string, error)
}

const latestResponseCacheControl = "public, max-age=60, must-revalidate"

func (m *memoryFile) Close() error {
	return nil
}

func publishResponseToCDN(ctx context.Context, params map[string]interface{}, response gin.H) {

	bucketName := viper.GetString("S3_BUCKET_NAME_CDN")
	if bucketName == "" {
		logrus.Debug("S3_BUCKET_NAME_CDN is not configured, skipping CDN response publish")
		return
	}

	factory := utils.NewStorageFactory(viper.GetViper())
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		logrus.Errorf("Failed to create storage client for CDN response publish: %v", err)
		return
	}

	objectKeyParts := []string{
		"responses",
		params["owner"].(string),
		params["app_name"].(string),
	}

	for _, key := range []string{"channel", "platform", "arch"} {
		if value, ok := params[key].(string); ok && value != "" {
			objectKeyParts = append(objectKeyParts, value)
		}
	}

	objectKeyParts = append(objectKeyParts, params["version"].(string)+".json")
	objectKey := strings.Join(objectKeyParts, "/")

	responseData, err := json.Marshal(response)
	if err != nil {
		logrus.Errorf("Failed to marshal latest response for CDN publish: %v", err)
		return
	}

	if statClient, ok := storageClient.(cdnObjectStatClient); ok {
		existingETag, exists, err := statClient.GetObjectETag(ctx, bucketName, objectKey)
		if err != nil {
			logrus.Errorf("Failed to stat existing CDN response object: %v", err)
			return
		}

		if exists && existingETag != "" {
			newMD5 := md5.Sum(responseData)
			newETag := strings.ToLower(fmt.Sprintf("%x", newMD5))
			if normalizeETag(existingETag) == newETag {
				logrus.Debugf("Skipping CDN response publish because content is unchanged: %s/%s", bucketName, objectKey)
				return
			}
		}
	}

	fileReader := &memoryFile{Reader: bytes.NewReader(responseData)}
	if uploader, ok := storageClient.(cdnPublicUploaderWithCacheControl); ok {
		if _, err := uploader.UploadPublicObjectWithCacheControl(ctx, bucketName, objectKey, fileReader, "application/json", latestResponseCacheControl); err != nil {
			logrus.Errorf("Failed to publish latest response to CDN bucket: %v", err)
			return
		}
	} else if _, err := storageClient.UploadPublicObject(ctx, bucketName, objectKey, fileReader, "application/json"); err != nil {
		logrus.Errorf("Failed to publish latest response to CDN bucket: %v", err)
		return
	}

	logrus.Debugf("Published latest response to CDN bucket: %s/%s", bucketName, objectKey)
}

func normalizeETag(etag string) string {
	return strings.ToLower(strings.Trim(etag, "\""))
}
