package info

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"faynoSync/server/utils"
	"fmt"
	"mime/multipart"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
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

const (
	latestResponseCacheControl = "public, max-age=60, must-revalidate"
	cdnPublishTimeout          = 5 * time.Second
	cdnEpochKeyPrefix          = "cdn_epoch:"
)

var (
	cdnPublishSlots = make(chan struct{}, 32)
	cdnClientMu     sync.Mutex
	cdnClient       utils.StorageClient
)

func (m *memoryFile) Close() error {
	return nil
}

func cdnEpochKey(owner, appName string) string {
	return cdnEpochKeyPrefix + owner + ":" + appName
}

// readCDNEpoch reports whether the epoch could be read at all, so callers can tell "the app was invalidated"
// apart from "Redis did not answer" instead of treating an unreadable epoch as a changed one.
func readCDNEpoch(ctx context.Context, rdb *redis.Client, owner, appName string) (string, bool) {
	if rdb == nil {
		return "", true
	}
	epoch, err := rdb.Get(ctx, cdnEpochKey(owner, appName)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", true
		}
		logrus.Errorf("Failed to read CDN epoch for %s/%s: %v", owner, appName, err)
		return "", false
	}
	return epoch, true
}

// ReadCDNEpoch must be called before the response data is read, so a publish that loses the race against an
// upload can be dropped instead of recreating an object the upload already deleted.
func ReadCDNEpoch(ctx context.Context, rdb *redis.Client, owner, appName string) string {
	epoch, _ := readCDNEpoch(ctx, rdb, owner, appName)
	return epoch
}

// BumpCDNEpoch drops every CDN publish whose response was read before this call.
func BumpCDNEpoch(ctx context.Context, rdb *redis.Client, owner, appName string) {
	if rdb == nil {
		return
	}
	if err := rdb.Incr(ctx, cdnEpochKey(owner, appName)).Err(); err != nil {
		logrus.Errorf("Failed to bump CDN epoch for %s/%s: %v", owner, appName, err)
	}
}

func publishResponseToCDN(ctx context.Context, rdb *redis.Client, epoch string, params map[string]interface{}, response gin.H) {

	bucketName := viper.GetString("S3_BUCKET_NAME_CDN")
	if bucketName == "" {
		logrus.Debug("S3_BUCKET_NAME_CDN is not configured, skipping CDN response publish")
		return
	}

	owner := params["owner"].(string)
	appName := params["app_name"].(string)

	objectKeyParts := []string{
		"responses",
		owner,
		appName,
	}

	for _, key := range []string{"channel", "platform", "arch", "updater"} {
		if value, ok := params[key].(string); ok && value != "" {
			// An unsupported updater gets the same native body as manual, and manual is the path the SDKs read.
			if key == "updater" && value == utils.UpdaterNotSupported {
				value = "manual"
			}
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

	// The CDN bucket can be in another region than the API, so a cache miss must not wait for its round trips.
	publishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cdnPublishTimeout)
	select {
	case cdnPublishSlots <- struct{}{}:
		go func() {
			defer func() { <-cdnPublishSlots }()
			defer cancel()
			uploadResponseToCDN(publishCtx, bucketName, objectKey, responseData, func(freshCtx context.Context) (fresh, known bool) {
				current, known := readCDNEpoch(freshCtx, rdb, owner, appName)
				return current == epoch, known
			})
		}()
	default:
		// Publishing inline here would put the CDN round trips back into the request path under peak load.
		cancel()
		logrus.Debugf("CDN publish slots are busy, skipping publish: %s/%s", bucketName, objectKey)
	}
}

func uploadResponseToCDN(ctx context.Context, bucketName, objectKey string, responseData []byte, stillFresh func(context.Context) (fresh, known bool)) {
	storageClient, err := cdnStorageClient()
	if err != nil {
		logrus.Errorf("Failed to create storage client for CDN response publish: %v", err)
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

	// Re-checked as late as possible: everything above is a round trip during which an upload can invalidate the app.
	if fresh, _ := stillFresh(ctx); !fresh {
		logrus.Debugf("Skipping CDN response publish because the app was invalidated meanwhile: %s/%s", bucketName, objectKey)
		return
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

	// The write is not atomic with the check above, so an invalidation sweep can delete this key while the
	// upload is in flight. The sweep bumps the epoch before it deletes, so re-reading the epoch afterwards
	// catches every such loss. The context gets its own deadline because the one above may be spent by now.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cdnPublishTimeout)
	defer cancel()
	// Only a read that succeeded may delete: an unreadable epoch here would destroy a perfectly fresh object.
	if fresh, known := stillFresh(cleanupCtx); known && !fresh {
		if err := storageClient.DeleteObject(cleanupCtx, bucketName, objectKey); err != nil {
			logrus.Errorf("Failed to remove CDN response object written after invalidation: %v", err)
			return
		}
		logrus.Debugf("Removed CDN response object written after invalidation: %s/%s", bucketName, objectKey)
		return
	}

	logrus.Debugf("Published latest response to CDN bucket: %s/%s", bucketName, objectKey)
}

// cdnStorageClient reuses one client so its connections to the CDN bucket stay open between publishes.
func cdnStorageClient() (utils.StorageClient, error) {
	cdnClientMu.Lock()
	defer cdnClientMu.Unlock()
	if cdnClient != nil {
		return cdnClient, nil
	}
	storageClient, err := utils.NewStorageFactory(viper.GetViper()).CreateStorageClient()
	if err != nil {
		return nil, err
	}
	cdnClient = storageClient
	return cdnClient, nil
}

func normalizeETag(etag string) string {
	return strings.ToLower(strings.Trim(etag, "\""))
}
