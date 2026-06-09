package report

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	defaultBlobRetentionDays       = 30
	defaultMaxBlobsPerGroup  int64 = 10
)

type bytesFile struct {
	*bytes.Reader
}

func (bytesFile) Close() error { return nil }

func buildBlobKey(prefix, appName, groupHash string, now time.Time) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	y, m, d := now.Date()
	return fmt.Sprintf("%s/%s/%04d/%02d/%02d/%s-%s.json.gz", prefix, appName, y, int(m), d, groupHash, hex.EncodeToString(b)), nil
}

// storeDetailsBlob uploads the compressed payload and records report_blobs metadata.
func storeDetailsBlob(ctx context.Context, repository db.AppRepository, appID primitive.ObjectID, owner, hash string, app model.ReportApplication, system model.ReportSystem, event model.ReportEvent, dd *decodedDetails, now time.Time) bool {
	prefix := viper.GetString("REPORTS_STORAGE_PREFIX")
	if prefix == "" {
		prefix = "reports"
	}
	// Reports may contain sensitive data (stack traces, logs, paths), so they go
	// to the private bucket: UploadObject sets no public ACL and access is only via
	// short-lived presigned URLs (same pattern as private app artifacts).
	bucket := viper.GetString("S3_BUCKET_NAME_PRIVATE")
	if bucket == "" {
		logrus.Errorf("Cannot store report details: S3_BUCKET_NAME_PRIVATE is not configured")
		return false
	}
	driver := viper.GetString("STORAGE_DRIVER")

	retentionDays := viper.GetInt("REPORTS_BLOB_RETENTION_DAYS")
	if retentionDays <= 0 {
		retentionDays = defaultBlobRetentionDays
	}

	key, err := buildBlobKey(prefix, app.Name, hash, now)
	if err != nil {
		logrus.Errorf("Failed to build report blob key: %v", err)
		return false
	}

	storageClient, err := utils.NewStorageFactory(viper.GetViper()).CreateStorageClient()
	if err != nil {
		logrus.Errorf("Failed to create storage client for report blob: %v", err)
		return false
	}

	file := bytesFile{bytes.NewReader(dd.compressed)}
	if err := storageClient.UploadObject(ctx, bucket, key, file, "application/gzip"); err != nil {
		logrus.Errorf("Failed to upload report blob to storage: %v", err)
		return false
	}

	blob := model.ReportBlob{
		GroupHash:   hash,
		AppID:       appID,
		Owner:       owner,
		Application: app,
		System:      system,
		Event:       event,
		Storage: model.ReportBlobStorage{
			Driver:           driver,
			Bucket:           bucket,
			Key:              key,
			CompressedSize:   int64(len(dd.compressed)),
			DecompressedSize: dd.decompressedSize,
			ContentType:      "application/json",
			Encoding:         "gzip",
		},
		CreatedAt: primitive.NewDateTimeFromTime(now),
		ExpiresAt: primitive.NewDateTimeFromTime(now.AddDate(0, 0, retentionDays)),
	}

	if err := repository.InsertReportBlob(ctx, blob); err != nil {
		logrus.Errorf("Failed to insert report blob metadata (cleaning up object %s/%s): %v", bucket, key, err)
		if delErr := storageClient.DeleteObject(ctx, bucket, key); delErr != nil {
			logrus.Errorf("Failed to delete orphaned report blob %s/%s: %v", bucket, key, delErr)
		}
		return false
	}

	logrus.Debugf("Uploaded report blob: bucket=%s key=%s compressed=%d", bucket, key, len(dd.compressed))

	maxBlobs := viper.GetInt64("REPORTS_MAX_BLOBS_PER_GROUP")
	if maxBlobs <= 0 {
		maxBlobs = defaultMaxBlobsPerGroup
	}
	trimGroupBlobs(ctx, repository, storageClient, bucket, appID, hash, maxBlobs)

	return true
}

// trimGroupBlobs keeps only the newest keepN blobs for a group. It is best-effort:
// storage objects are deleted before metadata, and any failure is logged and left
// to the S3 lifecycle / TTL index. It never affects the stored result of the caller.
func trimGroupBlobs(ctx context.Context, repository db.AppRepository, storageClient utils.StorageClient, bucket string, appID primitive.ObjectID, hash string, keepN int64) {
	excess, err := repository.FindExcessReportBlobs(ctx, appID, hash, keepN)
	if err != nil {
		logrus.Errorf("Failed to list excess report blobs for group %s: %v", hash, err)
		return
	}
	if len(excess) == 0 {
		return
	}

	logrus.Debugf("Trimming %d excess report blobs for group %s (keep=%d)", len(excess), hash, keepN)

	keys := make([]string, 0, len(excess))
	ids := make([]primitive.ObjectID, 0, len(excess))
	for _, b := range excess {
		keys = append(keys, b.Storage.Key)
		ids = append(ids, b.ID)
	}

	if err := storageClient.DeleteObjects(ctx, bucket, keys); err != nil {
		logrus.Errorf("Failed to delete excess report blob objects (relying on lifecycle/TTL): %v", err)
	}
	if _, err := repository.DeleteReportBlobsByIDs(ctx, ids); err != nil {
		logrus.Errorf("Failed to delete excess report blob metadata for group %s: %v", hash, err)
	}
}
