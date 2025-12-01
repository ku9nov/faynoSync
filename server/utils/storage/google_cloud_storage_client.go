package storage

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"time"

	"cloud.google.com/go/storage"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/api/option"
)

// GoogleCloudStorageClient implements StorageClient for GCS
type GoogleCloudStorageClient struct {
	client *storage.Client
	env    *viper.Viper
}

// NewGoogleCloudStorageClient creates a new GCS client
func NewGoogleCloudStorageClient(env *viper.Viper) (*GoogleCloudStorageClient, error) {
	ctx := context.Background()
	credsFile := env.GetString("GCS_CREDENTIALS_FILE")

	logrus.Debugf("GCS: Creating client with credentials file: %s\n", credsFile)

	var client *storage.Client
	var err error
	if credsFile != "" {
		client, err = storage.NewClient(ctx, option.WithCredentialsFile(credsFile))
	} else {
		logrus.Debugf("GCS: No credentials file provided, using default credentials\n")
		client, err = storage.NewClient(ctx)
	}
	if err != nil {
		logrus.Debugf("GCS: Failed to create client: %v\n", err)
		return nil, &StorageError{Message: "failed to create GCS client", Err: err}
	}

	logrus.Debugf("GCS: Client created successfully\n")
	return &GoogleCloudStorageClient{client: client, env: env}, nil
}

func (g *GoogleCloudStorageClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	logrus.Debugf("GCS: Uploading object to bucket: %s, key: %s\n", bucketName, objectKey)

	// Check if bucket exists
	bucket := g.client.Bucket(bucketName)
	_, err := bucket.Attrs(ctx)
	if err != nil {
		logrus.Debugf("GCS: Bucket %s does not exist or is not accessible: %v\n", bucketName, err)
		return &StorageError{Message: fmt.Sprintf("bucket %s does not exist or is not accessible", bucketName), Err: err}
	}

	logrus.Debugf("GCS: Bucket %s exists and is accessible\n", bucketName)

	w := bucket.Object(objectKey).NewWriter(ctx)

	// Set ContentType if provided
	if contentType != "" {
		w.ContentType = contentType
		logrus.Debugf("GCS: Setting ContentType to: %s\n", contentType)
	}

	bytesWritten, err := io.Copy(w, fileReader)
	if err != nil {
		w.Close()
		logrus.Debugf("GCS: Failed to copy file content: %v\n", err)
		return &StorageError{Message: "failed to upload object to GCS", Err: err}
	}

	logrus.Debugf("GCS: Copied %d bytes to writer\n", bytesWritten)

	if err := w.Close(); err != nil {
		logrus.Debugf("GCS: Failed to close writer: %v\n", err)
		return &StorageError{Message: "failed to finalize upload to GCS", Err: err}
	}

	logrus.Debugf("GCS: Upload completed successfully\n")
	return nil
}

func (g *GoogleCloudStorageClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {

	logrus.Debugf("GCS: Uploading public object to bucket: %s, key: %s\n", bucketName, objectKey)

	bucket := g.client.Bucket(bucketName)
	attrs, err := bucket.Attrs(ctx)
	if err != nil {
		logrus.Debugf("GCS: Bucket %s does not exist or is not accessible: %v\n", bucketName, err)
		return "", &StorageError{Message: fmt.Sprintf("bucket %s does not exist or is not accessible", bucketName), Err: err}
	}

	logrus.Debugf("GCS: Bucket %s exists and is accessible\n", bucketName)
	logrus.Debugf("GCS: Bucket uniform access enabled: %v\n", attrs.UniformBucketLevelAccess.Enabled)

	w := bucket.Object(objectKey).NewWriter(ctx)

	// Set ContentType if provided
	if contentType != "" {
		w.ContentType = contentType
		logrus.Debugf("GCS: Setting ContentType to: %s\n", contentType)
	}

	// Don't set PredefinedACL if uniform bucket-level access is enabled
	if !attrs.UniformBucketLevelAccess.Enabled {
		w.PredefinedACL = "publicRead"
		logrus.Debugf("GCS: Using legacy ACL (uniform access disabled)\n")
	} else {
		logrus.Debugf("GCS: Uniform bucket-level access enabled, skipping ACL\n")
	}

	bytesWritten, err := io.Copy(w, fileReader)
	if err != nil {
		w.Close()
		logrus.Debugf("GCS: Failed to copy file content: %v\n", err)
		return "", &StorageError{Message: "failed to upload public object to GCS", Err: err}
	}

	logrus.Debugf("GCS: Copied %d bytes to writer\n", bytesWritten)

	if err := w.Close(); err != nil {
		logrus.Debugf("GCS: Failed to close writer: %v\n", err)
		return "", &StorageError{Message: "failed to finalize upload to GCS", Err: err}
	}

	publicURL := fmt.Sprintf("https://storage.googleapis.com/%s/%s", bucketName, objectKey)
	logrus.Debugf("GCS: Upload completed successfully, public URL: %s\n", publicURL)
	return publicURL, nil
}

func (g *GoogleCloudStorageClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	bucket := g.client.Bucket(bucketName)
	obj := bucket.Object(objectKey)
	if err := obj.Delete(ctx); err != nil {
		return &StorageError{Message: "failed to delete object from GCS", Err: err}
	}
	return nil
}

func (g *GoogleCloudStorageClient) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {

	credsFile := g.env.GetString("GCS_CREDENTIALS_FILE")
	serviceAccount := g.env.GetString("GCS_SERVICE_ACCOUNT_EMAIL")
	if credsFile == "" || serviceAccount == "" {
		return "", &StorageError{Message: "GCS_CREDENTIALS_FILE and GCS_SERVICE_ACCOUNT_EMAIL are required for presigned URLs"}
	}
	opts := &storage.SignedURLOptions{
		GoogleAccessID: serviceAccount,
		PrivateKey:     []byte(g.env.GetString("GCS_PRIVATE_KEY")),
		Method:         "GET",
		Expires:        time.Now().Add(expiration),
	}
	url, err := storage.SignedURL(bucketName, objectKey, opts)
	if err != nil {
		return "", &StorageError{Message: "failed to generate presigned URL for GCS", Err: err}
	}
	return url, nil
}

// DownloadObject downloads a file from GCS to a local file path
func (g *GoogleCloudStorageClient) DownloadObject(ctx context.Context, bucketName, objectKey string, filePath string) error {
	bucket := g.client.Bucket(bucketName)
	obj := bucket.Object(objectKey)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		return &StorageError{Message: "failed to get object from GCS", Err: err}
	}
	defer reader.Close()

	file, err := os.Create(filePath)
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to create file %s", filePath), Err: err}
	}
	defer file.Close()

	_, err = io.Copy(file, reader)
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to write to file %s", filePath), Err: err}
	}

	return nil
}

// ListObjects lists objects in GCS with the given prefix
func (g *GoogleCloudStorageClient) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	bucket := g.client.Bucket(bucketName)
	query := &storage.Query{
		Prefix: prefix,
	}

	var objectKeys []string
	it := bucket.Objects(ctx, query)
	for {
		attrs, err := it.Next()
		if err == storage.ErrObjectNotExist || err == io.EOF {
			break
		}
		if err != nil {
			return nil, &StorageError{Message: "failed to list objects from GCS", Err: err}
		}
		objectKeys = append(objectKeys, attrs.Name)
	}

	return objectKeys, nil
}
