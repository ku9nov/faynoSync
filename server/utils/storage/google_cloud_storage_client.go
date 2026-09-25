package storage

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// GoogleCloudStorageClient implements StorageClient for GCS
type GoogleCloudStorageClient struct {
	client *storage.Client
	env    *viper.Viper
	// bucket name -> uniform bucket-level access; saves a bucket.Attrs round trip per upload
	uniformAccess sync.Map
}

func (g *GoogleCloudStorageClient) bucketUniformAccess(ctx context.Context, bucketName string) (bool, error) {
	if uniform, ok := g.uniformAccess.Load(bucketName); ok {
		return uniform.(bool), nil
	}
	attrs, err := g.client.Bucket(bucketName).Attrs(ctx)
	if err != nil {
		return false, err
	}
	g.uniformAccess.Store(bucketName, attrs.UniformBucketLevelAccess.Enabled)
	return attrs.UniformBucketLevelAccess.Enabled, nil
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
	_, err := g.bucketUniformAccess(ctx, bucketName)
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
		closeErr := w.Close()
		if closeErr != nil {
			logrus.Debugf("GCS: Failed io.Copy to writer w: %v; additionally failed to close writer w: %v\n", err, closeErr)
			return &StorageError{
				Message: "failed to upload object to GCS during io.Copy to writer w and writer finalization",
				Err:     errors.Join(err, closeErr),
			}
		}
		logrus.Debugf("GCS: Failed io.Copy to writer w: %v\n", err)
		return &StorageError{Message: "failed to upload object to GCS during io.Copy to writer w", Err: err}
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
	uniform, err := g.bucketUniformAccess(ctx, bucketName)
	if err != nil {
		logrus.Debugf("GCS: Bucket %s does not exist or is not accessible: %v\n", bucketName, err)
		return "", &StorageError{Message: fmt.Sprintf("bucket %s does not exist or is not accessible", bucketName), Err: err}
	}

	logrus.Debugf("GCS: Bucket %s exists and is accessible\n", bucketName)
	logrus.Debugf("GCS: Bucket uniform access enabled: %v\n", uniform)

	w := bucket.Object(objectKey).NewWriter(ctx)

	// Set ContentType if provided
	if contentType != "" {
		w.ContentType = contentType
		logrus.Debugf("GCS: Setting ContentType to: %s\n", contentType)
	}

	// Don't set PredefinedACL if uniform bucket-level access is enabled
	if !uniform {
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

	publicURL := g.PublicObjectURL(bucketName, objectKey)
	logrus.Debugf("GCS: Upload completed successfully, public URL: %s\n", publicURL)
	return publicURL, nil
}

func (g *GoogleCloudStorageClient) UploadPublicObjectWithCacheControl(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType, cacheControl string) (string, error) {
	logrus.Debugf("GCS: Uploading public object with cache control to bucket: %s, key: %s\n", bucketName, objectKey)

	bucket := g.client.Bucket(bucketName)
	uniform, err := g.bucketUniformAccess(ctx, bucketName)
	if err != nil {
		logrus.Debugf("GCS: Bucket %s does not exist or is not accessible: %v\n", bucketName, err)
		return "", &StorageError{Message: fmt.Sprintf("bucket %s does not exist or is not accessible", bucketName), Err: err}
	}

	w := bucket.Object(objectKey).NewWriter(ctx)
	if contentType != "" {
		w.ContentType = contentType
	}
	if cacheControl != "" {
		w.CacheControl = cacheControl
	}

	if !uniform {
		w.PredefinedACL = "publicRead"
	}

	if _, err := io.Copy(w, fileReader); err != nil {
		closeErr := w.Close()
		if closeErr != nil {
			return "", &StorageError{
				Message: "failed to upload public object to GCS during io.Copy to writer w and writer finalization",
				Err:     errors.Join(err, closeErr),
			}
		}
		return "", &StorageError{Message: "failed to upload public object to GCS during io.Copy to writer w", Err: err}
	}

	if err := w.Close(); err != nil {
		return "", &StorageError{Message: "failed to finalize upload to GCS", Err: err}
	}

	return g.PublicObjectURL(bucketName, objectKey), nil
}

func (g *GoogleCloudStorageClient) CopyObject(ctx context.Context, bucketName, srcKey, dstKey string, public bool) error {
	bucket := g.client.Bucket(bucketName)
	copier := bucket.Object(dstKey).CopierFrom(bucket.Object(srcKey))
	if public {
		if uniform, err := g.bucketUniformAccess(ctx, bucketName); err == nil && !uniform {
			copier.PredefinedACL = "publicRead"
		}
	}
	if _, err := copier.Run(ctx); err != nil {
		return &StorageError{Message: "failed to copy object in GCS", Err: err}
	}
	return nil
}

func (g *GoogleCloudStorageClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	bucket := g.client.Bucket(bucketName)
	obj := bucket.Object(objectKey)
	if err := obj.Delete(ctx); err != nil {
		return &StorageError{Message: "failed to delete object from GCS", Err: err}
	}
	return nil
}

func (g *GoogleCloudStorageClient) DeleteObjects(ctx context.Context, bucketName string, objectKeys []string) error {
	for _, key := range objectKeys {
		if key == "" {
			continue
		}
		if err := g.DeleteObject(ctx, bucketName, key); err != nil {
			return err
		}
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
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, &StorageError{Message: "failed to list objects from GCS", Err: err}
		}
		objectKeys = append(objectKeys, attrs.Name)
	}

	return objectKeys, nil
}

// GetObjectETag returns object checksum (MD5 hex when available) and existence for GCS.
func (g *GoogleCloudStorageClient) GetObjectETag(ctx context.Context, bucketName, objectKey string) (string, bool, error) {
	attrs, err := g.client.Bucket(bucketName).Object(objectKey).Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return "", false, nil
		}
		return "", false, &StorageError{Message: "failed to stat object in GCS", Err: err}
	}

	if len(attrs.MD5) == 0 {
		return "", true, nil
	}

	return hex.EncodeToString(attrs.MD5), true, nil
}

func (g *GoogleCloudStorageClient) PublicObjectURL(bucketName, objectKey string) string {
	return fmt.Sprintf("https://storage.googleapis.com/%s/%s", bucketName, encodeObjectKeyForPublicURL(objectKey))
}

// PresignPutObject binds the body through the signed MD5; GCS has no signed length, the MD5 pins it.
func (g *GoogleCloudStorageClient) PresignPutObject(ctx context.Context, bucketName, objectKey string, contentMD5 []byte, length int64, contentType string, ttl time.Duration) (PresignedRequest, error) {
	if len(contentMD5) != md5.Size {
		return PresignedRequest{}, &StorageError{Message: "content MD5 must be 16 bytes"}
	}
	if length < 0 {
		return PresignedRequest{}, &StorageError{Message: "content length must not be negative"}
	}

	credsFile := g.env.GetString("GCS_CREDENTIALS_FILE")
	serviceAccount := g.env.GetString("GCS_SERVICE_ACCOUNT_EMAIL")
	if credsFile == "" || serviceAccount == "" {
		return PresignedRequest{}, &StorageError{Message: "GCS_CREDENTIALS_FILE and GCS_SERVICE_ACCOUNT_EMAIL are required for presigned URLs"}
	}

	encodedMD5 := base64.StdEncoding.EncodeToString(contentMD5)
	headers := http.Header{}
	headers.Set("Content-MD5", encodedMD5)
	if contentType != "" {
		headers.Set("Content-Type", contentType)
	}

	signedURL, err := storage.SignedURL(bucketName, objectKey, &storage.SignedURLOptions{
		GoogleAccessID: serviceAccount,
		PrivateKey:     []byte(g.env.GetString("GCS_PRIVATE_KEY")),
		Method:         http.MethodPut,
		MD5:            encodedMD5,
		ContentType:    contentType,
		Expires:        time.Now().Add(ttl),
	})
	if err != nil {
		return PresignedRequest{}, &StorageError{Message: "failed to presign upload for GCS", Err: err}
	}
	return PresignedRequest{URL: signedURL, Headers: headers}, nil
}

// StatObject never returns SHA256: GCS does not compute one.
func (g *GoogleCloudStorageClient) StatObject(ctx context.Context, bucketName, objectKey string) (ObjectStat, error) {
	attrs, err := g.client.Bucket(bucketName).Object(objectKey).Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return ObjectStat{}, ErrObjectNotFound
		}
		return ObjectStat{}, &StorageError{Message: "failed to stat object in GCS", Err: err}
	}

	stat := ObjectStat{Size: attrs.Size}
	if len(attrs.MD5) == md5.Size {
		stat.MD5 = hex.EncodeToString(attrs.MD5)
	}
	return stat, nil
}

func (g *GoogleCloudStorageClient) OpenObject(ctx context.Context, bucketName, objectKey string) (io.ReadCloser, error) {
	reader, err := g.client.Bucket(bucketName).Object(objectKey).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, ErrObjectNotFound
		}
		return nil, &StorageError{Message: "failed to open object in GCS", Err: err}
	}
	return reader, nil
}
