package storage

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"time"

	"github.com/minio/minio-go/v7"
	minioCredentials "github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/spf13/viper"
)

// MinioClient implements StorageClient interface for MinIO
type MinioClient struct {
	client *minio.Client
	env    *viper.Viper
}

// NewMinioClient creates a new MinIO client
func NewMinioClient(env *viper.Viper) (*MinioClient, error) {
	client, err := minio.New(env.GetString("S3_ENDPOINT"), &minio.Options{
		Creds:  minioCredentials.NewStaticV4(env.GetString("S3_ACCESS_KEY"), env.GetString("S3_SECRET_KEY"), ""),
		Secure: env.GetBool("MINIO_SECURE"),
	})
	if err != nil {
		return nil, &StorageError{Message: "failed to create MinIO client", Err: err}
	}

	return &MinioClient{
		client: client,
		env:    env,
	}, nil
}

// UploadObject uploads a file to MinIO private bucket
func (m *MinioClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	options := minio.PutObjectOptions{}
	if contentType != "" {
		options.ContentType = contentType
	}
	_, err := m.client.PutObject(ctx, bucketName, objectKey, fileReader, -1, options)
	if err != nil {
		return &StorageError{Message: "failed to upload object to MinIO", Err: err}
	}
	return nil
}

// UploadPublicObject uploads a file to MinIO public bucket and returns the public URL
func (m *MinioClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	options := minio.PutObjectOptions{}
	if contentType != "" {
		options.ContentType = contentType
	}
	uploadInfo, err := m.client.PutObject(ctx, bucketName, objectKey, fileReader, -1, options)
	if err != nil {
		return "", &StorageError{Message: "failed to upload public object to MinIO", Err: err}
	}
	return uploadInfo.Location, nil
}

// DeleteObject deletes a file from MinIO
func (m *MinioClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	opts := minio.RemoveObjectOptions{
		GovernanceBypass: true,
		VersionID:        "",
	}
	err := m.client.RemoveObject(ctx, bucketName, objectKey, opts)
	if err != nil {
		return &StorageError{Message: "failed to delete object from MinIO", Err: err}
	}
	return nil
}

// GeneratePresignedURL generates a presigned URL for MinIO
func (m *MinioClient) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	urlStr, err := m.client.PresignedGetObject(ctx, bucketName, objectKey, expiration, nil)
	if err != nil {
		return "", &StorageError{Message: "failed to generate presigned URL for MinIO", Err: err}
	}
	return urlStr.String(), nil
}

// DownloadObject downloads a file from MinIO to a local file path
func (m *MinioClient) DownloadObject(ctx context.Context, bucketName, objectKey string, filePath string) error {
	object, err := m.client.GetObject(ctx, bucketName, objectKey, minio.GetObjectOptions{})
	if err != nil {
		return &StorageError{Message: "failed to get object from MinIO", Err: err}
	}
	defer object.Close()

	file, err := os.Create(filePath)
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to create file %s", filePath), Err: err}
	}
	defer file.Close()

	_, err = io.Copy(file, object)
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to write to file %s", filePath), Err: err}
	}

	return nil
}

// ListObjects lists objects in MinIO with the given prefix
func (m *MinioClient) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	objectCh := m.client.ListObjects(ctx, bucketName, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	})

	var objectKeys []string
	for object := range objectCh {
		if object.Err != nil {
			return nil, &StorageError{Message: "failed to list objects from MinIO", Err: object.Err}
		}
		objectKeys = append(objectKeys, object.Key)
	}

	return objectKeys, nil
}
