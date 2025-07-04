package storage

import (
	"context"
	"mime/multipart"
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
func (m *MinioClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File) error {
	_, err := m.client.PutObject(ctx, bucketName, objectKey, fileReader, -1, minio.PutObjectOptions{})
	if err != nil {
		return &StorageError{Message: "failed to upload object to MinIO", Err: err}
	}
	return nil
}

// UploadPublicObject uploads a file to MinIO public bucket and returns the public URL
func (m *MinioClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File) (string, error) {
	uploadInfo, err := m.client.PutObject(ctx, bucketName, objectKey, fileReader, -1, minio.PutObjectOptions{})
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
