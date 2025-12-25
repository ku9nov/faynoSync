package storage

import (
	"context"
	"mime/multipart"
	"time"
)

// StorageClient defines the interface for storage operations
type StorageClient interface {
	UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error
	UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error)
	DeleteObject(ctx context.Context, bucketName, objectKey string) error
	GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error)
	DownloadObject(ctx context.Context, bucketName, objectKey string, filePath string) error
	ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error)
}

type StorageError struct {
	Message string
	Err     error
}

func (e *StorageError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *StorageError) Unwrap() error {
	return e.Err
}

var (
	ErrUnknownStorageDriver = &StorageError{Message: "unknown storage driver"}
	ErrClientCreationFailed = &StorageError{Message: "failed to create storage client"}
	ErrUploadFailed         = &StorageError{Message: "failed to upload file"}
	ErrDeleteFailed         = &StorageError{Message: "failed to delete file"}
	ErrPresignedURLFailed   = &StorageError{Message: "failed to generate presigned URL"}
)
