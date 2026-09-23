package storage

import (
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

// StorageClient defines the interface for storage operations
type StorageClient interface {
	UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error
	UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error)
	CopyObject(ctx context.Context, bucketName, srcKey, dstKey string, public bool) error
	DeleteObject(ctx context.Context, bucketName, objectKey string) error
	DeleteObjects(ctx context.Context, bucketName string, objectKeys []string) error
	GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error)
	DownloadObject(ctx context.Context, bucketName, objectKey string, filePath string) error
	ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error)
}

// PresignedUploader is implemented by drivers that support direct client uploads.
// Drivers without it cannot serve presigned uploads.
type PresignedUploader interface {
	PresignPutObject(ctx context.Context, bucketName, objectKey string, contentMD5 []byte, length int64, contentType string, ttl time.Duration) (PresignedRequest, error)
	StatObject(ctx context.Context, bucketName, objectKey string) (ObjectStat, error)
	OpenObject(ctx context.Context, bucketName, objectKey string) (io.ReadCloser, error)
	PublicObjectURL(bucketName, objectKey string) string
}

// PresignedRequest is a signed PUT; the client must send Headers verbatim or the storage rejects it.
type PresignedRequest struct {
	URL     string
	Headers http.Header
}

// ObjectStat digests are hex and computed by the storage, never taken from the client.
// SHA256 is empty when the provider did not compute one; MD5 is empty for multipart objects.
type ObjectStat struct {
	Size   int64
	MD5    string
	SHA256 string
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
	ErrObjectNotFound       = &StorageError{Message: "object not found"}
)
