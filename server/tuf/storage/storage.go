package storage

import (
	"context"
	"faynoSync/server/utils"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func UploadMetadataToS3(ctx context.Context, adminName string, filename string, filePath string) error {
	env := viper.GetViper()
	factory := utils.NewStorageFactory(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		return fmt.Errorf("failed to create storage client: %w", err)
	}

	s3Key := fmt.Sprintf("tuf_metadata/%s/%s", adminName, filename)

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	bucketName := env.GetString("S3_BUCKET_NAME")
	if bucketName == "" {
		return fmt.Errorf("S3_BUCKET_NAME is not configured")
	}

	fileWrapper := &fileWrapper{file: file}

	_, err = storageClient.UploadPublicObject(ctx, bucketName, s3Key, fileWrapper, "application/json")
	if err != nil {
		return fmt.Errorf("failed to upload %s to S3: %w", filename, err)
	}

	logrus.Debugf("Successfully uploaded %s to S3: %s/%s", filename, bucketName, s3Key)
	return nil
}

type fileWrapper struct {
	file *os.File
}

func (f *fileWrapper) Read(p []byte) (n int, err error) {
	return f.file.Read(p)
}

func (f *fileWrapper) ReadAt(p []byte, off int64) (n int, err error) {
	return f.file.ReadAt(p, off)
}

func (f *fileWrapper) Seek(offset int64, whence int) (int64, error) {
	return f.file.Seek(offset, whence)
}

func (f *fileWrapper) Close() error {
	return f.file.Close()
}
