package storage

import (
	"context"
	"faynoSync/server/utils"
	"fmt"
	"os"
	"strconv"
	"strings"

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

func DownloadMetadataFromS3(ctx context.Context, adminName string, filename string, filePath string) error {
	env := viper.GetViper()
	factory := utils.NewStorageFactory(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		return fmt.Errorf("failed to create storage client: %w", err)
	}

	s3Key := fmt.Sprintf("tuf_metadata/%s/%s", adminName, filename)
	bucketName := env.GetString("S3_BUCKET_NAME")
	if bucketName == "" {
		return fmt.Errorf("S3_BUCKET_NAME is not configured")
	}

	if err := storageClient.DownloadObject(ctx, bucketName, s3Key, filePath); err != nil {
		return fmt.Errorf("failed to download %s from S3: %w", filename, err)
	}

	logrus.Debugf("Successfully downloaded %s from S3: %s/%s", filename, bucketName, s3Key)
	return nil
}

func ListMetadataFromS3(ctx context.Context, adminName string, prefix string) ([]string, error) {
	env := viper.GetViper()
	factory := utils.NewStorageFactory(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}

	s3Prefix := fmt.Sprintf("tuf_metadata/%s/%s", adminName, prefix)
	bucketName := env.GetString("S3_BUCKET_NAME")
	if bucketName == "" {
		return nil, fmt.Errorf("S3_BUCKET_NAME is not configured")
	}

	objects, err := storageClient.ListObjects(ctx, bucketName, s3Prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects from S3: %w", err)
	}

	metadataPrefix := fmt.Sprintf("tuf_metadata/%s/", adminName)
	var filenames []string
	for _, obj := range objects {
		if len(obj) > len(metadataPrefix) {
			filenames = append(filenames, obj[len(metadataPrefix):])
		}
	}

	return filenames, nil
}

func FindLatestMetadataVersion(ctx context.Context, adminName string, roleName string) (int, string, error) {
	if roleName == "timestamp" {
		return 0, "timestamp.json", nil
	}

	filenames, err := ListMetadataFromS3(ctx, adminName, "")
	if err != nil {
		return 0, "", fmt.Errorf("failed to list metadata files: %w", err)
	}

	var maxVersion int
	var latestFilename string
	expectedSuffix := roleName + ".json"

	for _, filename := range filenames {

		if !strings.HasSuffix(filename, expectedSuffix) {
			continue
		}

		if filename == expectedSuffix {
			if maxVersion == 0 {
				maxVersion = 1
				latestFilename = filename
			}
			continue
		}

		nameWithoutExt := strings.TrimSuffix(filename, ".json")

		lastDotIndex := strings.LastIndex(nameWithoutExt, ".")
		if lastDotIndex == -1 {
			continue
		}

		namePart := nameWithoutExt[lastDotIndex+1:]
		if namePart != roleName {
			continue
		}

		versionStr := nameWithoutExt[:lastDotIndex]
		version, err := strconv.Atoi(versionStr)
		if err != nil {
			continue
		}

		if version > maxVersion {
			maxVersion = version
			latestFilename = filename
		}
	}

	if latestFilename == "" {
		return 0, "", fmt.Errorf("no metadata file found for role: %s", roleName)
	}

	return maxVersion, latestFilename, nil
}
