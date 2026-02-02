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

// StorageFactory is minimal interface for creating storage client (injectable for tests from other packages).
type StorageFactory interface {
	CreateStorageClient() (utils.StorageClient, error)
}

// ListMetadataFunc is the type for listing metadata from storage (injectable for tests from other packages).
type ListMetadataFunc func(ctx context.Context, adminName, appName, prefix string) ([]string, error)

var (
	GetViperForUpload                          = func() *viper.Viper { return viper.GetViper() }
	StorageFactoryForUpload                    = func(env *viper.Viper) StorageFactory { return utils.NewStorageFactory(env) }
	GetViperForDownload                        = func() *viper.Viper { return viper.GetViper() }
	StorageFactoryForDownload                  = func(env *viper.Viper) StorageFactory { return utils.NewStorageFactory(env) }
	getViperForList                            = func() *viper.Viper { return viper.GetViper() }
	StorageFactoryForList                      = func(env *viper.Viper) StorageFactory { return utils.NewStorageFactory(env) }
	ListMetadataForLatest     ListMetadataFunc = func(ctx context.Context, adminName, appName, prefix string) ([]string, error) {
		return ListMetadataFromS3(ctx, adminName, appName, prefix)
	}
	listMetadataForGetAllDelegatedRoles ListMetadataFunc = func(ctx context.Context, adminName, appName, prefix string) ([]string, error) {
		return ListMetadataFromS3(ctx, adminName, appName, prefix)
	}
)

func UploadMetadataToS3(ctx context.Context, adminName string, appName string, filename string, filePath string) error {
	env := GetViperForUpload()
	factory := StorageFactoryForUpload(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		return fmt.Errorf("failed to create storage client: %w", err)
	}

	s3Key := fmt.Sprintf("tuf_metadata/%s/%s/%s", adminName, appName, filename)
	bucketName := env.GetString("S3_BUCKET_NAME")
	if bucketName == "" {
		return fmt.Errorf("S3_BUCKET_NAME is not configured")
	}

	if err := uploadWithClient(ctx, storageClient, bucketName, s3Key, filePath, "application/json"); err != nil {
		return fmt.Errorf("failed to upload %s to S3: %w", filename, err)
	}

	logrus.Debugf("Successfully uploaded %s to S3: %s/%s", filename, bucketName, s3Key)
	return nil
}

func uploadWithClient(ctx context.Context, client utils.StorageClient, bucketName, s3Key, filePath, contentType string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filePath, err)
	}

	fileWrapper := &fileWrapper{file: file}
	_, err = client.UploadPublicObject(ctx, bucketName, s3Key, fileWrapper, contentType)
	if err != nil {
		return err
	}
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

func DownloadMetadataFromS3(ctx context.Context, adminName string, appName string, filename string, filePath string) error {
	env := GetViperForDownload()
	factory := StorageFactoryForDownload(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		return fmt.Errorf("failed to create storage client: %w", err)
	}

	s3Key := fmt.Sprintf("tuf_metadata/%s/%s/%s", adminName, appName, filename)
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

func ListMetadataFromS3(ctx context.Context, adminName string, appName string, prefix string) ([]string, error) {
	env := getViperForList()
	factory := StorageFactoryForList(env)
	storageClient, err := factory.CreateStorageClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}

	s3Prefix := fmt.Sprintf("tuf_metadata/%s/%s/%s", adminName, appName, prefix)
	bucketName := env.GetString("S3_BUCKET_NAME")
	if bucketName == "" {
		return nil, fmt.Errorf("S3_BUCKET_NAME is not configured")
	}

	objects, err := storageClient.ListObjects(ctx, bucketName, s3Prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects from S3: %w", err)
	}

	metadataPrefix := fmt.Sprintf("tuf_metadata/%s/%s/", adminName, appName)
	var filenames []string
	for _, obj := range objects {
		if len(obj) > len(metadataPrefix) {
			filenames = append(filenames, obj[len(metadataPrefix):])
		}
	}

	return filenames, nil
}

func FindLatestMetadataVersion(ctx context.Context, adminName string, appName string, roleName string) (int, string, error) {
	if roleName == "timestamp" {
		return 0, "timestamp.json", nil
	}

	filenames, err := ListMetadataForLatest(ctx, adminName, appName, "")
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

// GetAllDelegatedRoles returns all delegated role names found in S3 storage
func GetAllDelegatedRoles(ctx context.Context, adminName string, appName string) ([]string, error) {
	filenames, err := listMetadataForGetAllDelegatedRoles(ctx, adminName, appName, "")
	if err != nil {
		return nil, fmt.Errorf("failed to list metadata files: %w", err)
	}

	roleSet := make(map[string]bool)
	knownRoles := []string{"root", "targets", "snapshot", "timestamp"}

	for _, filename := range filenames {

		isKnownRole := false
		for _, knownRole := range knownRoles {
			if filename == knownRole+".json" || strings.HasSuffix(filename, "."+knownRole+".json") {
				isKnownRole = true
				break
			}
		}
		if isKnownRole {
			continue
		}

		nameWithoutExt := strings.TrimSuffix(filename, ".json")

		lastDotIndex := strings.LastIndex(nameWithoutExt, ".")
		if lastDotIndex == -1 {

			roleSet[nameWithoutExt] = true
		} else {

			roleName := nameWithoutExt[lastDotIndex+1:]
			versionStr := nameWithoutExt[:lastDotIndex]
			if _, err := strconv.Atoi(versionStr); err == nil {
				roleSet[roleName] = true
			}
		}
	}

	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}

	logrus.Debugf("Found %d delegated roles in S3: %v", len(roles), roles)
	return roles, nil
}
