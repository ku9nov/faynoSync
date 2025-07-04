package storage

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type StorageFactory struct {
	env *viper.Viper
}

func NewStorageFactory(env *viper.Viper) *StorageFactory {
	return &StorageFactory{env: env}
}

func (f *StorageFactory) CreateStorageClient() (StorageClient, error) {
	storageDriver := f.env.GetString("STORAGE_DRIVER")
	logrus.Debugf("Creating storage client for driver: %s", storageDriver)

	switch storageDriver {
	case "minio":
		logrus.Debugf("Creating MinIO client")
		return f.createMinioClient()
	case "aws":
		logrus.Debugf("Creating AWS S3 client")
		return f.createAWSS3Client()
	case "digitalocean":
		logrus.Debugf("Creating DigitalOcean Spaces client")
		return f.createDigitalOceanSpacesClient()
	case "gcp":
		logrus.Debugf("Creating Google Cloud Storage client")
		return f.createGoogleCloudStorageClient()
	default:
		logrus.Errorf("unknown storage driver: %s", storageDriver)
		return nil, ErrUnknownStorageDriver
	}
}

// createMinioClient creates a MinIO client
func (f *StorageFactory) createMinioClient() (StorageClient, error) {
	return NewMinioClient(f.env)
}

// createAWSS3Client creates an AWS S3 client
func (f *StorageFactory) createAWSS3Client() (StorageClient, error) {
	return NewAWSS3Client(f.env)
}

// createDigitalOceanSpacesClient creates a DigitalOcean Spaces client
func (f *StorageFactory) createDigitalOceanSpacesClient() (StorageClient, error) {
	return NewDigitalOceanSpacesClient(f.env)
}

// createGoogleCloudStorageClient creates a GCS client
func (f *StorageFactory) createGoogleCloudStorageClient() (StorageClient, error) {

	credsFile := f.env.GetString("GCS_CREDENTIALS_FILE")
	if credsFile == "" {
		logrus.Error("GCS_CREDENTIALS_FILE is required for GCP storage driver")
		return nil, &StorageError{Message: "GCS_CREDENTIALS_FILE is required for GCP storage driver"}
	}

	logrus.Debugf("Creating GCS client with credentials file: %s", credsFile)
	return NewGoogleCloudStorageClient(f.env)
}
