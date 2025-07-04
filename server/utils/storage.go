package utils

import (
	"faynoSync/server/utils/storage"

	"github.com/spf13/viper"
)

type StorageClient = storage.StorageClient
type StorageFactory = storage.StorageFactory
type StorageError = storage.StorageError

func NewStorageFactory(env *viper.Viper) *StorageFactory {
	return storage.NewStorageFactory(env)
}

var (
	ErrUnknownStorageDriver = storage.ErrUnknownStorageDriver
	ErrClientCreationFailed = storage.ErrClientCreationFailed
	ErrUploadFailed         = storage.ErrUploadFailed
	ErrDeleteFailed         = storage.ErrDeleteFailed
	ErrPresignedURLFailed   = storage.ErrPresignedURLFailed
)
