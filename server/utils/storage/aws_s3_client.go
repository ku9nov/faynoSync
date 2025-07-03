package storage

import (
	"context"
	"fmt"
	"mime/multipart"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/spf13/viper"
)

// AWSS3Client implements StorageClient interface for AWS S3
type AWSS3Client struct {
	*BaseS3Client
}

// NewAWSS3Client creates a new AWS S3 client
func NewAWSS3Client(env *viper.Viper) (*AWSS3Client, error) {
	s3Config := S3Config{
		AccessKey: env.GetString("S3_ACCESS_KEY"),
		SecretKey: env.GetString("S3_SECRET_KEY"),
		Region:    env.GetString("S3_REGION"),
		// Endpoint:  env.GetString("S3_ENDPOINT"),
	}

	baseClient, err := NewBaseS3Client(env, "AWS S3", s3Config)
	if err != nil {
		return nil, err
	}

	return &AWSS3Client{
		BaseS3Client: baseClient,
	}, nil
}

// UploadPublicObject uploads a file to AWS S3 public bucket and returns the public URL
func (a *AWSS3Client) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File) (string, error) {
	_, err := a.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   fileReader,
		ACL:    types.ObjectCannedACLPublicRead,
	})
	if err != nil {
		return "", &StorageError{Message: "failed to upload public object to AWS S3", Err: err}
	}

	publicURL := fmt.Sprintf("%s/%s", a.env.GetString("S3_ENDPOINT_PUBLIC"), objectKey)
	return publicURL, nil
}
