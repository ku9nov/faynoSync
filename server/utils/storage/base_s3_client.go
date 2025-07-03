package storage

import (
	"context"
	"fmt"
	"mime/multipart"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/spf13/viper"
)

// BaseS3Client provides common S3-compatible storage functionality
type BaseS3Client struct {
	client        *s3.Client
	presignClient *s3.PresignClient
	env           *viper.Viper
	providerName  string
}

// S3Config holds configuration for S3-compatible storage
type S3Config struct {
	AccessKey string
	SecretKey string
	Region    string
	Endpoint  string
}

// NewBaseS3Client creates a new base S3 client with custom configuration
func NewBaseS3Client(env *viper.Viper, providerName string, s3Config S3Config) (*BaseS3Client, error) {
	creds := credentials.NewStaticCredentialsProvider(
		s3Config.AccessKey,
		s3Config.SecretKey,
		"",
	)

	var cfg aws.Config
	var err error

	// If endpoint is provided, use custom endpoint resolver (for DigitalOcean Spaces, MinIO, etc.)
	if s3Config.Endpoint != "" {
		customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL: fmt.Sprintf("https://%s", s3Config.Endpoint),
			}, nil
		})

		cfg, err = config.LoadDefaultConfig(
			context.TODO(),
			config.WithCredentialsProvider(creds),
			config.WithRegion(s3Config.Region),
			config.WithEndpointResolverWithOptions(customResolver),
		)
	} else {

		cfg, err = config.LoadDefaultConfig(
			context.TODO(),
			config.WithCredentialsProvider(creds),
			config.WithRegion(s3Config.Region),
		)
	}

	if err != nil {
		return nil, &StorageError{Message: fmt.Sprintf("failed to create %s client", providerName), Err: err}
	}

	client := s3.NewFromConfig(cfg)
	presignClient := s3.NewPresignClient(client)

	return &BaseS3Client{
		client:        client,
		presignClient: presignClient,
		env:           env,
		providerName:  providerName,
	}, nil
}

// UploadObject uploads a file to S3-compatible storage
func (b *BaseS3Client) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File) error {
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   fileReader,
	})
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to upload object to %s", b.providerName), Err: err}
	}
	return nil
}

// UploadObjectWithACL uploads a file to S3-compatible storage with specified ACL
func (b *BaseS3Client) UploadObjectWithACL(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, acl string) error {
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   fileReader,
		ACL:    types.ObjectCannedACL(acl),
	})
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to upload object to %s", b.providerName), Err: err}
	}
	return nil
}

// DeleteObject deletes a file from S3-compatible storage
func (b *BaseS3Client) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	_, err := b.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to delete object from %s", b.providerName), Err: err}
	}
	return nil
}

// GeneratePresignedURL generates a presigned URL for S3-compatible storage
func (b *BaseS3Client) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	request, err := b.presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = expiration
	})
	if err != nil {
		return "", &StorageError{Message: fmt.Sprintf("failed to generate presigned URL for %s", b.providerName), Err: err}
	}
	return request.URL, nil
}
