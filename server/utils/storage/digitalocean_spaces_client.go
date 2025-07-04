package storage

import (
	"context"
	"fmt"
	"mime/multipart"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/spf13/viper"
)

// DigitalOceanSpacesClient implements StorageClient interface for DigitalOcean Spaces
type DigitalOceanSpacesClient struct {
	*BaseS3Client
}

// NewDigitalOceanSpacesClient creates a new DigitalOcean Spaces client
func NewDigitalOceanSpacesClient(env *viper.Viper) (*DigitalOceanSpacesClient, error) {
	s3Config := S3Config{
		AccessKey: env.GetString("S3_ACCESS_KEY"),
		SecretKey: env.GetString("S3_SECRET_KEY"),
		Region:    env.GetString("S3_REGION"),
		Endpoint:  env.GetString("S3_ENDPOINT"),
	}

	baseClient, err := NewBaseS3Client(env, "DigitalOcean Spaces", s3Config)
	if err != nil {
		return nil, err
	}

	return &DigitalOceanSpacesClient{
		BaseS3Client: baseClient,
	}, nil
}

func (d *DigitalOceanSpacesClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File) error {
	_, err := d.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   fileReader,
	})
	if err != nil {
		return &StorageError{Message: "failed to upload object to DigitalOcean Spaces", Err: err}
	}
	return nil
}

// UploadPublicObject uploads a file to DigitalOcean Spaces public bucket and returns the public URL
func (d *DigitalOceanSpacesClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File) (string, error) {
	_, err := d.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   fileReader,
		ACL:    types.ObjectCannedACLPublicRead, // Set ACL to make the object publicly readable
	})
	if err != nil {
		return "", &StorageError{Message: "failed to upload public object to DigitalOcean Spaces", Err: err}
	}

	spacesEndpoint := d.env.GetString("S3_ENDPOINT")
	publicURL := fmt.Sprintf("https://%s.%s/%s", bucketName, spacesEndpoint, objectKey)
	return publicURL, nil
}

// DeleteObject deletes a file from DigitalOcean Spaces
func (d *DigitalOceanSpacesClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	_, err := d.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return &StorageError{Message: "failed to delete object from DigitalOcean Spaces", Err: err}
	}
	return nil
}

// GeneratePresignedURL generates a presigned URL for DigitalOcean Spaces
func (d *DigitalOceanSpacesClient) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	request, err := d.presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = expiration
	})
	if err != nil {
		return "", &StorageError{Message: "failed to generate presigned URL for DigitalOcean Spaces", Err: err}
	}
	return request.URL, nil
}
