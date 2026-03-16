package storage

import (
	"context"
	"fmt"
	"mime/multipart"
	"net/url"
	"strings"

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
	apiEndpoint := env.GetString("S3_API_ENDPOINT")
	if apiEndpoint == "" {
		for _, candidate := range []string{
			env.GetString("S3_ENDPOINT_PRIVATE"),
			env.GetString("S3_ENDPOINT"),
		} {
			if candidate != "" && !isAWSManagedS3Endpoint(candidate) {
				apiEndpoint = candidate
				break
			}
		}
	}

	s3Config := S3Config{
		AccessKey:      env.GetString("S3_ACCESS_KEY"),
		SecretKey:      env.GetString("S3_SECRET_KEY"),
		Region:         env.GetString("S3_REGION"),
		Endpoint:       apiEndpoint,
		ForcePathStyle: env.GetBool("S3_FORCE_PATH_STYLE"),
	}

	baseClient, err := NewBaseS3Client(env, "AWS S3", s3Config)
	if err != nil {
		return nil, err
	}

	return &AWSS3Client{
		BaseS3Client: baseClient,
	}, nil
}

func (a *AWSS3Client) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	input := &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   fileReader,
	}
	if !a.env.GetBool("S3_DISABLE_OBJECT_ACL") {
		input.ACL = types.ObjectCannedACLPublicRead
	}
	if contentType != "" {
		input.ContentType = aws.String(contentType)
	}
	_, err := a.client.PutObject(ctx, input)
	if err != nil {
		return "", &StorageError{Message: "failed to upload public object to AWS S3", Err: err}
	}

	publicURL := fmt.Sprintf("%s/%s", strings.TrimRight(a.env.GetString("S3_ENDPOINT"), "/"), encodeObjectKeyForPublicURL(objectKey))
	return publicURL, nil
}

func isAWSManagedS3Endpoint(endpoint string) bool {
	normalizedEndpoint := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	return strings.Contains(normalizedEndpoint, ".amazonaws.com")
}

func encodeObjectKeyForPublicURL(objectKey string) string {
	parts := strings.Split(strings.TrimLeft(objectKey, "/"), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}

	return strings.Join(parts, "/")
}
