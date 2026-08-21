package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/spf13/viper"
)

// BaseS3Client provides common S3-compatible storage functionality
type BaseS3Client struct {
	client         *s3.Client
	presignClient  *s3.PresignClient
	privateClient  *s3.Client
	privatePresign *s3.PresignClient
	privateBucket  string
	env            *viper.Viper
	providerName   string
}

// S3Config holds configuration for S3-compatible storage
type S3Config struct {
	AccessKey       string
	SecretKey       string
	Region          string
	PrivateRegion   string
	Endpoint        string
	PrivateEndpoint string
	ForcePathStyle  bool
}

// NewBaseS3Client creates a new base S3 client with custom configuration
func NewBaseS3Client(env *viper.Viper, providerName string, s3Config S3Config) (*BaseS3Client, error) {
	creds := credentials.NewStaticCredentialsProvider(
		s3Config.AccessKey,
		s3Config.SecretKey,
		"",
	)

	client, err := newRegionalS3Client(creds, s3Config, s3Config.Region, s3Config.Endpoint)
	if err != nil {
		return nil, &StorageError{Message: fmt.Sprintf("failed to create %s client", providerName), Err: err}
	}

	baseClient := &BaseS3Client{
		client:        client,
		presignClient: s3.NewPresignClient(client),
		env:           env,
		providerName:  providerName,
	}

	// The private bucket may live in another region than the public one, which needs its own signing region.
	privateBucket := env.GetString("S3_BUCKET_NAME_PRIVATE")
	if s3Config.PrivateRegion != "" && s3Config.PrivateRegion != s3Config.Region && privateBucket != "" {
		// Providers with regional endpoints (DigitalOcean Spaces) need the endpoint to match the signing region.
		privateEndpoint := s3Config.PrivateEndpoint
		if privateEndpoint == "" {
			privateEndpoint = s3Config.Endpoint
		}

		privateClient, err := newRegionalS3Client(creds, s3Config, s3Config.PrivateRegion, privateEndpoint)
		if err != nil {
			return nil, &StorageError{Message: fmt.Sprintf("failed to create %s client for private bucket region", providerName), Err: err}
		}

		baseClient.privateClient = privateClient
		baseClient.privatePresign = s3.NewPresignClient(privateClient)
		baseClient.privateBucket = privateBucket
	}

	return baseClient, nil
}

func newRegionalS3Client(creds aws.CredentialsProvider, s3Config S3Config, region, endpoint string) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithCredentialsProvider(creds),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(cfg, func(options *s3.Options) {
		if endpoint == "" {
			return
		}

		options.BaseEndpoint = aws.String(normalizeEndpointURL(endpoint))
		options.UsePathStyle = s3Config.ForcePathStyle
	}), nil
}

func (b *BaseS3Client) clientFor(bucketName string) *s3.Client {
	if b.privateClient != nil && bucketName == b.privateBucket {
		return b.privateClient
	}

	return b.client
}

func (b *BaseS3Client) presignClientFor(bucketName string) *s3.PresignClient {
	if b.privatePresign != nil && bucketName == b.privateBucket {
		return b.privatePresign
	}

	return b.presignClient
}

func normalizeEndpointURL(endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}

	return fmt.Sprintf("https://%s", endpoint)
}

// UploadObject uploads a file to S3-compatible storage
func (b *BaseS3Client) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	input := &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   fileReader,
	}
	if contentType != "" {
		input.ContentType = aws.String(contentType)
	}
	_, err := b.clientFor(bucketName).PutObject(ctx, input)
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to upload object to %s", b.providerName), Err: err}
	}
	return nil
}

// UploadObjectWithACL uploads a file to S3-compatible storage with specified ACL
func (b *BaseS3Client) UploadObjectWithACL(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, acl string) error {
	_, err := b.clientFor(bucketName).PutObject(ctx, &s3.PutObjectInput{
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

func (b *BaseS3Client) CopyObject(ctx context.Context, bucketName, srcKey, dstKey string, public bool) error {
	input := &s3.CopyObjectInput{
		Bucket:     aws.String(bucketName),
		Key:        aws.String(dstKey),
		CopySource: aws.String(bucketName + "/" + encodeObjectKeyForPublicURL(srcKey)),
	}
	if public && !b.env.GetBool("S3_DISABLE_OBJECT_ACL") {
		input.ACL = types.ObjectCannedACLPublicRead
	}
	_, err := b.clientFor(bucketName).CopyObject(ctx, input)
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to copy object in %s", b.providerName), Err: err}
	}
	return nil
}

// DeleteObject deletes a file from S3-compatible storage
func (b *BaseS3Client) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	_, err := b.clientFor(bucketName).DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to delete object from %s", b.providerName), Err: err}
	}
	return nil
}

// DeleteObjects deletes multiple files from S3-compatible storage in batches.
func (b *BaseS3Client) DeleteObjects(ctx context.Context, bucketName string, objectKeys []string) error {
	if len(objectKeys) == 0 {
		return nil
	}

	const maxBatchSize = 1000
	for start := 0; start < len(objectKeys); start += maxBatchSize {
		end := start + maxBatchSize
		if end > len(objectKeys) {
			end = len(objectKeys)
		}

		objects := make([]types.ObjectIdentifier, 0, end-start)
		for _, key := range objectKeys[start:end] {
			if key == "" {
				continue
			}
			objects = append(objects, types.ObjectIdentifier{Key: aws.String(key)})
		}

		if len(objects) == 0 {
			continue
		}

		output, err := b.clientFor(bucketName).DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(bucketName),
			Delete: &types.Delete{
				Objects: objects,
				Quiet:   aws.Bool(true),
			},
		})
		if err != nil {
			return &StorageError{Message: fmt.Sprintf("failed to delete objects from %s", b.providerName), Err: err}
		}

		if len(output.Errors) > 0 {
			firstErr := output.Errors[0]
			errMsg := fmt.Sprintf("key=%s code=%s message=%s",
				aws.ToString(firstErr.Key),
				aws.ToString(firstErr.Code),
				aws.ToString(firstErr.Message),
			)
			return &StorageError{Message: fmt.Sprintf("failed to delete objects from %s (%s)", b.providerName, errMsg)}
		}
	}

	return nil
}

// GeneratePresignedURL generates a presigned URL for S3-compatible storage
func (b *BaseS3Client) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	request, err := b.presignClientFor(bucketName).PresignGetObject(ctx, &s3.GetObjectInput{
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

// DownloadObject downloads a file from S3-compatible storage to a local file path
func (b *BaseS3Client) DownloadObject(ctx context.Context, bucketName, objectKey string, filePath string) error {
	result, err := b.clientFor(bucketName).GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to download object from %s", b.providerName), Err: err}
	}
	defer result.Body.Close()

	file, err := os.Create(filePath)
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to create file %s", filePath), Err: err}
	}
	defer file.Close()

	_, err = io.Copy(file, result.Body)
	if err != nil {
		return &StorageError{Message: fmt.Sprintf("failed to write to file %s", filePath), Err: err}
	}

	return nil
}

// ListObjects lists objects in S3-compatible storage with the given prefix
func (b *BaseS3Client) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
		Prefix: aws.String(prefix),
	}

	var objectKeys []string
	paginator := s3.NewListObjectsV2Paginator(b.clientFor(bucketName), input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, &StorageError{Message: fmt.Sprintf("failed to list objects from %s", b.providerName), Err: err}
		}

		for _, obj := range page.Contents {
			objectKeys = append(objectKeys, *obj.Key)
		}
	}

	return objectKeys, nil
}

// GetObjectETag returns object ETag and existence for S3-compatible storage.
func (b *BaseS3Client) GetObjectETag(ctx context.Context, bucketName, objectKey string) (string, bool, error) {
	output, err := b.clientFor(bucketName).HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			switch apiErr.ErrorCode() {
			case "NotFound", "NoSuchKey":
				return "", false, nil
			}
		}

		return "", false, &StorageError{
			Message: fmt.Sprintf("failed to stat object in %s", b.providerName),
			Err:     err,
		}
	}

	return strings.Trim(aws.ToString(output.ETag), "\""), true, nil
}
