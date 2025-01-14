package utils

import (
	"context"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/gin-gonic/gin"
	"github.com/minio/minio-go/v7"
	minioCredentials "github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func createStorageClient() interface{} {
	env := viper.GetViper()

	storageDriver := env.GetString("STORAGE_DRIVER")

	switch storageDriver {
	case "minio":
		// Set up Minio client
		minioClient, err := minio.New(env.GetString("S3_ENDPOINT"), &minio.Options{
			Creds:  minioCredentials.NewStaticV4(env.GetString("S3_ACCESS_KEY"), env.GetString("S3_SECRET_KEY"), ""),
			Secure: env.GetBool("MINIO_SECURE"),
		})
		if err != nil {
			logrus.Errorf("error setting up Minio client: %v", err)
			return nil
		}
		return minioClient

	case "aws":
		// Set up AWS S3 client
		creds := credentials.NewStaticCredentialsProvider(env.GetString("S3_ACCESS_KEY"), env.GetString("S3_SECRET_KEY"), "")
		cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(creds), config.WithRegion(env.GetString("S3_REGION")))
		if err != nil {
			logrus.Errorf("error setting up AWS S3 client: %v", err)
			return nil
		}
		return s3.NewFromConfig(cfg)

	default:
		logrus.Errorf("unknown storage driver: %s", storageDriver)
		return nil
	}
}

func UploadToS3(ctxQuery map[string]interface{}, file *multipart.FileHeader, c *gin.Context, env *viper.Viper) (string, string, error) {
	// // Create an S3 client using another func
	storageClient := createStorageClient()

	if storageClient == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create storage client"})
		return "", "", errors.New("failed to create storage client")
	}

	var extension string
	// Extract base filename and extension
	baseFileName := file.Filename
	dotIndex := strings.Index(baseFileName, ".")
	if dotIndex > -1 {
		extension = baseFileName[dotIndex:]
	}
	// Generate new file name
	newFileName := fmt.Sprintf("%s-%s%s", ctxQuery["app_name"].(string), ctxQuery["version"].(string), extension)

	var link string
	var s3Key string
	if ctxQuery["channel"].(string) == "" && ctxQuery["platform"].(string) == "" && ctxQuery["arch"].(string) == "" {
		link = fmt.Sprintf("%s/%s/%s", env.GetString("S3_ENDPOINT"), ctxQuery["app_name"].(string), newFileName)
		s3Key = ctxQuery["app_name"].(string) + "/" + newFileName
	} else {
		s3PathSegments := []string{ctxQuery["app_name"].(string)}

		if ctxQuery["channel"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["channel"].(string))
		}

		if ctxQuery["platform"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["platform"].(string))
		}

		if ctxQuery["arch"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["arch"].(string))
		}

		s3PathSegments = append(s3PathSegments, newFileName)
		encodedPath := url.PathEscape(strings.Join(s3PathSegments, "/"))
		link = fmt.Sprintf("%s/%s", env.GetString("S3_ENDPOINT"), encodedPath)
		s3Key = strings.Join(s3PathSegments, "/")
	}

	// Open the file for reading
	fileReader, err := file.Open()
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open file for reading"})
	}

	// Upload file to S3
	switch client := storageClient.(type) {
	case *minio.Client:
		var uploadInfo minio.UploadInfo
		uploadInfo, err = client.PutObject(c.Request.Context(), env.GetString("S3_BUCKET_NAME"), s3Key, fileReader, -1, minio.PutObjectOptions{})

		logrus.Debugln("Upload Info:", uploadInfo)
		link = uploadInfo.Location
	case *s3.Client:
		_, err = client.PutObject(c.Request.Context(), &s3.PutObjectInput{
			Bucket: aws.String(env.GetString("S3_BUCKET_NAME")),
			Key:    aws.String(s3Key),
			Body:   fileReader,
		})
	default:
		logrus.Errorf("unknown storage client type")
		return "", "", errors.New("unknown storage client type")
	}
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file to S3"})

	}
	return link, extension, err
}

func DeleteFromS3(objectKey string, c *gin.Context, env *viper.Viper) {

	storageClient := createStorageClient()

	if storageClient == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create storage client"})
	}
	var err error
	objectKey = strings.TrimPrefix(objectKey, "/")
	// Delete object from bucket
	switch client := storageClient.(type) {
	case *minio.Client:
		opts := minio.RemoveObjectOptions{
			GovernanceBypass: true,
			VersionID:        "",
		}
		var objectKeyAfterBucket string
		parts := strings.Split(objectKey, env.GetString("S3_BUCKET_NAME"))
		if len(parts) > 1 {
			objectKeyAfterBucket = strings.TrimPrefix(parts[1], "/")
			logrus.Infof("Deleting object with key after bucket name: '%s'", objectKeyAfterBucket)
		}
		decodedKey, err := url.QueryUnescape(objectKeyAfterBucket)
		if err != nil {
			logrus.Error("Failed to decode object key: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode object key"})
			return
		}
		err = client.RemoveObject(context.Background(), env.GetString("S3_BUCKET_NAME"), decodedKey, opts)
		if err != nil {
			logrus.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete file from Minio"})
		}

	case *s3.Client:
		_, err = client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(env.GetString("S3_BUCKET_NAME")),
			Key:    aws.String(objectKey),
		})
		if err != nil {
			logrus.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete file from S3"})
		}
	default:
		logrus.Errorf("unknown storage client type")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unknown storage client type"})
	}

	logrus.Infof("Object '%s' deleted from bucket '%s'\n", objectKey, env.GetString("S3_BUCKET_NAME"))
}
