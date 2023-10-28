package utils

import (
	"context"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func createS3Client() *s3.Client {
	env := viper.GetViper()
	// Manually set the AWS credentials and region
	creds := credentials.NewStaticCredentialsProvider(env.GetString("S3_ACCESS_KEY"), env.GetString("S3_SECRET_KEY"), "")

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(creds), config.WithRegion(env.GetString("S3_REGION")))
	if err != nil {
		log.Printf("error: %v", err)
		return nil
	}

	// Create an S3 client using the AWS config
	return s3.NewFromConfig(cfg)
}

func UploadToS3(ctxQuery map[string]interface{}, file *multipart.FileHeader, c *gin.Context, env *viper.Viper) (string, string, error) {
	// // Create an S3 client using another func
	s3Client := createS3Client()

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

		link = fmt.Sprintf("%s/%s", env.GetString("S3_ENDPOINT"), strings.Join(s3PathSegments, "/"))
		s3Key = strings.Join(s3PathSegments, "/")
	}

	// Open the file for reading
	fileReader, err := file.Open()
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open file for reading"})
	}

	// Upload file to S3
	_, err = s3Client.PutObject(c.Request.Context(), &s3.PutObjectInput{
		Bucket: aws.String(env.GetString("S3_BUCKET_NAME")),
		Key:    aws.String(s3Key),
		Body:   fileReader,
	})
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file to S3"})

	}
	return link, extension, err
}

func DeleteFromS3(objectKey string, c *gin.Context, env *viper.Viper) {

	s3Client := createS3Client()

	// Delete object from bucket
	_, err := s3Client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(env.GetString("S3_BUCKET_NAME")),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete file from S3"})
	}

	fmt.Printf("Object '%s' deleted from bucket '%s'\n", objectKey, env.GetString("S3_BUCKET_NAME"))
}
