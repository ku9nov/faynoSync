package utils

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type Configuration struct {
	Database DatabaseSetting
	Server   ServerSettings
}
type DatabaseSetting struct {
	Url        string
	DbName     string
	Collection string
}

type ServerSettings struct {
	Port string
}

func IsValidInputAppName(input string) bool {
	// Only allow letters and numbers, no spaces or special characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	return validName.MatchString(input)
}
func IsValidInputVersion(input string) bool {
	// Only allow letters and numbers, no spaces or special characters
	validVersion := regexp.MustCompile(`^[0-9.-]+$`)
	return validVersion.MatchString(input)
}

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

func UploadToS3(appName, version string, file *multipart.FileHeader, c *gin.Context, env *viper.Viper) string {
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
	newFileName := fmt.Sprintf("%s-%s%s", appName, version, extension)

	link := fmt.Sprintf("%s/%s/%s", env.GetString("S3_ENDPOINT"), appName, newFileName)

	// Open the file for reading
	fileReader, err := file.Open()
	if err != nil {
		logrus.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open file for reading"})
	}
	s3Key := appName + "/" + newFileName

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
	return link
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

func AuthMiddleware(db *mongo.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		bytes, err := DecryptUserCredentials(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		// extract the username and password from the decrypted bytes
		pair := strings.SplitN(string(bytes), ":", 2)
		if len(pair) != 2 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		username := pair[0]
		password := pair[1]

		// check the user credentials against the admins collection in MongoDB
		admins := db.Collection("admins")
		var result bson.M
		err = admins.FindOne(c.Request.Context(), bson.M{"username": username}).Decode(&result)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}

		// compare the hashed passwords
		hashedPassword := result["password"].(string)
		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}

		// set the authenticated user in the request context for later use
		c.Set("username", username)
		c.Next()
	}
}

func EncryptUserCredentials(data []byte) (string, error) {
	block, err := aes.NewCipher([]byte(viper.GetViper().GetString("SYSTEM_KEY")))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func DecryptUserCredentials(token string) ([]byte, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher([]byte(viper.GetViper().GetString("SYSTEM_KEY")))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
