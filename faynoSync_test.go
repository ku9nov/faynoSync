package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"faynoSync/mongod"
	"faynoSync/redisdb"
	"faynoSync/server/handler"
	"faynoSync/server/model"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

var (
	client        *mongo.Client
	appDB         mongod.AppRepository
	mongoDatabase *mongo.Database
	configDB      connstring.ConnString
	s3Endpoint    string
	s3Bucket      string
	apiKey        string
	redisClient   *redis.Client
)

func TestMain(m *testing.M) {
	// Set up resources before running tests
	setup()
	// Run the tests
	code := m.Run()
	teardown()
	os.Exit(code)
}

func copyFile(src, dst string) {
	input, err := os.ReadFile(src)
	if err != nil {
		logrus.Errorf("Failed to read the file: %v", err)
		return
	}

	err = os.WriteFile(dst, input, 0644)
	if err != nil {
		logrus.Errorf("Failed to copy the file: %v", err)
		return
	}
}

func removeFile(filename string) {
	err := os.Remove(filename)
	if err != nil {
		logrus.Errorf("Failed to remove the file: %v", err)
		return
	}
}

func setup() {
	viper.SetConfigType("env")
	viper.SetConfigName(".env")
	// set the configuration file path
	viper.AddConfigPath(".")
	// read in the configuration file
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}
	// Create a single database connection
	flagMap := map[string]interface{}{
		"migration": true,
		"rollback":  false,
	}
	s3Endpoint = viper.GetString("S3_ENDPOINT")
	s3Bucket = viper.GetString("S3_BUCKET_NAME")
	client, configDB = mongod.ConnectToDatabase(viper.GetString("MONGODB_URL_TESTS"), flagMap)
	appDB = mongod.NewAppRepository(&configDB, client)
	mongoDatabase = client.Database(configDB.Database)
	if viper.GetBool("PERFORMANCE_MODE") {
		redisConfig := redisdb.RedisConfig{
			Addr:     viper.GetString("REDIS_HOST") + ":" + viper.GetString("REDIS_PORT"),
			Password: viper.GetString("REDIS_PASSWORD"),
			DB:       viper.GetInt("REDIS_DB"),
		}
		redisClient = redisdb.ConnectToRedis(redisConfig)
	}
	os.Setenv("API_KEY", viper.GetString("API_KEY"))
	apiKey = viper.GetString("API_KEY")
	copyFile("LICENSE", "testapp.dmg")
	copyFile("LICENSE", "testapp.pkg")

}

func teardown() {
	adminsCollection := mongoDatabase.Collection("admins")
	filter := bson.M{"username": "admin"}

	// Delete the admin user from the collection
	_, err := adminsCollection.DeleteOne(context.TODO(), filter)
	if err != nil {
		logrus.Errorf("Failed to remove admin user: %v", err)
	}
	logrus.Infoln("Successfully removed admin user.")
	client.Disconnect(context.Background())
	logrus.Infoln("MongoDB is disconnected.")
	removeFile("testapp.dmg")
	removeFile("testapp.pkg")
}

func TestHealthCheck(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/health", func(c *gin.Context) {
		handler.HealthCheck(c)
	})

	req, _ := http.NewRequest("GET", "/health", nil)

	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	// Check the response body.
	expected := `{"status":"healthy"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestFailedSignUp(t *testing.T) {
	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/signup", func(c *gin.Context) {
		handler.SignUp(c)
	})

	payload := `{"username": "admin", "password": "password", "api_key": "UHp3aKb40poKZluZByWQ"}`
	req, err := http.NewRequest("POST", "/signup", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Parse the JSON response body to extract the token.
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"error":"wrong api key"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestSignUp(t *testing.T) {
	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/signup", func(c *gin.Context) {
		handler.SignUp(c)
	})

	regKey := os.Getenv("API_KEY")
	payload := fmt.Sprintf(`{"username": "admin", "password": "password", "api_key": "%s"}`, regKey)
	req, err := http.NewRequest("POST", "/signup", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the JSON response body to extract the token.
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"result":"Successfully created admin user."}`
	assert.Equal(t, expected, w.Body.String())
}

func TestFailedLogin(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/login", func(c *gin.Context) {
		handler.Login(c)
	})

	// Create a JSON payload for the request
	payload := `{"username": "admin", "password": "password1"}`

	req, err := http.NewRequest("POST", "/login", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Parse the JSON response body to extract the token.
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"error":"invalid username or password"}`
	assert.Equal(t, expected, w.Body.String())
}

var authToken string

func TestLogin(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/login", func(c *gin.Context) {
		handler.Login(c)
	})

	// Create a JSON payload for the request
	payload := `{"username": "admin", "password": "password"}`

	req, err := http.NewRequest("POST", "/login", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the JSON response body to extract the token.
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the "token" key exists in the response.
	token, tokenExists := response["token"]
	assert.True(t, tokenExists)

	authToken = token.(string)

	// Check that the authToken variable has been set (assuming authToken is a global variable).
	assert.NotEmpty(t, authToken)
}

func TestListApps(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /app/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/app/list", func(c *gin.Context) {
		handler.ListApps(c)
	})

	// Create a POST request for the /app/list endpoint.
	req, err := http.NewRequest("GET", "/app/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"apps":null}`
	assert.Equal(t, expected, w.Body.String())
}

func TestListAppsWithInvalidToken(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/app/list", func(c *gin.Context) {
		handler.ListApps(c)
	})

	tests := []struct {
		name      string
		modifyFn  func(token string) string
		expectErr bool
	}{
		{
			name: "Modified header",
			modifyFn: func(token string) string {
				parts := strings.Split(token, ".")
				parts[0] = parts[0][:len(parts[0])-1] + "X" // Modify header
				return strings.Join(parts, ".")
			},
			expectErr: true,
		},
		{
			name: "Modified payload",
			modifyFn: func(token string) string {
				parts := strings.Split(token, ".")
				parts[1] = parts[1][:len(parts[1])-1] + "Y" // Modify payload
				return strings.Join(parts, ".")
			},
			expectErr: true,
		},
		{
			name: "Modified signature",
			modifyFn: func(token string) string {
				parts := strings.Split(token, ".")
				parts[2] = parts[2][:len(parts[2])-1] + "Z" // Modify signature
				return strings.Join(parts, ".")
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifiedToken := tt.modifyFn(authToken)

			logrus.Infof("Testing with token: %s", modifiedToken)

			req, err := http.NewRequest("GET", "/app/list", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Authorization", "Bearer "+modifiedToken)

			router.ServeHTTP(w, req)

			logrus.Infof("Status code for %s: %d", tt.name, w.Code)
			logrus.Infof("Response body: %s", w.Body.String())

			if tt.expectErr {
				assert.Equal(t, http.StatusUnauthorized, w.Code)
			} else {
				assert.Equal(t, http.StatusOK, w.Code)
			}
		})
	}
}

var idTestappApp string

func TestAppCreate(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/app/create", func(c *gin.Context) {
		handler.CreateApp(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"app": "testapp"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /app/create endpoint
	req, err := http.NewRequest("POST", "/app/create", body)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Check for the presence of the "createAppResult.Created" key in the response
	id, idExists := response["createAppResult.Created"]
	assert.True(t, idExists)
	idTestappApp = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, idTestappApp)
}

func TestSecondaryAppCreate(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/app/create", func(c *gin.Context) {
		handler.CreateApp(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"app": "testapp"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /app/create endpoint
	req, err := http.NewRequest("POST", "/app/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 500).
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"app with this name already exists"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

var uploadedFirstApp string

func TestUpload(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/upload", func(c *gin.Context) {
		handler.UploadApp(c)
	})

	// Create a file to upload (you can replace this with a test file path).
	filePath := "LICENSE"
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// Create a multipart/form-data request with the file.
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(part, file)
	if err != nil {
		t.Fatal(err)
	}
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"app_name": "testapp", "version": "0.0.1.137"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request for the /upload endpoint.
	req, err := http.NewRequest("POST", "/upload", body)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Content-Type header for multipart/form-data.
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	logrus.Infof("Response Body after unmarshaling: %+v", response)
	// Check that the "token" key exists in the response.
	id, idExists := response["uploadResult.Uploaded"]
	assert.True(t, idExists)

	uploadedFirstApp = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, uploadedFirstApp)
}

func TestUploadDuplicateApp(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/upload", func(c *gin.Context) {
		handler.UploadApp(c)
	})

	// Create a file to upload (you can replace this with a test file path).
	filePath := "LICENSE"
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// Create a multipart/form-data request with the file.
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(part, file)
	if err != nil {
		t.Fatal(err)
	}
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"app_name": "testapp", "version": "0.0.1.137"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request for the /upload endpoint.
	req, err := http.NewRequest("POST", "/upload", body)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Content-Type header for multipart/form-data.
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code (expecting 500).
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"app with this name, version, platform, architecture and extension already exists"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

func TestDeleteApp(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /apps/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.DELETE("/apps/delete", func(c *gin.Context) {
		handler.DeleteSpecificVersionOfApp(c)
	})

	// Create a POST request for the /apps/delete endpoint.
	req, err := http.NewRequest("DELETE", "/apps/delete?id="+uploadedFirstApp, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deleteSpecificAppResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}

func TestListChannels(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/channel/list", func(c *gin.Context) {
		handler.ListChannels(c)
	})

	// Create a POST request for the /channel/list endpoint.
	req, err := http.NewRequest("GET", "/channel/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"channels":null}`
	assert.Equal(t, expected, w.Body.String())
}

var idNightlyChannel string
var idStableChannel string

func TestChannelCreateNightly(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /channel/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/channel/create", func(c *gin.Context) {
		handler.CreateChannel(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"channel": "nightly"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/channel/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Check for the presence of the "createChannelResult.Created" key in the response
	id, idExists := response["createChannelResult.Created"]
	assert.True(t, idExists)
	idNightlyChannel = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, idNightlyChannel)
}
func TestChannelCreateWithWrongName(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /channel/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/channel/create", func(c *gin.Context) {
		handler.CreateChannel(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"channel": "nightly *"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/channel/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 400).
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"invalid channel name"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}
func TestSecondaryChannelCreateNightly(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /channel/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/channel/create", func(c *gin.Context) {
		handler.CreateChannel(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"channel": "nightly"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/channel/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 500).
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"channel with this name already exists"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

func TestChannelCreateStable(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /channel/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/channel/create", func(c *gin.Context) {
		handler.CreateChannel(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"channel": "stable"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/channel/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Check for the presence of the "createChannelResult.Created" key in the response
	id, idExists := response["createChannelResult.Created"]
	assert.True(t, idExists)
	idStableChannel = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, idStableChannel)
}

func TestUploadAppWithoutChannel(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/upload", func(c *gin.Context) {
		handler.UploadApp(c)
	})

	// Create a file to upload (you can replace this with a test file path).
	filePath := "LICENSE"
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// Create a multipart/form-data request with the file.
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(part, file)
	if err != nil {
		t.Fatal(err)
	}
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"app_name": "testapp", "version": "0.0.1.137"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("POST", "/upload", body)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Content-Type header for multipart/form-data.
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code (expecting 500).
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"you have a created channels, setting channel is required"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

func TestListPlatforms(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/platform/list", func(c *gin.Context) {
		handler.ListPlatforms(c)
	})

	// Create a POST request for the /platform/list endpoint.
	req, err := http.NewRequest("GET", "/platform/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"platforms":null}`
	assert.Equal(t, expected, w.Body.String())
}

var platformId string

func TestPlatformCreate(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/platform/create", func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"platform": "universalPlatform"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /platform/create endpoint
	req, err := http.NewRequest("POST", "/platform/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	id, idExists := response["createPlatformResult.Created"]
	assert.True(t, idExists)
	platformId = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, platformId)
}
func TestSecondaryPlatformCreate(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/platform/create", func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"platform": "universalPlatform"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /platform/create endpoint
	req, err := http.NewRequest("POST", "/platform/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 500).
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"platform with this name already exists"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

var secondPlatformId string

func TestCreateSecondPlatform(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/platform/create", func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"platform": "secondPlatform"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /platform/create endpoint
	req, err := http.NewRequest("POST", "/platform/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	id, idExists := response["createPlatformResult.Created"]
	assert.True(t, idExists)
	secondPlatformId = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, secondPlatformId)
}

func TestUploadAppWithoutPlatform(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/upload", func(c *gin.Context) {
		handler.UploadApp(c)
	})

	// Create a file to upload (you can replace this with a test file path).
	filePath := "LICENSE"
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// Create a multipart/form-data request with the file.
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(part, file)
	if err != nil {
		t.Fatal(err)
	}
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"app_name": "testapp", "version": "0.0.1.137", "channel": "nightly"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("POST", "/upload", body)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Content-Type header for multipart/form-data.
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code (expecting 500).
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"you have a created platforms, setting platform is required"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

func TestListArchs(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /arch/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/arch/list", func(c *gin.Context) {
		handler.ListArchs(c)
	})

	// Create a POST request for the /arch/list endpoint.
	req, err := http.NewRequest("GET", "/arch/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"archs":null}`
	assert.Equal(t, expected, w.Body.String())
}

var archId string

func TestArchCreate(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/arch/create", func(c *gin.Context) {
		handler.CreateArch(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"arch": "universalArch"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/arch/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	id, idExists := response["createArchResult.Created"]
	assert.True(t, idExists)
	archId = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, archId)
}
func TestSecondaryArchCreate(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/arch/create", func(c *gin.Context) {
		handler.CreateArch(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the arch to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"arch": "universalArch"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/arch/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 500).
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"arch with this name already exists"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

var secondArchId string

func TestCreateSecondArch(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/arch/create", func(c *gin.Context) {
		handler.CreateArch(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"arch": "secondArch"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/arch/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	id, idExists := response["createArchResult.Created"]
	assert.True(t, idExists)
	secondArchId = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, secondArchId)
}

func TestUploadAppWithoutArch(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/upload", func(c *gin.Context) {
		handler.UploadApp(c)
	})

	// Create a file to upload (you can replace this with a test file path).
	filePath := "LICENSE"
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// Create a multipart/form-data request with the file.
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(part, file)
	if err != nil {
		t.Fatal(err)
	}
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"app_name": "testapp", "version": "0.0.1.137", "channel": "nightly", "platform": "universalPlatform"}`
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("POST", "/upload", body)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Content-Type header for multipart/form-data.
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code (expecting 500).
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"you have a created archs, setting arch is required"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

var uploadedAppIDs []string

func TestMultipleUpload(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/upload", func(c *gin.Context) {
		handler.UploadApp(c)
	})

	// Create a file to upload (you can replace this with a test file path).
	filePaths := []string{"testapp.dmg", "testapp.pkg", "LICENSE"}
	for _, filePath := range filePaths {
		file, err := os.Open(filePath)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		combinations := []struct {
			AppVersion  string
			ChannelName string
			Published   bool
			Critical    bool
			Platform    string
			Arch        string
		}{
			{"0.0.1.137", "nightly", true, false, "universalPlatform", "universalArch"},
			{"0.0.2.137", "nightly", true, false, "universalPlatform", "universalArch"},
			{"0.0.3.137", "nightly", false, false, "universalPlatform", "universalArch"},
			{"0.0.4.137", "stable", true, true, "universalPlatform", "universalArch"},
			{"0.0.5.137", "stable", false, false, "universalPlatform", "universalArch"},
		}

		// Iterate through the combinations and upload the file for each combination.
		for _, combo := range combinations {
			w := httptest.NewRecorder()
			// Reset the request body for each iteration.
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)
			part, err := writer.CreateFormFile("file", filepath.Base(filePath))
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(part, file)
			if err != nil {
				t.Fatal(err)
			}
			dataPart, err := writer.CreateFormField("data")
			if err != nil {
				t.Fatal(err)
			}
			payload := fmt.Sprintf(`{"app_name": "testapp", "version": "%s", "channel": "%s", "publish": %v, "critical": %v, "platform": "%s", "arch": "%s"}`, combo.AppVersion, combo.ChannelName, combo.Published, combo.Critical, combo.Platform, combo.Arch)
			_, err = dataPart.Write([]byte(payload))
			if err != nil {
				t.Fatal(err)
			}

			// Close the writer to finalize the form
			err = writer.Close()
			if err != nil {
				t.Fatal(err)
			}
			// Create a POST request for the /upload endpoint with the current combination.
			req, err := http.NewRequest("POST", "/upload", body)
			if err != nil {
				t.Fatal(err)
			}

			// Set the Content-Type header for multipart/form-data.
			req.Header.Set("Content-Type", writer.FormDataContentType())

			// Set the Authorization header.
			req.Header.Set("Authorization", "Bearer "+authToken)
			// Serve the request using the Gin router.
			router.ServeHTTP(w, req)

			// Check the response status code.
			assert.Equal(t, http.StatusOK, w.Code)
			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			if err != nil {
				t.Fatal(err)
			}

			id, idExists := response["uploadResult.Uploaded"]
			assert.True(t, idExists)

			// Check if the id already exists in the uploadedAppIDs array
			exists := false
			for _, val := range uploadedAppIDs {
				if val == id {
					exists = true
					break
				}
			}

			// If id does not exist in the array, append it
			if !exists {
				uploadedAppIDs = append(uploadedAppIDs, id.(string))
			}

			assert.True(t, idExists)
			assert.NotEmpty(t, id.(string))
		}
	}
}

func TestUpdateSpecificApp(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	// Define the route for the update endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/apps/update", func(c *gin.Context) {
		handler.UpdateSpecificApp(c)
	})

	// Create a file to update (you can replace this with a test file path).
	filePaths := []string{"LICENSE", "LICENSE"}
	for _, filePath := range filePaths {
		file, err := os.Open(filePath)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		combinations := []struct {
			ID          string
			AppVersion  string
			ChannelName string
			Published   bool
			Critical    bool
			Platform    string
			Arch        string
			Changelog   string
		}{
			{uploadedAppIDs[1], "0.0.2.137", "nightly", true, true, "universalPlatform", "universalArch", "### Changelog"},
		}

		// Iterate through the combinations and update the file for each combination.
		for _, combo := range combinations {
			w := httptest.NewRecorder()
			// Reset the request body for each iteration.
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)
			part, err := writer.CreateFormFile("file", filepath.Base(filePath))
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(part, file)
			if err != nil {
				t.Fatal(err)
			}
			// Create a POST request for the update endpoint with the current combination.
			dataPart, err := writer.CreateFormField("data")
			if err != nil {
				t.Fatal(err)
			}
			payload := fmt.Sprintf(`{"id": "%s", "app_name": "testapp", "version": "%s", "channel": "%s", "publish": %v, "critical": %v, "platform": "%s", "arch": "%s", "changelog": "%s"}`, combo.ID, combo.AppVersion, combo.ChannelName, combo.Published, combo.Critical, combo.Platform, combo.Arch, combo.Changelog)
			_, err = dataPart.Write([]byte(payload))
			if err != nil {
				t.Fatal(err)
			}

			// Close the writer to finalize the form
			err = writer.Close()
			if err != nil {
				t.Fatal(err)
			}
			// logrus.Infoln("Body: ", body)
			req, err := http.NewRequest("POST", "/apps/update", body)
			if err != nil {
				t.Fatal(err)
			}

			// Set the Content-Type header for multipart/form-data.
			req.Header.Set("Content-Type", writer.FormDataContentType())

			// Set the Authorization header.
			req.Header.Set("Authorization", "Bearer "+authToken)
			// Serve the request using the Gin router.
			router.ServeHTTP(w, req)
			// Check the response status code.
			assert.Equal(t, http.StatusOK, w.Code)

			// Check the response status code.
			assert.Equal(t, http.StatusOK, w.Code)

			expected := `{"updatedResult.Updated":true}`
			assert.Equal(t, expected, w.Body.String())
		}
	}
}

func TestSearch(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /search endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/search", func(c *gin.Context) {
		handler.GetAppByName(c)
	})

	// Create a POST request for the /search endpoint.
	req, err := http.NewRequest("GET", "/search?app_name=testapp", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)
	// Define the expected JSON response as a slice of AppInfo.
	type AppInfo struct {
		ID         string                              `json:"ID"`
		AppID      string                              `json:"AppID"`
		AppName    string                              `json:"AppName"`
		Version    string                              `json:"Version"`
		Channel    string                              `json:"Channel"`
		Published  bool                                `json:"Published"`
		Critical   bool                                `json:"Critical"`
		Artifacts  []model.SpecificArtifactsWithoutIDs `json:"Artifacts" bson:"artifacts"`
		Changelog  []model.Changelog                   `json:"Changelog" bson:"changelog"`
		Updated_at string                              `json:"Updated_at"`
	}
	type AppResponse struct {
		Apps []AppInfo `json:"apps"`
	}

	expected := []AppInfo{
		{
			AppName:   "testapp",
			Version:   "0.0.5.137",
			Channel:   "stable",
			Published: false,
			Critical:  false,
			Artifacts: []model.SpecificArtifactsWithoutIDs{
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  ".dmg",
				},
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  ".pkg",
				},
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  "",
				},
			},
			Changelog: []model.Changelog{
				{
					Version: "0.0.5.137",
					Changes: "",
					Date:    time.Now().Format("2006-01-02"),
				},
			},
		},
		{
			AppName:   "testapp",
			Version:   "0.0.4.137",
			Channel:   "stable",
			Published: true,
			Critical:  true,
			Artifacts: []model.SpecificArtifactsWithoutIDs{
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  ".dmg",
				},
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  ".pkg",
				},
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  "",
				},
			},
			Changelog: []model.Changelog{
				{
					Version: "0.0.4.137",
					Changes: "",
					Date:    time.Now().Format("2006-01-02"),
				},
			},
		},
		{
			AppName:   "testapp",
			Version:   "0.0.3.137",
			Channel:   "nightly",
			Published: false,
			Critical:  false,
			Artifacts: []model.SpecificArtifactsWithoutIDs{
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  ".dmg",
				},
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  ".pkg",
				},
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  "",
				},
			},
			Changelog: []model.Changelog{
				{
					Version: "0.0.3.137",
					Changes: "",
					Date:    time.Now().Format("2006-01-02"),
				},
			},
		},
		{
			AppName:   "testapp",
			Version:   "0.0.2.137",
			Channel:   "nightly",
			Published: true,
			Critical:  true,
			Artifacts: []model.SpecificArtifactsWithoutIDs{
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  ".dmg",
				},
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  ".pkg",
				},
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  "",
				},
			},
			Changelog: []model.Changelog{
				{
					Version: "0.0.2.137",
					Changes: "### Changelog",
					Date:    time.Now().Format("2006-01-02"),
				},
			},
		},
		{
			AppName:   "testapp",
			Version:   "0.0.1.137",
			Channel:   "nightly",
			Published: true,
			Critical:  false,
			Artifacts: []model.SpecificArtifactsWithoutIDs{
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  ".dmg",
				},
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  ".pkg",
				},
				{
					Platform: "universalPlatform",
					Arch:     "universalArch",
					Package:  "",
				},
			},
			Changelog: []model.Changelog{
				{
					Version: "0.0.1.137",
					Changes: "",
					Date:    time.Now().Format("2006-01-02"),
				},
			},
		},
	}

	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (AppName, Version, Channel, Changelog) for each item in the response.

	if len(actual.Apps) != len(expected) {
		t.Fatalf("Expected %d apps but got %d", len(expected), len(actual.Apps))
	}

	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Apps[i].AppName)
		assert.Equal(t, expectedApp.Version, actual.Apps[i].Version)
		assert.Equal(t, expectedApp.Channel, actual.Apps[i].Channel)
		assert.Equal(t, expectedApp.Published, actual.Apps[i].Published)

		if len(expectedApp.Artifacts) != len(actual.Apps[i].Artifacts) {
			t.Fatalf("Expected %d artifacts for app %s with version %s but got %d", len(expectedApp.Artifacts), expectedApp.AppID, expectedApp.Version, len(actual.Apps[i].Artifacts))
		}
		for j, expectedArtifact := range expectedApp.Artifacts {
			assert.Equal(t, expectedArtifact.Platform, actual.Apps[i].Artifacts[j].Platform)
			assert.Equal(t, expectedArtifact.Arch, actual.Apps[i].Artifacts[j].Arch)
			assert.Equal(t, expectedArtifact.Package, actual.Apps[i].Artifacts[j].Package)
		}

		if len(expectedApp.Changelog) != len(actual.Apps[i].Changelog) {
			t.Fatalf("Expected %d changelog entries for app %s but got %d", len(expectedApp.Changelog), expectedApp.AppID, len(actual.Apps[i].Changelog))
		}
		for c, expectedChanges := range expectedApp.Changelog {
			assert.Equal(t, expectedChanges.Version, actual.Apps[i].Changelog[c].Version)
			assert.Equal(t, expectedChanges.Changes, actual.Apps[i].Changelog[c].Changes)
			assert.Equal(t, expectedChanges.Date, actual.Apps[i].Changelog[c].Date)
		}
	}

}
func TestFetchkLatestVersionOfApp(t *testing.T) {
	router := gin.Default()
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/apps/latest", func(c *gin.Context) {
		handler.FetchLatestVersionOfApp(c)
	})
	// Define test scenarios.
	testScenarios := []struct {
		AppName      string
		ChannelName  string
		ExpectedJSON map[string]interface{}
		ExpectedCode int
		Platform     string
		Arch         string
		TestName     string
	}{
		{
			AppName:     "testapp",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"nightly": map[string]interface{}{
					"universalPlatform": map[string]interface{}{
						"universalArch": map[string]interface{}{
							"dmg": map[string]interface{}{
								"url": fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.137.dmg"),
							},
							"pkg": map[string]interface{}{
								"url": fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.137.pkg"),
							},
							"no-extension": map[string]interface{}{
								"url": fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.137"),
							},
						},
					},
				},
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
		},
		{
			AppName:     "testapp",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"stable": map[string]interface{}{
					"universalPlatform": map[string]interface{}{
						"universalArch": map[string]interface{}{
							"dmg": map[string]interface{}{
								"url": fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/stable/universalPlatform/universalArch/testapp-0.0.4.137.dmg"),
							},
							"pkg": map[string]interface{}{
								"url": fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/stable/universalPlatform/universalArch/testapp-0.0.4.137.pkg"),
							},
							"no-extension": map[string]interface{}{
								"url": fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/stable/universalPlatform/universalArch/testapp-0.0.4.137"),
							},
						},
					},
				},
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "StableUpdateAvailable",
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.TestName, func(t *testing.T) {
			w := httptest.NewRecorder()

			// Create a GET request for checking the version.
			req, err := http.NewRequest("GET", fmt.Sprintf("/apps/latest?app_name=%s&channel=%s&platform=%s&arch=%s", scenario.AppName, scenario.ChannelName, scenario.Platform, scenario.Arch), nil)
			if err != nil {
				t.Fatal(err)
			}

			// Serve the request using the Gin router.
			router.ServeHTTP(w, req)

			// Check the response status code.
			assert.Equal(t, scenario.ExpectedCode, w.Code)

			var actual map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &actual)
			if err != nil {
				t.Fatal(err)
			}

			// Compare the response with the expected values.
			assert.Equal(t, scenario.ExpectedJSON, actual)
		})
	}
}
func TestCheckVersion(t *testing.T) {
	router := gin.Default()
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/checkVersion", func(c *gin.Context) {
		handler.FindLatestVersion(c)
	})
	// Define test scenarios.
	testScenarios := []struct {
		AppName      string
		Version      string
		ChannelName  string
		ExpectedJSON map[string]interface{}
		ExpectedCode int
		Published    bool
		Platform     string
		Arch         string
		TestName     string
	}{
		{
			AppName:     "testapp",
			Version:     "0.0.1.137",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"changelog":        "### Changelog\n",
				"update_available": true,
				"critical":         true,
				"update_url_dmg":   fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.137.dmg"),
				"update_url_pkg":   fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.137.pkg"),
				"update_url":       fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.137"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.2.137",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"update_available": false,
				"update_url_dmg":   fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.137.dmg"),
				"update_url_pkg":   fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.137.pkg"),
				"update_url":       fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.137"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.3.137",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"error": "requested version 0.0.3.137 is newer than the latest version available",
			},
			ExpectedCode: http.StatusBadRequest,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.4.137",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"update_available": false,
				"update_url_dmg":   fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/stable/universalPlatform/universalArch/testapp-0.0.4.137.dmg"),
				"update_url_pkg":   fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/stable/universalPlatform/universalArch/testapp-0.0.4.137.pkg"),
				"update_url":       fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/stable/universalPlatform/universalArch/testapp-0.0.4.137"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "StableUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.5.137",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"error": "requested version 0.0.5.137 is newer than the latest version available",
			},
			ExpectedCode: http.StatusBadRequest,
			// Published:    false,
			Platform: "universalPlatform",
			Arch:     "universalArch",
			TestName: "StableUpdateAvailable",
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.TestName, func(t *testing.T) {
			w := httptest.NewRecorder()

			// Create a GET request for checking the version.
			req, err := http.NewRequest("GET", fmt.Sprintf("/checkVersion?app_name=%s&version=%s&channel=%s&platform=%s&arch=%s", scenario.AppName, scenario.Version, scenario.ChannelName, scenario.Platform, scenario.Arch), nil)
			if err != nil {
				t.Fatal(err)
			}

			// Serve the request using the Gin router.
			router.ServeHTTP(w, req)

			// Check the response status code.
			assert.Equal(t, scenario.ExpectedCode, w.Code)

			var actual map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &actual)
			if err != nil {
				t.Fatal(err)
			}

			// Compare the response with the expected values.
			assert.Equal(t, scenario.ExpectedJSON, actual)
		})
	}
}

func TestMultipleDelete(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	// Define the route for the /apps/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.DELETE("/apps/delete", func(c *gin.Context) {
		handler.DeleteSpecificVersionOfApp(c)
	})

	// Iterate over the uploadedAppIDs and send a DELETE request for each ID.
	for _, appID := range uploadedAppIDs {
		w := httptest.NewRecorder()

		req, err := http.NewRequest("DELETE", "/apps/delete?id="+appID, nil)
		if err != nil {
			t.Fatal(err)
		}

		// Set the Authorization header.
		req.Header.Set("Authorization", "Bearer "+authToken)
		// Serve the request using the Gin router.
		router.ServeHTTP(w, req)

		// Check the response status code for each request.
		assert.Equal(t, http.StatusOK, w.Code)

		expected := `{"deleteSpecificAppResult.DeletedCount":1}`
		assert.Equal(t, expected, w.Body.String())
	}
}

var uploadedAppIDsWithSameExtension []string

func TestMultipleUploadWithSameExtension(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/upload", func(c *gin.Context) {
		handler.UploadApp(c)
	})

	// Create a file to upload (you can replace this with a test file path).
	filePaths := []string{"testapp.dmg"}
	for _, filePath := range filePaths {
		file, err := os.Open(filePath)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		combinations := []struct {
			AppVersion  string
			ChannelName string
			Published   bool
			Critical    bool
			Platform    string
			Arch        string
		}{
			{"0.0.1.138", "nightly", true, false, "secondPlatform", "secondArch"},
			{"0.0.2.138", "nightly", true, false, "universalPlatform", "secondArch"},
			{"0.0.2.138", "nightly", true, false, "universalPlatform", "universalArch"},
			{"0.0.4.138", "stable", true, true, "universalPlatform", "universalArch"},
			{"0.0.4.138", "stable", true, true, "secondPlatform", "universalArch"},
		}
		logrus.Infof("Initial combinations: %v", combinations)
		// Iterate through the combinations and upload the file for each combination.
		for _, combo := range combinations {
			logrus.Infof("Uploading payload for: %v", combo)
			w := httptest.NewRecorder()
			// Reset the request body for each iteration.
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)
			part, err := writer.CreateFormFile("file", filepath.Base(filePath))
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(part, file)
			if err != nil {
				t.Fatal(err)
			}
			dataPart, err := writer.CreateFormField("data")
			if err != nil {
				t.Fatal(err)
			}
			payload := fmt.Sprintf(`{"app_name": "testapp", "version": "%s", "channel": "%s", "publish": %v, "critical": %v, "platform": "%s", "arch": "%s"}`, combo.AppVersion, combo.ChannelName, combo.Published, combo.Critical, combo.Platform, combo.Arch)
			_, err = dataPart.Write([]byte(payload))
			if err != nil {
				t.Fatal(err)
			}

			// Close the writer to finalize the form
			err = writer.Close()
			if err != nil {
				t.Fatal(err)
			}
			logrus.Infoln("Payload: ", payload)
			// Create a POST request for the /upload endpoint with the current combination.
			req, err := http.NewRequest("POST", "/upload", body)
			if err != nil {
				t.Fatal(err)
			}

			// Set the Content-Type header for multipart/form-data.
			req.Header.Set("Content-Type", writer.FormDataContentType())

			// Set the Authorization header.
			req.Header.Set("Authorization", "Bearer "+authToken)
			// Serve the request using the Gin router.
			router.ServeHTTP(w, req)

			// Check the response status code.
			assert.Equal(t, http.StatusOK, w.Code)
			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			if err != nil {
				t.Fatal(err)
			}

			id, idExists := response["uploadResult.Uploaded"]
			assert.True(t, idExists)

			// Check if the id already exists in the uploadedAppIDsWithSameExtension array
			exists := false
			for _, val := range uploadedAppIDsWithSameExtension {
				if val == id {
					exists = true
					break
				}
			}

			// If id does not exist in the array, append it
			if !exists {
				uploadedAppIDsWithSameExtension = append(uploadedAppIDsWithSameExtension, id.(string))
			}

			assert.True(t, idExists)
			assert.NotEmpty(t, id.(string))
		}
	}
}

func TestCheckVersionWithSameExtensionArtifactsAndDiffPlatformsArchs(t *testing.T) {
	router := gin.Default()
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/checkVersion", func(c *gin.Context) {
		handler.FindLatestVersion(c)
	})
	// Define test scenarios.
	testScenarios := []struct {
		AppName      string
		Version      string
		ChannelName  string
		ExpectedJSON map[string]interface{}
		ExpectedCode int
		Published    bool
		Platform     string
		Arch         string
		TestName     string
	}{
		{
			AppName:     "testapp",
			Version:     "0.0.1.138",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"update_available": true,
				"critical":         false,
				"update_url_dmg":   fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/nightly/universalPlatform/secondArch/testapp-0.0.2.138.dmg"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "secondArch",
			TestName:     "NightlyUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.1.138",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"update_available": true,
				"critical":         false,
				"update_url_dmg":   fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.138.dmg"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.3.138",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"error": "requested version 0.0.3.138 is newer than the latest version available",
			},
			ExpectedCode: http.StatusBadRequest,
			Platform:     "secondPlatform",
			Arch:         "secondArch",
			TestName:     "NightlyUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.3.138",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"update_available": true,
				"critical":         true,
				"update_url_dmg":   fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/stable/universalPlatform/universalArch/testapp-0.0.4.138.dmg"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "StableUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.3.138",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"update_available": true,
				"critical":         true,
				"update_url_dmg":   fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "testapp/stable/secondPlatform/universalArch/testapp-0.0.4.138.dmg"),
			},
			ExpectedCode: http.StatusOK,
			// Published:    false,
			Platform: "secondPlatform",
			Arch:     "universalArch",
			TestName: "StableUpdateAvailable",
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.TestName, func(t *testing.T) {
			w := httptest.NewRecorder()

			// Create a GET request for checking the version.
			req, err := http.NewRequest("GET", fmt.Sprintf("/checkVersion?app_name=%s&version=%s&channel=%s&platform=%s&arch=%s", scenario.AppName, scenario.Version, scenario.ChannelName, scenario.Platform, scenario.Arch), nil)
			if err != nil {
				t.Fatal(err)
			}

			// Serve the request using the Gin router.
			router.ServeHTTP(w, req)

			// Check the response status code.
			assert.Equal(t, scenario.ExpectedCode, w.Code)

			var actual map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &actual)
			if err != nil {
				t.Fatal(err)
			}

			// Compare the response with the expected values.
			assert.Equal(t, scenario.ExpectedJSON, actual)
		})
	}
}

func TestMultipleDeleteWithSameExtensionArtifactsAndDiffPlatformsArchs(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	// Define the route for the /apps/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.DELETE("/apps/delete", func(c *gin.Context) {
		handler.DeleteSpecificVersionOfApp(c)
	})

	// Iterate over the uploadedAppIDsWithSameExtension and send a DELETE request for each ID.
	for _, appID := range uploadedAppIDsWithSameExtension {
		w := httptest.NewRecorder()

		req, err := http.NewRequest("DELETE", "/apps/delete?id="+appID, nil)
		if err != nil {
			t.Fatal(err)
		}

		// Set the Authorization header.
		req.Header.Set("Authorization", "Bearer "+authToken)
		// Serve the request using the Gin router.
		router.ServeHTTP(w, req)

		// Check the response status code for each request.
		assert.Equal(t, http.StatusOK, w.Code)

		expected := `{"deleteSpecificAppResult.DeletedCount":1}`
		assert.Equal(t, expected, w.Body.String())
	}
}

func TestUpdateChannel(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /channel/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/channel/update", func(c *gin.Context) {
		handler.UpdateChannel(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"id": "%s", "channel":"unstable"}`, idStableChannel)
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /channel/update endpoint
	req, err := http.NewRequest("POST", "/channel/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Check for the presence of the "updateChannelResult.Updated" key in the response
	updated, exists := response["updateChannelResult.Updated"]
	assert.True(t, exists)
	assert.True(t, updated.(bool))
}
func TestListChannelsWhenExist(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/channel/list", func(c *gin.Context) {
		handler.ListChannels(c)
	})

	// Create a POST request for the /channel/list endpoint.
	req, err := http.NewRequest("GET", "/channel/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)
	type ChannelInfo struct {
		ID          string `json:"ID"`
		ChannelName string `json:"ChannelName"`
		Updated_at  string `json:"Updated_at"`
	}
	type ChannelResponse struct {
		Channels []ChannelInfo `json:"channels"`
	}

	expected := []ChannelInfo{
		{
			ChannelName: "nightly",
		},
		{
			ChannelName: "unstable",
		},
	}
	var actual ChannelResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (ChannelName) for each item in the response.
	for i, expectedChannel := range expected {
		assert.Equal(t, expectedChannel.ChannelName, actual.Channels[i].ChannelName)
	}
}

func TestDeleteNightlyChannel(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.DELETE("/channel/delete", func(c *gin.Context) {
		handler.DeleteChannel(c)
	})

	// Create a DELETE request for the /channel/delete endpoint.
	req, err := http.NewRequest("DELETE", "/channel/delete?id="+idNightlyChannel, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deleteChannelResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}

func TestDeleteStableChannel(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.DELETE("/channel/delete", func(c *gin.Context) {
		handler.DeleteChannel(c)
	})

	// Create a DELETE request for the /channel/delete endpoint.
	req, err := http.NewRequest("DELETE", "/channel/delete?id="+idStableChannel, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deleteChannelResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}

func TestDeleteSecondPlatform(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.DELETE("/platform/delete", func(c *gin.Context) {
		handler.DeletePlatform(c)
	})

	// Create a DELETE request for the /platform/delete endpoint.
	req, err := http.NewRequest("DELETE", "/platform/delete?id="+secondPlatformId, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deletePlatformResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}

func TestUpdatePlatform(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /platform/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/platform/update", func(c *gin.Context) {
		handler.UpdatePlatform(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"id": "%s", "platform":"newPlatform"}`, platformId)
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /platform/update endpoint
	req, err := http.NewRequest("POST", "/platform/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Check for the presence of the "updateChannelResult.Updated" key in the response
	updated, exists := response["updatePlatformResult.Updated"]
	assert.True(t, exists)
	assert.True(t, updated.(bool))
}

func TestFailedUpdatePlatform(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /platform/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/platform/update", func(c *gin.Context) {
		handler.UpdatePlatform(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"id": "%s", "platform":"new * Platform"}`, platformId)
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /platform/update endpoint
	req, err := http.NewRequest("POST", "/platform/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 400).
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"invalid platform name"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

func TestListPlatformsWhenExist(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/platform/list", func(c *gin.Context) {
		handler.ListPlatforms(c)
	})

	// Create a POST request for the /platform/list endpoint.
	req, err := http.NewRequest("GET", "/platform/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)
	type PlatformInfo struct {
		ID           string `json:"ID"`
		PlatformName string `json:"PlatformName"`
		Updated_at   string `json:"Updated_at"`
	}
	type PlatformResponse struct {
		Platforms []PlatformInfo `json:"platforms"`
	}

	expected := []PlatformInfo{
		{
			PlatformName: "newPlatform",
		},
	}
	var actual PlatformResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (PlatformName) for each item in the response.
	for i, expectedPlatform := range expected {
		assert.Equal(t, expectedPlatform.PlatformName, actual.Platforms[i].PlatformName)
	}
}

func TestDeletePlatform(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.DELETE("/platform/delete", func(c *gin.Context) {
		handler.DeletePlatform(c)
	})

	// Create a DELETE request for the /platform/delete endpoint.
	req, err := http.NewRequest("DELETE", "/platform/delete?id="+platformId, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deletePlatformResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}
func TestDeleteSecondArch(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /arch/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.DELETE("/arch/delete", func(c *gin.Context) {
		handler.DeleteArch(c)
	})

	// Create a DELETE request for the /arch/delete endpoint.
	req, err := http.NewRequest("DELETE", "/arch/delete?id="+secondArchId, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deleteArchResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}
func TestUpdateArch(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /arch/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/arch/update", func(c *gin.Context) {
		handler.UpdateArch(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"id": "%s", "arch":"newArch"}`, archId)
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /arch/update endpoint
	req, err := http.NewRequest("POST", "/arch/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Check for the presence of the "updateChannelResult.Updated" key in the response
	updated, exists := response["updateArchResult.Updated"]
	assert.True(t, exists)
	assert.True(t, updated.(bool))
}
func TestListArchsWhenExist(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /arch/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/arch/list", func(c *gin.Context) {
		handler.ListArchs(c)
	})

	// Create a POST request for the /arch/list endpoint.
	req, err := http.NewRequest("GET", "/arch/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)
	type ArchInfo struct {
		ID         string `json:"ID"`
		ArchID     string `json:"ArchID"`
		Updated_at string `json:"Updated_at"`
	}
	type ArchResponse struct {
		Archs []ArchInfo `json:"archs"`
	}

	expected := []ArchInfo{
		{
			ArchID: "newArch",
		},
	}
	var actual ArchResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (ArchID) for each item in the response.
	for i, expectedArch := range expected {
		assert.Equal(t, expectedArch.ArchID, actual.Archs[i].ArchID)
	}
}

func TestDeleteArch(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /arch/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.DELETE("/arch/delete", func(c *gin.Context) {
		handler.DeleteArch(c)
	})

	// Create a DELETE request for the /arch/delete endpoint.
	req, err := http.NewRequest("DELETE", "/arch/delete?id="+archId, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deleteArchResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}
func TestUpdateApp(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.POST("/app/update", func(c *gin.Context) {
		handler.UpdateApp(c)
	})

	// Create multipart/form-data request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add a field for the channel to the form
	dataPart, err := writer.CreateFormField("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"id": "%s", "app":"newApp"}`, idTestappApp)
	_, err = dataPart.Write([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Create a POST request to the /app/update endpoint
	req, err := http.NewRequest("POST", "/app/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Check for the presence of the "updateAppResult.Updated" key in the response
	updated, exists := response["updateAppResult.Updated"]
	assert.True(t, exists)
	assert.True(t, updated.(bool))
}
func TestListAppsWhenExist(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /app/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.GET("/app/list", func(c *gin.Context) {
		handler.ListApps(c)
	})

	// Create a GET request for the /app/list endpoint.
	req, err := http.NewRequest("GET", "/app/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)
	type AppInfo struct {
		ID         string `json:"ID"`
		AppName    string `json:"AppName"`
		Updated_at string `json:"Updated_at"`
	}
	type AppResponse struct {
		Apps []AppInfo `json:"apps"`
	}

	expected := []AppInfo{
		{
			AppName: "newApp",
		},
	}
	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (ChannelName) for each item in the response.
	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Apps[i].AppName)
	}
}

func TestDeleteAppMeta(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /app/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, true)
	router.DELETE("/app/delete", func(c *gin.Context) {
		handler.DeleteApp(c)
	})

	// Create a DELETE request for the /app/delete endpoint.
	req, err := http.NewRequest("DELETE", "/app/delete?id="+idTestappApp, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deleteAppResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}
