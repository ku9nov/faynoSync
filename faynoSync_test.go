package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	apiKey        string
	apiUrl        string
	s3Endpoint    string
	s3Bucket      string
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

func checkFileContent(t *testing.T, url string) string {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Log the content of the file
	logrus.Infof("Content of %s:\n%s", url, string(body))
	return string(body)
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

func generateFile(filename, content string) {
	err := os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		logrus.Errorf("Failed to generate the file %s: %v", filename, err)
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
	apiUrl = viper.GetString("API_URL")
	client, configDB = mongod.ConnectToDatabase(viper.GetString("MONGODB_URL_TESTS"), flagMap)
	appDB = mongod.NewAppRepository(&configDB, client)
	mongoDatabase = client.Database(configDB.Database)
	if viper.GetBool("ENABLE_TELEMETRY") {
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
	generateFile("RELEASES", "RELEASES FILE FOR WINDOWS sqirrel")
	generateFile("latest.yml", "latest file for windows electron-builder")
	generateFile("latest-mac.yml", "latest file for macos electron builder")
	copyFile("LICENSE", "test.zip")
	copyFile("LICENSE", "test.exe")

}

func teardown() {
	if redisClient != nil {
		err := redisClient.FlushDB(context.Background()).Err()
		if err != nil {
			logrus.Errorf("Failed to flush Redis DB: %v", err)
		} else {
			logrus.Infoln("Redis DB flushed successfully.")
		}
	}

	adminsCollection := mongoDatabase.Collection("admins")
	filter := bson.M{"username": bson.M{"$in": []string{"admin", "administrator"}}}

	// Delete the admin user from the collection
	_, err := adminsCollection.DeleteMany(context.TODO(), filter)
	if err != nil {
		logrus.Errorf("Failed to remove admin users: %v", err)
	}
	logrus.Infoln("Successfully removed admin users.")
	client.Disconnect(context.Background())
	logrus.Infoln("MongoDB is disconnected.")
	removeFile("testapp.dmg")
	removeFile("testapp.pkg")
	removeFile("RELEASES")
	removeFile("latest.yml")
	removeFile("latest-mac.yml")
	removeFile("test.zip")
	removeFile("test.exe")
}

func generateDateRangeAndStats(startDate time.Time, days int) ([]interface{}, []interface{}) {
	var dateRange []interface{}
	var dailyStats []interface{}

	for i := 0; i < days; i++ {
		d := startDate.AddDate(0, 0, i).Format("2006-01-02")
		dateRange = append(dateRange, d)
		dailyStats = append(dailyStats, d)
	}
	return dateRange, dailyStats
}

func TestHealthCheck(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

func TestSignUpSecondUser(t *testing.T) {
	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/signup", func(c *gin.Context) {
		handler.SignUp(c)
	})

	regKey := os.Getenv("API_KEY")
	payload := fmt.Sprintf(`{"username": "administrator", "password": "password", "api_key": "%s"}`, regKey)
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

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

var authTokenSecondUser string

func TestLoginSecondUser(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/login", func(c *gin.Context) {
		handler.Login(c)
	})

	// Create a JSON payload for the request
	payload := `{"username": "administrator", "password": "password"}`

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

	authTokenSecondUser = token.(string)

	// Check that the authTokenSecondUser variable has been set (assuming authTokenSecondUser is a global variable).
	assert.NotEmpty(t, authTokenSecondUser)
}

func TestListApps(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /app/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
var idPublicTestappApp string

func TestAppCreate(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/app/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
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
	payload := `{"app": "testapp", "private": "true"}`
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

func TestCreatePublicApp(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	payload := `{"app": "public testapp"}`
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
	idPublic, idExists := response["createAppResult.Created"]
	assert.True(t, idExists)
	idPublicTestappApp = idPublic.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, idTestappApp)
}

var idTestappAppWithUpdaters string

func TestCreateAppWithUpdaters(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	payload := `{"app": "updaters"}`
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
	idTestappAppWithUpdaters = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, idTestappAppWithUpdaters)
}

func TestSecondaryAppCreate(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/channel/create", func(c *gin.Context) {
		handler.CreateChannel(c)
	})

	payload := `{
		"channel": "nightly"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/channel/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/channel/create", func(c *gin.Context) {
		handler.CreateChannel(c)
	})

	payload := `{
		"channel": "nightly *"
	}`

	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/channel/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/channel/create", func(c *gin.Context) {
		handler.CreateChannel(c)
	})

	payload := `{
		"channel": "nightly"
	}`

	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/channel/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/channel/create", func(c *gin.Context) {
		handler.CreateChannel(c)
	})

	payload := `{
		"channel": "stable"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/channel/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/create", func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	payload := `{
		"platform": "universalPlatform"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/create endpoint
	req, err := http.NewRequest("POST", "/platform/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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

var platformIdWindows string

func TestPlatformCreateWindows(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/create", func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	payload := `{
		"platform": "windows"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/create endpoint
	req, err := http.NewRequest("POST", "/platform/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	platformIdWindows = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, platformIdWindows)
}

func TestUpdatePlatformWindows(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /platform/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/update", func(c *gin.Context) {
		handler.UpdatePlatform(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s", 
		"platform":"windows",
		"updaters": [
			{ "type": "manual", "default": false },
			{ "type": "squirrel_windows", "default": true },
			{ "type": "electron-builder", "default": false }
		]
	}`, platformIdWindows)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/update endpoint
	req, err := http.NewRequest("POST", "/platform/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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

var platformIdMacos string

func TestPlatformCreateMacos(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/create", func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	payload := `{
		"platform": "macos"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/create endpoint
	req, err := http.NewRequest("POST", "/platform/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	platformIdMacos = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, platformIdMacos)
}

func TestUpdatePlatformMacos(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /platform/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/update", func(c *gin.Context) {
		handler.UpdatePlatform(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s", 
		"platform":"macos",
		"updaters": [
			{ "type": "manual", "default": false },
			{ "type": "squirrel_darwin", "default": true },
			{ "type": "electron-builder", "default": false }
		]
	}`, platformIdMacos)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/update endpoint
	req, err := http.NewRequest("POST", "/platform/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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

var platformIdMacosSquirrel string

func TestPlatformCreateMacosSquirrel(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/create", func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	payload := `{
		"platform": "macosSquirrel"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/create endpoint
	req, err := http.NewRequest("POST", "/platform/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	platformIdMacosSquirrel = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, platformIdMacosSquirrel)
}

func TestUpdatePlatformMacosSquirrel(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /platform/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/update", func(c *gin.Context) {
		handler.UpdatePlatform(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s", 
		"platform":"macosSquirrel",
		"updaters": [
			{ "type": "manual", "default": false },
			{ "type": "squirrel_darwin", "default": true },
			{ "type": "electron-builder", "default": false }
		]
	}`, platformIdMacosSquirrel)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/update endpoint
	req, err := http.NewRequest("POST", "/platform/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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

func TestSecondaryPlatformCreate(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/create", func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	payload := `{
		"platform": "universalPlatform"
	}`

	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/create endpoint
	req, err := http.NewRequest("POST", "/platform/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/create", func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	payload := `{
		"platform": "secondPlatform"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/create endpoint
	req, err := http.NewRequest("POST", "/platform/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/arch/create", func(c *gin.Context) {
		handler.CreateArch(c)
	})

	payload := `{
		"arch": "universalArch"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/arch/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/arch/create", func(c *gin.Context) {
		handler.CreateArch(c)
	})

	payload := `{
		"arch": "universalArch"
	}`

	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/arch/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/arch/create", func(c *gin.Context) {
		handler.CreateArch(c)
	})

	payload := `{
		"arch": "secondArch"
	}`

	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/arch/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
			AppName     string
			AppVersion  string
			ChannelName string
			Published   bool
			Critical    bool
			Platform    string
			Arch        string
		}{
			{"public testapp", "0.0.1.137", "nightly", true, false, "universalPlatform", "universalArch"},
			{"testapp", "0.0.2.137", "nightly", true, false, "universalPlatform", "universalArch"},
			{"testapp", "0.0.3.137", "nightly", false, false, "universalPlatform", "universalArch"},
			{"testapp", "0.0.4.137", "stable", true, true, "universalPlatform", "universalArch"},
			{"testapp", "0.0.5.137", "stable", false, false, "universalPlatform", "universalArch"},
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
			payload := fmt.Sprintf(`{"app_name": "%s", "version": "%s", "channel": "%s", "publish": %v, "critical": %v, "platform": "%s", "arch": "%s"}`, combo.AppName, combo.AppVersion, combo.ChannelName, combo.Published, combo.Critical, combo.Platform, combo.Arch)
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

var uploadedAppIDsWithUpdaters []string

func TestMultipleUploadWithUpdaters(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/upload", func(c *gin.Context) {
		handler.UploadApp(c)
	})

	combinations := []struct {
		AppName     string
		AppVersion  string
		ChannelName string
		Published   bool
		Critical    bool
		Platform    string
		Arch        string
		Updater     string
		FileName    string
	}{
		{"updaters", "0.0.1.137", "nightly", false, false, "macosSquirrel", "universalArch", "squirrel_darwin", "testapp.dmg"},
		{"updaters", "0.0.2.137", "nightly", true, false, "macosSquirrel", "universalArch", "squirrel_darwin", "test.zip"},
		{"updaters", "0.0.3.137", "nightly", false, false, "macos", "universalArch", "electron-builder", "testapp.dmg"},
		{"updaters", "0.0.4.137", "nightly", true, false, "macos", "universalArch", "electron-builder", "latest-mac.yml"},
		{"updaters", "0.0.5.137", "stable", false, true, "windows", "universalArch", "squirrel_windows", "test.exe"},
		{"updaters", "0.0.6.137", "stable", true, false, "windows", "universalArch", "squirrel_windows", "RELEASES"},
		{"updaters", "0.0.7.137", "stable", false, false, "windows", "universalArch", "electron-builder", "test.exe"},
		{"updaters", "0.0.8.137", "stable", true, false, "windows", "universalArch", "electron-builder", "latest.yml"},
	}

	// Iterate through the combinations and upload the file for each combination.
	for _, combo := range combinations {
		logrus.Infoln("Uploading this combo:", combo)
		filePath := combo.FileName
		file, err := os.Open(filePath)

		if err != nil {
			t.Fatal(err)
		}

		defer file.Close()
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
		payload := fmt.Sprintf(`{"app_name": "%s", "version": "%s", "channel": "%s", "publish": %v, "critical": %v, "platform": "%s", "arch": "%s", "updater": "%s"}`, combo.AppName, combo.AppVersion, combo.ChannelName, combo.Published, combo.Critical, combo.Platform, combo.Arch, combo.Updater)
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

		// Check if this combination should expect an error
		shouldExpectError := (combo.AppVersion == "0.0.1.137" && combo.FileName == "testapp.dmg") ||
			(combo.AppVersion == "0.0.3.137" && combo.FileName == "testapp.dmg") ||
			(combo.AppVersion == "0.0.5.137" && combo.FileName == "test.exe") ||
			(combo.AppVersion == "0.0.7.137" && combo.FileName == "test.exe")

		if shouldExpectError {
			// Expect 400 status code for error cases
			assert.Equal(t, http.StatusBadRequest, w.Code)
			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			if err != nil {
				t.Fatal(err)
			}
			// Check that there's an error message in the response
			errorMsg, hasError := response["error"]
			assert.True(t, hasError, "Expected error message in response")
			assert.NotEmpty(t, errorMsg, "Error message should not be empty")

			// Check specific error messages based on updater type
			var expectedErrorMsg string
			switch combo.Updater {
			case "squirrel_windows":
				expectedErrorMsg = "squirrel windows updater requires a RELEASES file for update functionality. Please include a RELEASES file in your upload"
			case "electron-builder":
				expectedErrorMsg = "electron-builder updater requires a YML/YAML file for update functionality. Please include a .yml or .yaml file in your upload"
			case "squirrel_darwin":
				expectedErrorMsg = "squirrel darwin updater requires a ZIP archive for update functionality. Please include a ZIP file in your upload"
			}

			if expectedErrorMsg != "" {
				assert.Equal(t, expectedErrorMsg, errorMsg, "Expected specific error message for %s updater", combo.Updater)
			}
		} else {
			// Check the response status code for successful cases
			assert.Equal(t, http.StatusOK, w.Code)
			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			if err != nil {
				t.Fatal(err)
			}

			id, idExists := response["uploadResult.Uploaded"]
			assert.True(t, idExists)

			// Check if the id already exists in the uploadedAppIDsWithUpdaters array
			exists := false
			for _, val := range uploadedAppIDsWithUpdaters {
				if val == id {
					exists = true
					break
				}
			}

			// If id does not exist in the array, append it
			if !exists {
				uploadedAppIDsWithUpdaters = append(uploadedAppIDsWithUpdaters, id.(string))
			}

			assert.True(t, idExists)
			assert.NotEmpty(t, id.(string))
		}
	}

}

func TestCheckVersionWithUpdaters(t *testing.T) {
	router := gin.Default()
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
		Owner        string
		Updater      string
		ExpectedBody string
	}{
		{
			AppName:      "updaters",
			Version:      "0.0.2.137",
			ChannelName:  "nightly",
			ExpectedJSON: map[string]interface{}{"status": "no_content"},
			ExpectedCode: http.StatusNoContent,
			Platform:     "macosSquirrel",
			Arch:         "universalArch",
			TestName:     "SquirrelDarwinUpdateNotAvailable",
			Owner:        "admin",
			Updater:      "squirrel_darwin",
		},
		{
			AppName:     "updaters",
			Version:     "0.0.1.135",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"critical":         false,
				"update_available": true,
				"url":              "http://localhost:9010/cb-faynosync-s3-public/updaters-admin/nightly/macosSquirrel/universalArch/updaters-0.0.2.137.zip",
			},
			ExpectedCode: http.StatusOK,
			Platform:     "macosSquirrel",
			Arch:         "universalArch",
			TestName:     "SquirrelDarwinUpdateAvailable",
			Owner:        "admin",
			Updater:      "squirrel_darwin",
		},
		{
			AppName:      "updaters",
			Version:      "0.0.4.137",
			ChannelName:  "nightly",
			ExpectedJSON: map[string]interface{}{"status": "no_content"},
			ExpectedCode: http.StatusNoContent,
			// Published:    false,
			Platform: "macos",
			Arch:     "universalArch",
			TestName: "ElectronBuilderMacosUpdateNotAvailable",
			Owner:    "admin",
			Updater:  "electron-builder",
		},
		{
			AppName:     "updaters",
			Version:     "0.0.1.133",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"critical":         false,
				"update_available": true,
				"update_url_yml":   "http://localhost:9010/cb-faynosync-s3-public/electron-builder/updaters-admin/0.0.4.137/nightly/macos/universalArch/latest-mac.yml",
			},
			ExpectedCode: http.StatusFound,
			// Published:    false,
			Platform:     "macos",
			Arch:         "universalArch",
			TestName:     "ElectronBuilderMacosUpdateAvailable",
			Owner:        "admin",
			Updater:      "electron-builder",
			ExpectedBody: "latest file for macos electron builder",
		},
		{
			AppName:      "updaters",
			Version:      "0.0.8.137",
			ChannelName:  "stable",
			ExpectedJSON: map[string]interface{}{"status": "no_content"},
			ExpectedCode: http.StatusNoContent,
			// Published:    false,
			Platform: "windows",
			Arch:     "universalArch",
			TestName: "ElectronBuilderWindowsUpdateNotAvailable",
			Owner:    "admin",
			Updater:  "electron-builder",
		},
		{
			AppName:     "updaters",
			Version:     "0.0.1.131",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"status": "redirect",
				"url":    "http://localhost:9010/cb-faynosync-s3-public/electron-builder/updaters-admin/0.0.8.137/stable/windows/universalArch/latest.yml",
			},
			ExpectedCode: http.StatusFound,
			// Published:    false,
			Platform:     "windows",
			Arch:         "universalArch",
			TestName:     "ElectronBuilderWindowsUpdateAvailable",
			Owner:        "admin",
			Updater:      "electron-builder",
			ExpectedBody: "latest file for windows electron-builder",
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.TestName, func(t *testing.T) {
			w := httptest.NewRecorder()

			// Create a GET request for checking the version.
			req, err := http.NewRequest("GET", fmt.Sprintf("/checkVersion?app_name=%s&version=%s&channel=%s&platform=%s&arch=%s&owner=%s&updater=%s", scenario.AppName, scenario.Version, scenario.ChannelName, scenario.Platform, scenario.Arch, scenario.Owner, scenario.Updater), nil)
			if err != nil {
				t.Fatal(err)
			}

			// Serve the request using the Gin router.
			router.ServeHTTP(w, req)

			// Check the response status code.
			assert.Equal(t, scenario.ExpectedCode, w.Code)
			fmt.Println("Code: , Response: ", w.Code, w.Body.String())

			switch scenario.ExpectedCode {
			case http.StatusNoContent:
				// For 204, we expect either empty body or {"status": "no_content"}
				if len(w.Body.Bytes()) == 0 {
					// Empty body is fine for 204
					return
				}
				fmt.Println("Content: ", w.Body.String())
				// If there's content, it should be {"status": "no_content"}
				var actual map[string]interface{}
				err = json.Unmarshal(w.Body.Bytes(), &actual)
				if err != nil {
					t.Fatal(err)
				}
				expectedNoContent := map[string]interface{}{"status": "no_content"}
				assert.Equal(t, expectedNoContent, actual)
			case http.StatusFound:
				// For 302 Found (redirect), check the Location header and HTML body
				locationHeader := w.Header().Get("Location")
				logrus.Infof("Location Header: %s", locationHeader)
				if locationHeader != "" {
					// If Location header is set, that's the redirect URL
					var expectedURL string
					if url, exists := scenario.ExpectedJSON["url"]; exists {
						expectedURL = url.(string)
					} else if updateURL, exists := scenario.ExpectedJSON["update_url_yml"]; exists {
						expectedURL = updateURL.(string)
					} else {
						t.Fatal("Neither 'url' nor 'update_url_yml' found in ExpectedJSON")
					}
					assert.Equal(t, expectedURL, locationHeader)
					body := checkFileContent(t, locationHeader)
					logrus.Infof("asserting that body: %s, contains: %s", body, scenario.ExpectedBody)
					assert.Contains(t, body, scenario.ExpectedBody)
				} else {
					// If no Location header, check HTML body for redirect link
					body := w.Body.String()
					expectedURL := scenario.ExpectedJSON["url"].(string)
					// Check if the expected URL is present in the HTML body
					assert.Contains(t, body, expectedURL)
				}
			default:
				// For other status codes, parse and compare JSON
				var actual map[string]interface{}
				logrus.Infoln("Body: ", w.Body.String())
				err = json.Unmarshal(w.Body.Bytes(), &actual)
				if err != nil {
					t.Fatal(err)
				}

				// Compare the response with the expected values.
				assert.Equal(t, scenario.ExpectedJSON, actual)
			}
		})
	}
}

// func TestSquirrelReleases(t *testing.T) {
// 	router := gin.Default()
// 	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
// 	router.GET("/update/:owner/:app/:channel/:platform/:arch/:version/RELEASES", func(c *gin.Context) {
// 		handler.SquirrelReleases(c)
// 	})

// 	// Define test scenarios for SquirrelReleases handler
// 	testScenarios := []struct {
// 		Owner        string
// 		AppName      string
// 		ChannelName  string
// 		Platform     string
// 		Arch         string
// 		Version      string
// 		ExpectedCode int
// 		TestName     string
// 		ExpectedBody string
// 	}{
// 		{
// 			Owner:        "admin",
// 			AppName:      "updaters",
// 			ChannelName:  "stable",
// 			Platform:     "windows",
// 			Arch:         "universalArch",
// 			Version:      "0.0.1.137",
// 			ExpectedCode: http.StatusFound, // 302 redirect
// 			TestName:     "SquirrelReleasesUpdateAvailable",
// 			ExpectedBody: "RELEASES FILE FOR WINDOWS sqirrel",
// 		},
// 		{
// 			Owner:        "admin",
// 			AppName:      "updaters",
// 			ChannelName:  "stable",
// 			Platform:     "windows",
// 			Arch:         "universalArch",
// 			Version:      "0.0.6.137",
// 			ExpectedCode: http.StatusFound, // 302 redirect
// 			TestName:     "SquirrelReleasesUpdateNotAvailable",
// 			ExpectedBody: "RELEASES FILE FOR WINDOWS sqirrel",
// 		},
// 		// {
// 		// 	Owner:        "admin",
// 		// 	AppName:      "nonexistent",
// 		// 	ChannelName:  "stable",
// 		// 	Platform:     "windows",
// 		// 	Arch:         "universalArch",
// 		// 	Version:      "0.0.1.137",
// 		// 	ExpectedCode: http.StatusBadRequest, // Should return error for non-existent app
// 		// 	TestName:     "SquirrelReleasesNonExistentApp",
// 		// },
// 	}

// 	// Run test scenarios
// 	for _, scenario := range testScenarios {
// 		t.Run(scenario.TestName, func(t *testing.T) {
// 			// Create URL with parameters
// 			url := fmt.Sprintf("/update/%s/%s/%s/%s/%s/%s/RELEASES",
// 				scenario.Owner,
// 				scenario.AppName,
// 				scenario.ChannelName,
// 				scenario.Platform,
// 				scenario.Arch,
// 				scenario.Version,
// 			)

// 			// Create request with proper host information
// 			req, err := http.NewRequest("GET", url, nil)
// 			if err != nil {
// 				t.Fatal(err)
// 			}

// 			// Create response recorder
// 			w := httptest.NewRecorder()

// 			// Serve the request
// 			router.ServeHTTP(w, req)

// 			// Log full response for debugging
// 			logrus.Infof("=== Test: %s ===", scenario.TestName)
// 			logrus.Infof("Status Code: %d", w.Code)
// 			logrus.Infof("Headers: %v", w.Header())
// 			logrus.Infof("Body: %s", w.Body.String())
// 			logrus.Infof("==================")

// 			// Check status code
// 			assert.Equal(t, scenario.ExpectedCode, w.Code, "Expected status code %d, got %d", scenario.ExpectedCode, w.Code)
// 			// For 302 Found (redirect), check the Location header and HTML body
// 			locationHeader := w.Header().Get("Location")
// 			logrus.Infof("Location Header: %s", locationHeader)
// 			if locationHeader != "" {
// 				// If Location header is set, that's the redirect URL
// 				// var expectedURL string
// 				// if url, exists := scenario.ExpectedJSON["url"]; exists {
// 				// 	expectedURL = url.(string)
// 				// } else if updateURL, exists := scenario.ExpectedJSON["update_url_yml"]; exists {
// 				// 	expectedURL = updateURL.(string)
// 				// } else {
// 				// 	t.Fatal("Neither 'url' nor 'update_url_yml' found in ExpectedJSON")
// 				// }
// 				// assert.Equal(t, expectedURL, locationHeader)
// 				body := checkFileContent(t, locationHeader)
// 				logrus.Infof("asserting that body: %s, contains: %s", body, scenario.ExpectedBody)
// 				assert.Contains(t, body, scenario.ExpectedBody)
// 			} else {
// 				// If no Location header, check HTML body for redirect link
// 				body := w.Body.String()
// 				logrus.Infof("Body in squirrel win releases: %s", body)
// 				// expectedURL := scenario.ExpectedJSON["url"].(string)
// 				// Check if the expected URL is present in the HTML body
// 				// assert.Contains(t, body, expectedURL)
// 			}
// 			// // For 302 redirects, check if Location header is present
// 			// if scenario.ExpectedCode == http.StatusFound {
// 			// 	locationHeader := w.Header().Get("Location")
// 			// 	assert.NotEmpty(t, locationHeader, "Location header should be present for 302 redirect")

// 			// 	// Log the redirect URL for debugging
// 			// 	logrus.Infof("Redirect URL for %s: %s", scenario.TestName, locationHeader)
// 			// }

// 			// // For error cases, check if error message is present
// 			// if scenario.ExpectedCode == http.StatusBadRequest {
// 			// 	var response map[string]interface{}
// 			// 	err := json.Unmarshal(w.Body.Bytes(), &response)
// 			// 	assert.NoError(t, err, "Should be able to parse error response as JSON")
// 			// 	assert.Contains(t, response, "error", "Error response should contain 'error' field")
// 			// }
// 		})
// 	}
// }

func TestUpdateSpecificAppWithSecondUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	// Define the route for the update endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
			req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
			// Serve the request using the Gin router.
			router.ServeHTTP(w, req)
			// Check the response status code.
			assert.Equal(t, http.StatusInternalServerError, w.Code)

			expected := `{"error":"app_name not found in apps_meta collection"}`
			assert.Equal(t, expected, w.Body.String())
		}
	}
}

func TestUpdateSpecificApp(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	// Define the route for the update endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
		Items []AppInfo `json:"items"`
		Total int       `json:"total"`
		Page  int       `json:"page"`
		Limit int       `json:"limit"`
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
	}

	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (AppName, Version, Channel, Changelog) for each item in the response.
	if len(actual.Items) != len(expected) {
		t.Fatalf("Expected %d apps but got %d", len(expected), len(actual.Items))
	}

	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Items[i].AppName)
		assert.Equal(t, expectedApp.Version, actual.Items[i].Version)
		assert.Equal(t, expectedApp.Channel, actual.Items[i].Channel)
		assert.Equal(t, expectedApp.Published, actual.Items[i].Published)

		if len(expectedApp.Artifacts) != len(actual.Items[i].Artifacts) {
			t.Fatalf("Expected %d artifacts for app %s with version %s but got %d", len(expectedApp.Artifacts), expectedApp.ID, expectedApp.Version, len(actual.Items[i].Artifacts))
		}
		for j, expectedArtifact := range expectedApp.Artifacts {
			assert.Equal(t, expectedArtifact.Platform, actual.Items[i].Artifacts[j].Platform)
			assert.Equal(t, expectedArtifact.Arch, actual.Items[i].Artifacts[j].Arch)
			assert.Equal(t, expectedArtifact.Package, actual.Items[i].Artifacts[j].Package)
		}

		if len(expectedApp.Changelog) != len(actual.Items[i].Changelog) {
			t.Fatalf("Expected %d changelog entries for app %s but got %d", len(expectedApp.Changelog), expectedApp.ID, len(actual.Items[i].Changelog))
		}
		for c, expectedChanges := range expectedApp.Changelog {
			assert.Equal(t, expectedChanges.Version, actual.Items[i].Changelog[c].Version)
			assert.Equal(t, expectedChanges.Changes, actual.Items[i].Changelog[c].Changes)
			assert.Equal(t, expectedChanges.Date, actual.Items[i].Changelog[c].Date)
		}
	}

	assert.Equal(t, 1, actual.Page)
	assert.Equal(t, 9, actual.Limit)
	assert.Equal(t, len(expected), actual.Total)
}

func TestFilterSearchWithChannel(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /search endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/search", func(c *gin.Context) {
		handler.GetAppByName(c)
	})

	// Create a POST request for the /search endpoint.
	req, err := http.NewRequest("GET", "/search?app_name=testapp&channel=nightly", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)
	fmt.Println(w.Body.String())
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
		Items []AppInfo `json:"items"`
		Total int       `json:"total"`
		Page  int       `json:"page"`
		Limit int       `json:"limit"`
	}

	expected := []AppInfo{
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
	}

	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (AppName, Version, Channel, Changelog) for each item in the response.
	if len(actual.Items) != len(expected) {
		t.Fatalf("Expected %d apps but got %d", len(expected), len(actual.Items))
	}

	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Items[i].AppName)
		assert.Equal(t, expectedApp.Version, actual.Items[i].Version)
		assert.Equal(t, expectedApp.Channel, actual.Items[i].Channel)
		assert.Equal(t, expectedApp.Published, actual.Items[i].Published)

		if len(expectedApp.Artifacts) != len(actual.Items[i].Artifacts) {
			t.Fatalf("Expected %d artifacts for app %s with version %s but got %d", len(expectedApp.Artifacts), expectedApp.ID, expectedApp.Version, len(actual.Items[i].Artifacts))
		}
		for j, expectedArtifact := range expectedApp.Artifacts {
			assert.Equal(t, expectedArtifact.Platform, actual.Items[i].Artifacts[j].Platform)
			assert.Equal(t, expectedArtifact.Arch, actual.Items[i].Artifacts[j].Arch)
			assert.Equal(t, expectedArtifact.Package, actual.Items[i].Artifacts[j].Package)
		}

		if len(expectedApp.Changelog) != len(actual.Items[i].Changelog) {
			t.Fatalf("Expected %d changelog entries for app %s but got %d", len(expectedApp.Changelog), expectedApp.ID, len(actual.Items[i].Changelog))
		}
		for c, expectedChanges := range expectedApp.Changelog {
			assert.Equal(t, expectedChanges.Version, actual.Items[i].Changelog[c].Version)
			assert.Equal(t, expectedChanges.Changes, actual.Items[i].Changelog[c].Changes)
			assert.Equal(t, expectedChanges.Date, actual.Items[i].Changelog[c].Date)
		}
	}

	assert.Equal(t, 1, actual.Page)
	assert.Equal(t, 9, actual.Limit)
	assert.Equal(t, len(expected), actual.Total)
}

func TestFilterSearchWithChannelAndPublished(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /search endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/search", func(c *gin.Context) {
		handler.GetAppByName(c)
	})

	// Create a POST request for the /search endpoint.
	req, err := http.NewRequest("GET", "/search?app_name=testapp&channel=stable&published=true", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)
	fmt.Println(w.Body.String())
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
		Items []AppInfo `json:"items"`
		Total int       `json:"total"`
		Page  int       `json:"page"`
		Limit int       `json:"limit"`
	}

	expected := []AppInfo{
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
	}

	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (AppName, Version, Channel, Changelog) for each item in the response.
	if len(actual.Items) != len(expected) {
		t.Fatalf("Expected %d apps but got %d", len(expected), len(actual.Items))
	}

	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Items[i].AppName)
		assert.Equal(t, expectedApp.Version, actual.Items[i].Version)
		assert.Equal(t, expectedApp.Channel, actual.Items[i].Channel)
		assert.Equal(t, expectedApp.Published, actual.Items[i].Published)

		if len(expectedApp.Artifacts) != len(actual.Items[i].Artifacts) {
			t.Fatalf("Expected %d artifacts for app %s with version %s but got %d", len(expectedApp.Artifacts), expectedApp.ID, expectedApp.Version, len(actual.Items[i].Artifacts))
		}
		for j, expectedArtifact := range expectedApp.Artifacts {
			assert.Equal(t, expectedArtifact.Platform, actual.Items[i].Artifacts[j].Platform)
			assert.Equal(t, expectedArtifact.Arch, actual.Items[i].Artifacts[j].Arch)
			assert.Equal(t, expectedArtifact.Package, actual.Items[i].Artifacts[j].Package)
		}

		if len(expectedApp.Changelog) != len(actual.Items[i].Changelog) {
			t.Fatalf("Expected %d changelog entries for app %s but got %d", len(expectedApp.Changelog), expectedApp.ID, len(actual.Items[i].Changelog))
		}
		for c, expectedChanges := range expectedApp.Changelog {
			assert.Equal(t, expectedChanges.Version, actual.Items[i].Changelog[c].Version)
			assert.Equal(t, expectedChanges.Changes, actual.Items[i].Changelog[c].Changes)
			assert.Equal(t, expectedChanges.Date, actual.Items[i].Changelog[c].Date)
		}
	}

	assert.Equal(t, 1, actual.Page)
	assert.Equal(t, 9, actual.Limit)
	assert.Equal(t, len(expected), actual.Total)
}

func TestFilterSearchWithChannelAndPublishedAndCritical(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /search endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/search", func(c *gin.Context) {
		handler.GetAppByName(c)
	})

	// Create a POST request for the /search endpoint.
	req, err := http.NewRequest("GET", "/search?app_name=testapp&channel=stable&published=true&critical=true", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)
	fmt.Println(w.Body.String())
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
		Items []AppInfo `json:"items"`
		Total int       `json:"total"`
		Page  int       `json:"page"`
		Limit int       `json:"limit"`
	}

	expected := []AppInfo{
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
	}

	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (AppName, Version, Channel, Changelog) for each item in the response.
	if len(actual.Items) != len(expected) {
		t.Fatalf("Expected %d apps but got %d", len(expected), len(actual.Items))
	}

	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Items[i].AppName)
		assert.Equal(t, expectedApp.Version, actual.Items[i].Version)
		assert.Equal(t, expectedApp.Channel, actual.Items[i].Channel)
		assert.Equal(t, expectedApp.Published, actual.Items[i].Published)

		if len(expectedApp.Artifacts) != len(actual.Items[i].Artifacts) {
			t.Fatalf("Expected %d artifacts for app %s with version %s but got %d", len(expectedApp.Artifacts), expectedApp.ID, expectedApp.Version, len(actual.Items[i].Artifacts))
		}
		for j, expectedArtifact := range expectedApp.Artifacts {
			assert.Equal(t, expectedArtifact.Platform, actual.Items[i].Artifacts[j].Platform)
			assert.Equal(t, expectedArtifact.Arch, actual.Items[i].Artifacts[j].Arch)
			assert.Equal(t, expectedArtifact.Package, actual.Items[i].Artifacts[j].Package)
		}

		if len(expectedApp.Changelog) != len(actual.Items[i].Changelog) {
			t.Fatalf("Expected %d changelog entries for app %s but got %d", len(expectedApp.Changelog), expectedApp.ID, len(actual.Items[i].Changelog))
		}
		for c, expectedChanges := range expectedApp.Changelog {
			assert.Equal(t, expectedChanges.Version, actual.Items[i].Changelog[c].Version)
			assert.Equal(t, expectedChanges.Changes, actual.Items[i].Changelog[c].Changes)
			assert.Equal(t, expectedChanges.Date, actual.Items[i].Changelog[c].Date)
		}
	}

	assert.Equal(t, 1, actual.Page)
	assert.Equal(t, 9, actual.Limit)
	assert.Equal(t, len(expected), actual.Total)
}

func TestFilterSearchWithChannelAndPublishedAndCriticalAndPlatform(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /search endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/search", func(c *gin.Context) {
		handler.GetAppByName(c)
	})

	// Create a POST request for the /search endpoint.
	req, err := http.NewRequest("GET", "/search?app_name=testapp&channel=nightly&published=true&critical=true&platform=universalPlatform", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)
	fmt.Println(w.Body.String())
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
		Items []AppInfo `json:"items"`
		Total int       `json:"total"`
		Page  int       `json:"page"`
		Limit int       `json:"limit"`
	}

	expected := []AppInfo{
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
	}

	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (AppName, Version, Channel, Changelog) for each item in the response.
	if len(actual.Items) != len(expected) {
		t.Fatalf("Expected %d apps but got %d", len(expected), len(actual.Items))
	}

	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Items[i].AppName)
		assert.Equal(t, expectedApp.Version, actual.Items[i].Version)
		assert.Equal(t, expectedApp.Channel, actual.Items[i].Channel)
		assert.Equal(t, expectedApp.Published, actual.Items[i].Published)

		if len(expectedApp.Artifacts) != len(actual.Items[i].Artifacts) {
			t.Fatalf("Expected %d artifacts for app %s with version %s but got %d", len(expectedApp.Artifacts), expectedApp.ID, expectedApp.Version, len(actual.Items[i].Artifacts))
		}
		for j, expectedArtifact := range expectedApp.Artifacts {
			assert.Equal(t, expectedArtifact.Platform, actual.Items[i].Artifacts[j].Platform)
			assert.Equal(t, expectedArtifact.Arch, actual.Items[i].Artifacts[j].Arch)
			assert.Equal(t, expectedArtifact.Package, actual.Items[i].Artifacts[j].Package)
		}

		if len(expectedApp.Changelog) != len(actual.Items[i].Changelog) {
			t.Fatalf("Expected %d changelog entries for app %s but got %d", len(expectedApp.Changelog), expectedApp.ID, len(actual.Items[i].Changelog))
		}
		for c, expectedChanges := range expectedApp.Changelog {
			assert.Equal(t, expectedChanges.Version, actual.Items[i].Changelog[c].Version)
			assert.Equal(t, expectedChanges.Changes, actual.Items[i].Changelog[c].Changes)
			assert.Equal(t, expectedChanges.Date, actual.Items[i].Changelog[c].Date)
		}
	}

	assert.Equal(t, 1, actual.Page)
	assert.Equal(t, 9, actual.Limit)
	assert.Equal(t, len(expected), actual.Total)
}

func TestFilterSearchWithChannelAndPublishedAndCriticalAndPlatformAndArch(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /search endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/search", func(c *gin.Context) {
		handler.GetAppByName(c)
	})

	// Create a POST request for the /search endpoint.
	req, err := http.NewRequest("GET", "/search?app_name=testapp&channel=stable&published=true&critical=true&platform=universalPlatform&arch=universalArch", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)
	fmt.Println(w.Body.String())
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
		Items []AppInfo `json:"items"`
		Total int       `json:"total"`
		Page  int       `json:"page"`
		Limit int       `json:"limit"`
	}

	expected := []AppInfo{

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
	}

	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (AppName, Version, Channel, Changelog) for each item in the response.
	if len(actual.Items) != len(expected) {
		t.Fatalf("Expected %d apps but got %d", len(expected), len(actual.Items))
	}

	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Items[i].AppName)
		assert.Equal(t, expectedApp.Version, actual.Items[i].Version)
		assert.Equal(t, expectedApp.Channel, actual.Items[i].Channel)
		assert.Equal(t, expectedApp.Published, actual.Items[i].Published)

		if len(expectedApp.Artifacts) != len(actual.Items[i].Artifacts) {
			t.Fatalf("Expected %d artifacts for app %s with version %s but got %d", len(expectedApp.Artifacts), expectedApp.ID, expectedApp.Version, len(actual.Items[i].Artifacts))
		}
		for j, expectedArtifact := range expectedApp.Artifacts {
			assert.Equal(t, expectedArtifact.Platform, actual.Items[i].Artifacts[j].Platform)
			assert.Equal(t, expectedArtifact.Arch, actual.Items[i].Artifacts[j].Arch)
			assert.Equal(t, expectedArtifact.Package, actual.Items[i].Artifacts[j].Package)
		}

		if len(expectedApp.Changelog) != len(actual.Items[i].Changelog) {
			t.Fatalf("Expected %d changelog entries for app %s but got %d", len(expectedApp.Changelog), expectedApp.ID, len(actual.Items[i].Changelog))
		}
		for c, expectedChanges := range expectedApp.Changelog {
			assert.Equal(t, expectedChanges.Version, actual.Items[i].Changelog[c].Version)
			assert.Equal(t, expectedChanges.Changes, actual.Items[i].Changelog[c].Changes)
			assert.Equal(t, expectedChanges.Date, actual.Items[i].Changelog[c].Date)
		}
	}

	assert.Equal(t, 1, actual.Page)
	assert.Equal(t, 9, actual.Limit)
	assert.Equal(t, len(expected), actual.Total)
}

func TestSearchOnlyPublished(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /search endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/search", func(c *gin.Context) {
		handler.GetAppByName(c)
	})

	// Create a POST request for the /search endpoint.
	req, err := http.NewRequest("GET", "/search?app_name=testapp&published=true", nil)
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
		Items []AppInfo `json:"items"`
		Total int       `json:"total"`
		Page  int       `json:"page"`
		Limit int       `json:"limit"`
	}

	expected := []AppInfo{
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
	}

	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (AppName, Version, Channel, Changelog) for each item in the response.
	if len(actual.Items) != len(expected) {
		t.Fatalf("Expected %d apps but got %d", len(expected), len(actual.Items))
	}

	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Items[i].AppName)
		assert.Equal(t, expectedApp.Version, actual.Items[i].Version)
		assert.Equal(t, expectedApp.Channel, actual.Items[i].Channel)
		assert.Equal(t, expectedApp.Published, actual.Items[i].Published)

		if len(expectedApp.Artifacts) != len(actual.Items[i].Artifacts) {
			t.Fatalf("Expected %d artifacts for app %s with version %s but got %d", len(expectedApp.Artifacts), expectedApp.ID, expectedApp.Version, len(actual.Items[i].Artifacts))
		}
		for j, expectedArtifact := range expectedApp.Artifacts {
			assert.Equal(t, expectedArtifact.Platform, actual.Items[i].Artifacts[j].Platform)
			assert.Equal(t, expectedArtifact.Arch, actual.Items[i].Artifacts[j].Arch)
			assert.Equal(t, expectedArtifact.Package, actual.Items[i].Artifacts[j].Package)
		}

		if len(expectedApp.Changelog) != len(actual.Items[i].Changelog) {
			t.Fatalf("Expected %d changelog entries for app %s but got %d", len(expectedApp.Changelog), expectedApp.ID, len(actual.Items[i].Changelog))
		}
		for c, expectedChanges := range expectedApp.Changelog {
			assert.Equal(t, expectedChanges.Version, actual.Items[i].Changelog[c].Version)
			assert.Equal(t, expectedChanges.Changes, actual.Items[i].Changelog[c].Changes)
			assert.Equal(t, expectedChanges.Date, actual.Items[i].Changelog[c].Date)
		}
	}

	assert.Equal(t, 1, actual.Page)
	assert.Equal(t, 9, actual.Limit)
	assert.Equal(t, len(expected), actual.Total)
}

func TestSearchOnlyCritical(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /search endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/search", func(c *gin.Context) {
		handler.GetAppByName(c)
	})

	// Create a POST request for the /search endpoint.
	req, err := http.NewRequest("GET", "/search?app_name=testapp&critical=true", nil)
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
		Items []AppInfo `json:"items"`
		Total int       `json:"total"`
		Page  int       `json:"page"`
		Limit int       `json:"limit"`
	}

	expected := []AppInfo{
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
	}

	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (AppName, Version, Channel, Changelog) for each item in the response.
	if len(actual.Items) != len(expected) {
		t.Fatalf("Expected %d apps but got %d", len(expected), len(actual.Items))
	}

	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Items[i].AppName)
		assert.Equal(t, expectedApp.Version, actual.Items[i].Version)
		assert.Equal(t, expectedApp.Channel, actual.Items[i].Channel)
		assert.Equal(t, expectedApp.Published, actual.Items[i].Published)

		if len(expectedApp.Artifacts) != len(actual.Items[i].Artifacts) {
			t.Fatalf("Expected %d artifacts for app %s with version %s but got %d", len(expectedApp.Artifacts), expectedApp.ID, expectedApp.Version, len(actual.Items[i].Artifacts))
		}
		for j, expectedArtifact := range expectedApp.Artifacts {
			assert.Equal(t, expectedArtifact.Platform, actual.Items[i].Artifacts[j].Platform)
			assert.Equal(t, expectedArtifact.Arch, actual.Items[i].Artifacts[j].Arch)
			assert.Equal(t, expectedArtifact.Package, actual.Items[i].Artifacts[j].Package)
		}

		if len(expectedApp.Changelog) != len(actual.Items[i].Changelog) {
			t.Fatalf("Expected %d changelog entries for app %s but got %d", len(expectedApp.Changelog), expectedApp.ID, len(actual.Items[i].Changelog))
		}
		for c, expectedChanges := range expectedApp.Changelog {
			assert.Equal(t, expectedChanges.Version, actual.Items[i].Changelog[c].Version)
			assert.Equal(t, expectedChanges.Changes, actual.Items[i].Changelog[c].Changes)
			assert.Equal(t, expectedChanges.Date, actual.Items[i].Changelog[c].Date)
		}
	}

	assert.Equal(t, 1, actual.Page)
	assert.Equal(t, 9, actual.Limit)
	assert.Equal(t, len(expected), actual.Total)
}

func TestSearchOnlyUniversalPlatform(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /search endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/search", func(c *gin.Context) {
		handler.GetAppByName(c)
	})

	// Create a POST request for the /search endpoint.
	req, err := http.NewRequest("GET", "/search?app_name=testapp&platform=universalPlatform", nil)
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
		Items []AppInfo `json:"items"`
		Total int       `json:"total"`
		Page  int       `json:"page"`
		Limit int       `json:"limit"`
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
	}

	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (AppName, Version, Channel, Changelog) for each item in the response.
	if len(actual.Items) != len(expected) {
		t.Fatalf("Expected %d apps but got %d", len(expected), len(actual.Items))
	}

	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Items[i].AppName)
		assert.Equal(t, expectedApp.Version, actual.Items[i].Version)
		assert.Equal(t, expectedApp.Channel, actual.Items[i].Channel)
		assert.Equal(t, expectedApp.Published, actual.Items[i].Published)

		if len(expectedApp.Artifacts) != len(actual.Items[i].Artifacts) {
			t.Fatalf("Expected %d artifacts for app %s with version %s but got %d", len(expectedApp.Artifacts), expectedApp.ID, expectedApp.Version, len(actual.Items[i].Artifacts))
		}
		for j, expectedArtifact := range expectedApp.Artifacts {
			assert.Equal(t, expectedArtifact.Platform, actual.Items[i].Artifacts[j].Platform)
			assert.Equal(t, expectedArtifact.Arch, actual.Items[i].Artifacts[j].Arch)
			assert.Equal(t, expectedArtifact.Package, actual.Items[i].Artifacts[j].Package)
		}

		if len(expectedApp.Changelog) != len(actual.Items[i].Changelog) {
			t.Fatalf("Expected %d changelog entries for app %s but got %d", len(expectedApp.Changelog), expectedApp.ID, len(actual.Items[i].Changelog))
		}
		for c, expectedChanges := range expectedApp.Changelog {
			assert.Equal(t, expectedChanges.Version, actual.Items[i].Changelog[c].Version)
			assert.Equal(t, expectedChanges.Changes, actual.Items[i].Changelog[c].Changes)
			assert.Equal(t, expectedChanges.Date, actual.Items[i].Changelog[c].Date)
		}
	}

	assert.Equal(t, 1, actual.Page)
	assert.Equal(t, 9, actual.Limit)
	assert.Equal(t, len(expected), actual.Total)
}

func TestFetchkLatestVersionOfApp(t *testing.T) {
	router := gin.Default()
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
		Owner        string
	}{
		{
			AppName:     "testapp",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"nightly": map[string]interface{}{
					"universalPlatform": map[string]interface{}{
						"universalArch": map[string]interface{}{
							"dmg": map[string]interface{}{
								"url": fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137.dmg"),
							},
							"pkg": map[string]interface{}{
								"url": fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137.pkg"),
							},
							"no-extension": map[string]interface{}{
								"url": fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137"),
							},
						},
					},
				},
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
			Owner:        "admin",
		},
		{
			AppName:     "testapp",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"stable": map[string]interface{}{
					"universalPlatform": map[string]interface{}{
						"universalArch": map[string]interface{}{
							"dmg": map[string]interface{}{
								"url": fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137.dmg"),
							},
							"pkg": map[string]interface{}{
								"url": fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137.pkg"),
							},
							"no-extension": map[string]interface{}{
								"url": fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137"),
							},
						},
					},
				},
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "StableUpdateAvailable",
			Owner:        "admin",
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.TestName, func(t *testing.T) {
			w := httptest.NewRecorder()

			// Create a GET request for checking the version.
			req, err := http.NewRequest("GET", fmt.Sprintf("/apps/latest?app_name=%s&channel=%s&platform=%s&arch=%s&owner=%s", scenario.AppName, scenario.ChannelName, scenario.Platform, scenario.Arch, scenario.Owner), nil)
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
		Owner        string
	}{
		{
			AppName:     "public%20testapp",
			Version:     "0.0.1.137",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				// "changelog":        "### Changelog\n",
				"update_available": false,
				// "critical":         true,
				"update_url_dmg": fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "public%20testapp-admin/nightly/universalPlatform/universalArch/public%20testapp-0.0.1.137.dmg"),
				"update_url_pkg": fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "public%20testapp-admin/nightly/universalPlatform/universalArch/public%20testapp-0.0.1.137.pkg"),
				"update_url":     fmt.Sprintf("http://%s/%s/%s", s3Endpoint, s3Bucket, "public%20testapp-admin/nightly/universalPlatform/universalArch/public%20testapp-0.0.1.137"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
			Owner:        "admin",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.2.137",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"update_available": false,
				"update_url_dmg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137.dmg"),
				"update_url_pkg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137.pkg"),
				"update_url":       fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
			Owner:        "admin",
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
			Owner:        "admin",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.4.137",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"update_available": false,
				"update_url_dmg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137.dmg"),
				"update_url_pkg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137.pkg"),
				"update_url":       fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "StableUpdateAvailable",
			Owner:        "admin",
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
			Owner:    "admin",
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.TestName, func(t *testing.T) {
			w := httptest.NewRecorder()

			// Create a GET request for checking the version.
			req, err := http.NewRequest("GET", fmt.Sprintf("/checkVersion?app_name=%s&version=%s&channel=%s&platform=%s&arch=%s&owner=%s", scenario.AppName, scenario.Version, scenario.ChannelName, scenario.Platform, scenario.Arch, scenario.Owner), nil)
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

func TestMultipleDeleteWithUpdaters(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	// Define the route for the /apps/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/apps/delete", func(c *gin.Context) {
		handler.DeleteSpecificVersionOfApp(c)
	})

	// Iterate over the uploadedAppIDs and send a DELETE request for each ID.
	for _, appID := range uploadedAppIDsWithUpdaters {
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
		Owner        string
		DeviceID     string
	}{
		{
			AppName:     "testapp",
			Version:     "0.0.1.138",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"update_available": true,
				"critical":         false,
				"update_url_dmg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FsecondArch%2Ftestapp-0.0.2.138.dmg"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "secondArch",
			TestName:     "NightlyUpdateAvailable",
			Owner:        "admin",
			DeviceID:     "device-001",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.1.138",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"update_available": true,
				"critical":         false,
				"update_url_dmg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.138.dmg"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
			Owner:        "admin",
			DeviceID:     "device-002",
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
			Owner:        "admin",
			DeviceID:     "device-003",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.3.138",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"update_available": true,
				"critical":         true,
				"update_url_dmg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.138.dmg"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "StableUpdateAvailable",
			Owner:        "admin",
			DeviceID:     "device-004",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.3.138",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"update_available": true,
				"critical":         true,
				"update_url_dmg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FsecondPlatform%2FuniversalArch%2Ftestapp-0.0.4.138.dmg"),
			},
			ExpectedCode: http.StatusOK,
			// Published:    false,
			Platform: "secondPlatform",
			Arch:     "universalArch",
			TestName: "StableUpdateAvailable",
			Owner:    "admin",
			DeviceID: "device-005",
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.TestName, func(t *testing.T) {
			w := httptest.NewRecorder()

			// Create a GET request for checking the version.
			req, err := http.NewRequest("GET", fmt.Sprintf("/checkVersion?app_name=%s&version=%s&channel=%s&platform=%s&arch=%s&owner=%s", scenario.AppName, scenario.Version, scenario.ChannelName, scenario.Platform, scenario.Arch, scenario.Owner), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Device-ID", scenario.DeviceID)
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

func TestTelemetryWithVariousParams(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/telemetry", func(c *gin.Context) {
		handler.GetTelemetry(c)
	})
	endDate := time.Now().UTC().Truncate(24 * time.Hour)
	startDate := endDate.AddDate(0, 0, -7)
	dateRange, dailyStats := generateDateRangeAndStats(startDate, 8)
	scenarios := []struct {
		Name         string
		QueryParams  string
		ExpectedCode int
		ExpectedJSON map[string]interface{}
	}{
		{
			Name:         "Nightly universalPlatform + secondArch",
			QueryParams:  "range=week&apps=testapp&channels=nightly&platforms=universalPlatform&architectures=secondArch",
			ExpectedCode: http.StatusOK,
			ExpectedJSON: map[string]interface{}{
				"date":       startDate.Format("2006-01-02"),
				"date_range": dateRange,
				"admin":      "admin",
				"summary": map[string]interface{}{
					"total_requests":               float64(4),
					"unique_clients":               float64(1),
					"clients_using_latest_version": float64(0),
					"clients_outdated":             float64(1),
					"total_active_apps":            float64(1),
				},
				"versions": map[string]interface{}{
					"used_versions_count": float64(1),
					"known_versions": []interface{}{
						"0.0.1.138", "0.0.3.138",
					},
					"usage": []interface{}{
						map[string]interface{}{
							"version":      "0.0.1.138",
							"client_count": float64(1),
						},
					},
				},
				"platforms": []interface{}{
					map[string]interface{}{
						"platform":     "universalPlatform",
						"client_count": float64(1),
					},
				},
				"architectures": []interface{}{
					map[string]interface{}{
						"arch":         "secondArch",
						"client_count": float64(1),
					},
				},
				"channels": []interface{}{
					map[string]interface{}{
						"channel":      "nightly",
						"client_count": float64(1),
					},
				},
				"daily_stats": []interface{}{
					map[string]interface{}{"date": dailyStats[0], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[1], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[2], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[3], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[4], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[5], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[6], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[7], "total_requests": float64(4), "unique_clients": float64(1), "clients_using_latest_version": float64(0), "clients_outdated": float64(1)},
				},
			},
		},

		{
			Name:         "Nightly universalPlatform + universalArch",
			QueryParams:  "range=week&apps=testapp&channels=nightly&platforms=universalPlatform&architectures=universalArch",
			ExpectedCode: http.StatusOK,
			ExpectedJSON: map[string]interface{}{
				"date":       startDate.Format("2006-01-02"),
				"date_range": dateRange,
				"admin":      "admin",
				"summary": map[string]interface{}{
					"total_requests":               float64(4),
					"unique_clients":               float64(1),
					"clients_using_latest_version": float64(0),
					"clients_outdated":             float64(1),
					"total_active_apps":            float64(1),
				},
				"versions": map[string]interface{}{
					"used_versions_count": float64(1),
					"known_versions": []interface{}{
						"0.0.1.138", "0.0.3.138",
					},
					"usage": []interface{}{
						map[string]interface{}{
							"version":      "0.0.1.138",
							"client_count": float64(1),
						},
					},
				},
				"platforms": []interface{}{
					map[string]interface{}{
						"platform":     "universalPlatform",
						"client_count": float64(1),
					},
				},
				"architectures": []interface{}{
					map[string]interface{}{
						"arch":         "universalArch",
						"client_count": float64(1),
					},
				},
				"channels": []interface{}{
					map[string]interface{}{
						"channel":      "nightly",
						"client_count": float64(1),
					},
				},
				"daily_stats": []interface{}{
					map[string]interface{}{"date": dailyStats[0], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[1], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[2], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[3], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[4], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[5], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[6], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[7], "total_requests": float64(4), "unique_clients": float64(1), "clients_using_latest_version": float64(0), "clients_outdated": float64(1)},
				},
			},
		},
		{
			Name:         "Stable secondPlatform + universalArch",
			QueryParams:  "range=week&apps=testapp&channels=stable&platforms=secondPlatform&architectures=universalArch",
			ExpectedCode: http.StatusOK,
			ExpectedJSON: map[string]interface{}{
				"date":       startDate.Format("2006-01-02"),
				"date_range": dateRange,
				"admin":      "admin",
				"summary": map[string]interface{}{
					"total_requests":               float64(4),
					"unique_clients":               float64(1),
					"clients_using_latest_version": float64(0),
					"clients_outdated":             float64(1),
					"total_active_apps":            float64(1),
				},
				"versions": map[string]interface{}{
					"used_versions_count": float64(1),
					"known_versions": []interface{}{
						"0.0.1.138", "0.0.3.138",
					},
					"usage": []interface{}{
						map[string]interface{}{
							"version":      "0.0.3.138",
							"client_count": float64(1),
						},
					},
				},
				"platforms": []interface{}{
					map[string]interface{}{
						"platform":     "secondPlatform",
						"client_count": float64(1),
					},
				},
				"architectures": []interface{}{
					map[string]interface{}{
						"arch":         "universalArch",
						"client_count": float64(1),
					},
				},
				"channels": []interface{}{
					map[string]interface{}{
						"channel":      "stable",
						"client_count": float64(1),
					},
				},
				"daily_stats": []interface{}{
					map[string]interface{}{"date": dailyStats[0], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[1], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[2], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[3], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[4], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[5], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[6], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[7], "total_requests": float64(4), "unique_clients": float64(1), "clients_using_latest_version": float64(0), "clients_outdated": float64(1)},
				},
			},
		},
		{
			Name:         "Newer version — stable universal",
			QueryParams:  "range=week&apps=testapp&channels=stable&platforms=universalPlatform&architectures=universalArch",
			ExpectedCode: http.StatusOK,
			ExpectedJSON: map[string]interface{}{
				"date":       startDate.Format("2006-01-02"),
				"date_range": dateRange,
				"admin":      "admin",
				"summary": map[string]interface{}{
					"total_requests":               float64(4),
					"unique_clients":               float64(1),
					"clients_using_latest_version": float64(0),
					"clients_outdated":             float64(1),
					"total_active_apps":            float64(1),
				},
				"versions": map[string]interface{}{
					"used_versions_count": float64(1),
					"known_versions": []interface{}{
						"0.0.1.138", "0.0.3.138",
					},
					"usage": []interface{}{
						map[string]interface{}{
							"version":      "0.0.3.138",
							"client_count": float64(1),
						},
					},
				},
				"platforms": []interface{}{
					map[string]interface{}{
						"platform":     "universalPlatform",
						"client_count": float64(1),
					},
				},
				"architectures": []interface{}{
					map[string]interface{}{
						"arch":         "universalArch",
						"client_count": float64(1),
					},
				},
				"channels": []interface{}{
					map[string]interface{}{
						"channel":      "stable",
						"client_count": float64(1),
					},
				},
				"daily_stats": []interface{}{
					map[string]interface{}{"date": dailyStats[0], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[1], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[2], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[3], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[4], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[5], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[6], "total_requests": float64(0), "unique_clients": float64(0), "clients_using_latest_version": float64(0), "clients_outdated": float64(0)},
					map[string]interface{}{"date": dailyStats[7], "total_requests": float64(4), "unique_clients": float64(1), "clients_using_latest_version": float64(0), "clients_outdated": float64(1)},
				},
			},
		},
	}

	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, err := http.NewRequest("GET", "/telemetry?"+s.QueryParams, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Authorization", "Bearer "+authToken)
			router.ServeHTTP(w, req)

			assert.Equal(t, s.ExpectedCode, w.Code)

			var actual map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &actual)
			if err != nil {
				t.Fatalf("failed to parse response JSON: %v\nBody: %s", err, w.Body.String())
			}

			assert.Equal(t, s.ExpectedJSON, actual)
		})
	}
}

func TestListAppsWithSecondUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /app/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/app/list", func(c *gin.Context) {
		handler.ListApps(c)
	})

	// Create a POST request for the /app/list endpoint.
	req, err := http.NewRequest("GET", "/app/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"apps":null}`
	assert.Equal(t, expected, w.Body.String())
}
func TestListChannelsWithSecondUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/channel/list", func(c *gin.Context) {
		handler.ListChannels(c)
	})

	// Create a POST request for the /channel/list endpoint.
	req, err := http.NewRequest("GET", "/channel/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"channels":null}`
	assert.Equal(t, expected, w.Body.String())
}

func TestListPlatformsWithSecondUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/platform/list", func(c *gin.Context) {
		handler.ListPlatforms(c)
	})

	// Create a POST request for the /platform/list endpoint.
	req, err := http.NewRequest("GET", "/platform/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"platforms":null}`
	assert.Equal(t, expected, w.Body.String())
}

func TestListArchsWithSecondUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /arch/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/arch/list", func(c *gin.Context) {
		handler.ListArchs(c)
	})

	// Create a POST request for the /arch/list endpoint.
	req, err := http.NewRequest("GET", "/arch/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"archs":null}`
	assert.Equal(t, expected, w.Body.String())
}

func TestUpdateAppWithSecondUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d; got %d", http.StatusInternalServerError, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"error":"you don't have permission to update this app"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestUpdateChannelWithSecondUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /channel/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/channel/update", func(c *gin.Context) {
		handler.UpdateChannel(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s",
		"channel": "unstable"
	}`, idStableChannel)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/update endpoint
	req, err := http.NewRequest("POST", "/channel/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 500 Internal Server Error)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d; got %d", http.StatusInternalServerError, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"error":"you don't have permission to update this channel"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestUpdatePlatformWithSecondUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /platform/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/update", func(c *gin.Context) {
		handler.UpdatePlatform(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s",
		"platform": "newPlatform",
		"updaters": [
			{ "type": "manual", "default": true }
		]
	}`, platformId)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/update endpoint
	req, err := http.NewRequest("POST", "/platform/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d; got %d", http.StatusInternalServerError, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"error":"you don't have permission to update this platform"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestUpdateArchWithSecondUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /arch/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/arch/update", func(c *gin.Context) {
		handler.UpdateArch(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s",
		"arch": "newArch"
	}`, archId)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /arch/update endpoint
	req, err := http.NewRequest("POST", "/arch/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d; got %d", http.StatusInternalServerError, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"error":"you don't have permission to update this arch"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestMultipleDeleteWithSameExtensionArtifactsAndDiffPlatformsArchsWithSecondUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	// Define the route for the /apps/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
		req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
		// Serve the request using the Gin router.
		router.ServeHTTP(w, req)

		// Check the response status code for each request.
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		expected := `{"details":"you don't have permission to delete this item","error":"failed to delete specific version of app"}`
		assert.Equal(t, expected, w.Body.String())
	}
}

func TestDeleteNightlyChannelWithSecondUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/channel/delete", func(c *gin.Context) {
		handler.DeleteChannel(c)
	})

	// Create a DELETE request for the /channel/delete endpoint.
	req, err := http.NewRequest("DELETE", "/channel/delete?id="+idNightlyChannel, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	expected := `{"details":"you don't have permission to delete this channel","error":"failed to delete channel"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestDeletePlatformWithSecondUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/platform/delete", func(c *gin.Context) {
		handler.DeletePlatform(c)
	})

	// Create a DELETE request for the /platform/delete endpoint.
	req, err := http.NewRequest("DELETE", "/platform/delete?id="+platformId, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	expected := `{"details":"you don't have permission to delete this platform","error":"failed to delete platform"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestDeleteArchWithSecondUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /arch/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/arch/delete", func(c *gin.Context) {
		handler.DeleteArch(c)
	})

	// Create a DELETE request for the /arch/delete endpoint.
	req, err := http.NewRequest("DELETE", "/arch/delete?id="+archId, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	expected := `{"details":"you don't have permission to delete this arch","error":"failed to delete arch"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestDeleteAppMetaWithSecondUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /app/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/app/delete", func(c *gin.Context) {
		handler.DeleteApp(c)
	})

	// Create a DELETE request for the /app/delete endpoint.
	req, err := http.NewRequest("DELETE", "/app/delete?id="+idTestappApp, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	expected := `{"details":"you don't have permission to delete this app","error":"failed to delete app"}`
	assert.Equal(t, expected, w.Body.String())
}
func TestMultipleDeleteWithSameExtensionArtifactsAndDiffPlatformsArchs(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	// Define the route for the /apps/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

func TestCreateTeamUser(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/user/create", utils.AuthMiddleware(), utils.AdminOnlyMiddleware(mongoDatabase), func(c *gin.Context) {
		handler.CreateTeamUser(c)
	})

	type Permissions struct {
		Create   bool     `json:"create"`
		Delete   bool     `json:"delete"`
		Edit     bool     `json:"edit"`
		Download bool     `json:"download,omitempty"`
		Upload   bool     `json:"upload,omitempty"`
		Allowed  []string `json:"allowed"`
	}

	type Payload struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Permissions struct {
			Apps      Permissions `json:"apps"`
			Channels  Permissions `json:"channels"`
			Platforms Permissions `json:"platforms"`
			Archs     Permissions `json:"archs"`
		} `json:"permissions"`
	}

	payload := Payload{
		Username: "teamuser1",
		Password: "password123",
	}
	// It's unclear why, but if we pass a plain string in the array, everything works as expected. However, if we pass a variable containing a string value, it still exists throughout the process, but ends up being added to the database as an empty value.
	// There were many attempts to construct the request body using Sprintf, with new variables, or fetching the ID during the test — nothing helped.
	// The behavior is very strange. It seems that passing two identical values resolves the issue.
	// This has nothing to do with the application code — only one element from the array gets added to the database, so this quirk appears to relate specifically to the testing process.

	payload.Permissions.Apps = Permissions{
		Create: true, Delete: false, Edit: false, Download: true, Upload: false,
		Allowed: []string{idTestappApp, idTestappApp},
	}
	payload.Permissions.Channels = Permissions{
		Create: true, Delete: false, Edit: false,
		Allowed: []string{idStableChannel, idStableChannel},
	}
	payload.Permissions.Platforms = Permissions{
		Create: true, Delete: false, Edit: false,
		Allowed: []string{platformId, platformId},
	}
	payload.Permissions.Archs = Permissions{
		Create: true, Delete: false, Edit: false,
		Allowed: []string{archId, archId},
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	jsonString := string(jsonBytes)

	fmt.Println("payload", jsonString)
	req, err := http.NewRequest("POST", "/user/create", bytes.NewBufferString(jsonString))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
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

	expected := `{"message":"Team user created successfully"}`
	assert.Equal(t, expected, w.Body.String())
}

// TestTeamUserLogin tests logging in as the team user

var teamUserToken string

func TestTeamUserLogin(t *testing.T) {
	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/login", func(c *gin.Context) {
		handler.Login(c)
	})

	// Create a JSON payload for the request
	payload := `{"username": "teamuser1", "password": "password123"}`

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

	// Store the team user token for later tests
	teamUserToken = token.(string)

	// Check that the teamUserToken variable has been set
	assert.NotEmpty(t, teamUserToken)
}

var uploadedTeamApp string

func TestFailedUploadAppUsingTeamUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/upload", utils.CheckPermission(utils.PermissionUpload, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
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
	payload := `{"app_name": "testapp", "version": "0.0.1.137", "channel": "stable", "platform": "universalPlatform", "arch": "universalArch"}`
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
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code.
	assert.Equal(t, http.StatusForbidden, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	// Check the response status code (expecting 500).
	assert.Equal(t, http.StatusForbidden, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"Permission denied"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())

}

func TestFailedUpdateAppUsingTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/app/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
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
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for multipart/form-data
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 400).
	assert.Equal(t, http.StatusForbidden, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"Permission denied"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

func TestFailedUpdateChannelUsingTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /channel/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/channel/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceChannels, mongoDatabase), func(c *gin.Context) {
		handler.UpdateChannel(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s", 
		"channel":"newChannel"
	}`, idStableChannel)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/update endpoint
	req, err := http.NewRequest("POST", "/channel/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 403).
	assert.Equal(t, http.StatusForbidden, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"Permission denied"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

func TestFailedUpdatePlatformUsingTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /platform/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourcePlatforms, mongoDatabase), func(c *gin.Context) {
		handler.UpdatePlatform(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s", 
		"platform":"newPlatform"
	}`, platformId)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/update endpoint
	req, err := http.NewRequest("POST", "/platform/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 403).
	assert.Equal(t, http.StatusForbidden, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"Permission denied"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

func TestFailedUpdateArchUsingTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /arch/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/arch/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceArchs, mongoDatabase), func(c *gin.Context) {
		handler.UpdateArch(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s", 
		"arch":"newArch"
	}`, archId)

	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /arch/update endpoint
	req, err := http.NewRequest("POST", "/arch/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 403).
	assert.Equal(t, http.StatusForbidden, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"Permission denied"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}
func TestListAppsUsingTeamUserBeforeCreate(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /app/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/app/list", func(c *gin.Context) {
		handler.ListApps(c)
	})

	// Create a GET request for the /app/list endpoint.
	req, err := http.NewRequest("GET", "/app/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
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
			AppName: "testapp",
		},
	}
	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}
	// Verify that we received exactly one app
	assert.Equal(t, 1, len(actual.Apps), "Expected exactly one app in the response")
	// Compare the relevant fields (AppName) for each item in the response.
	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Apps[i].AppName)
	}
}

func TestListChannelsUsingTeamUserBeforeCreate(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/channel/list", func(c *gin.Context) {
		handler.ListChannels(c)
	})

	// Create a POST request for the /channel/list endpoint.
	req, err := http.NewRequest("GET", "/channel/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
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
			ChannelName: "stable",
		},
	}
	var actual ChannelResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that we received exactly one channel
	assert.Equal(t, 1, len(actual.Channels), "Expected exactly one channel in the response")

	// Compare the relevant fields (ChannelName) for each item in the response.
	for i, expectedChannel := range expected {
		assert.Equal(t, expectedChannel.ChannelName, actual.Channels[i].ChannelName)
	}
}

func TestListPlatformsUsingTeamUserBeforeCreate(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/platform/list", func(c *gin.Context) {
		handler.ListPlatforms(c)
	})

	// Create a POST request for the /platform/list endpoint.
	req, err := http.NewRequest("GET", "/platform/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
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
			PlatformName: "universalPlatform",
		},
	}
	var actual PlatformResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}
	// Verify that we received exactly one platform
	assert.Equal(t, 1, len(actual.Platforms), "Expected exactly one platform in the response")

	// Compare the relevant fields (PlatformName) for each item in the response.
	for i, expectedPlatform := range expected {
		assert.Equal(t, expectedPlatform.PlatformName, actual.Platforms[i].PlatformName)
	}
}

func TestListArchsUsingTeamUserBeforeCreate(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /arch/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/arch/list", func(c *gin.Context) {
		handler.ListArchs(c)
	})

	// Create a POST request for the /arch/list endpoint.
	req, err := http.NewRequest("GET", "/arch/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
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
			ArchID: "universalArch",
		},
	}
	var actual ArchResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}
	// Verify that we received exactly one arch
	assert.Equal(t, 1, len(actual.Archs), "Expected exactly one arch in the response")

	// Compare the relevant fields (ArchID) for each item in the response.
	for i, expectedArch := range expected {
		assert.Equal(t, expectedArch.ArchID, actual.Archs[i].ArchID)
	}
}

var idTeamApp string

func TestAppCreateTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/app/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
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
	payload := `{"app": "teamapp"}`
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
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
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

	// Check for the presence of the "createAppResult.Created" key in the response
	id, idExists := response["createAppResult.Created"]
	assert.True(t, idExists)
	idTeamApp = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, idTeamApp)
}

func TestListAppsUsingTeamUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/app/list", func(c *gin.Context) {
		handler.ListApps(c)
	})

	// Create a POST request for the /app/list endpoint.
	req, err := http.NewRequest("GET", "/app/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)
	type AppInfo struct {
		ID         string `json:"ID"`
		AppName    string `json:"AppName"`
		Owner      string `json:"Owner"`
		Updated_at string `json:"Updated_at"`
	}
	type AppResponse struct {
		Apps []AppInfo `json:"apps"`
	}

	expected := []AppInfo{
		{
			AppName: "testapp",
			Owner:   "admin",
		},
		{
			AppName: "teamapp",
			Owner:   "admin",
		},
	}
	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (ChannelName) for each item in the response.
	for i, expectedApp := range expected {
		logrus.Infoln("expectedApp.AppName", expectedApp.AppName)
		logrus.Infoln("actual.Apps[i].AppName", actual.Apps[i].AppName)
		assert.Equal(t, expectedApp.AppName, actual.Apps[i].AppName)
		assert.Equal(t, expectedApp.Owner, actual.Apps[i].Owner)
	}
}

func TestFailedDeleteTeamUserApp(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/app/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.DeleteApp(c)
	})

	// Create a DELETE request for the /channel/delete endpoint.
	req, err := http.NewRequest("DELETE", "/app/delete?id="+idTeamApp, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusForbidden, w.Code)

	expected := `{"error":"Permission denied"}`
	assert.Equal(t, expected, w.Body.String())
}

var idTeamChannel string

func TestChannelCreateTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /channel/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/channel/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceChannels, mongoDatabase), func(c *gin.Context) {
		handler.CreateChannel(c)
	})

	payload := `{
		"channel": "teamchannel"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/channel/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	idTeamChannel = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, idTeamChannel)
}

func TestListChannelsUsingTeamUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/channel/list", func(c *gin.Context) {
		handler.ListChannels(c)
	})

	// Create a POST request for the /channel/list endpoint.
	req, err := http.NewRequest("GET", "/channel/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)
	type ChannelInfo struct {
		ID          string `json:"ID"`
		ChannelName string `json:"ChannelName"`
		Owner       string `json:"Owner"`
		Updated_at  string `json:"Updated_at"`
	}
	type ChannelResponse struct {
		Channels []ChannelInfo `json:"channels"`
	}

	expected := []ChannelInfo{
		{
			ChannelName: "stable",
			Owner:       "admin",
		},
		{
			ChannelName: "teamchannel",
			Owner:       "admin",
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
		assert.Equal(t, expectedChannel.Owner, actual.Channels[i].Owner)
	}
}

func TestFailedDeleteTeamUserChannel(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/channel/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceChannels, mongoDatabase), func(c *gin.Context) {
		handler.DeleteChannel(c)
	})

	// Create a DELETE request for the /channel/delete endpoint.
	req, err := http.NewRequest("DELETE", "/channel/delete?id="+idTeamChannel, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusForbidden, w.Code)

	expected := `{"error":"Permission denied"}`
	assert.Equal(t, expected, w.Body.String())
}

var idTeamPlatform string

func TestPlatformCreateTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /channel/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourcePlatforms, mongoDatabase), func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	payload := `{
		"platform": "teamplatform"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/platform/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	id, idExists := response["createPlatformResult.Created"]
	assert.True(t, idExists)
	idTeamPlatform = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, idTeamPlatform)
}

func TestListPlatformsUsingTeamUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/platform/list", func(c *gin.Context) {
		handler.ListPlatforms(c)
	})

	// Create a POST request for the /channel/list endpoint.
	req, err := http.NewRequest("GET", "/platform/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)
	type PlatformInfo struct {
		ID           string `json:"ID"`
		PlatformName string `json:"PlatformName"`
		Owner        string `json:"Owner"`
		Updated_at   string `json:"Updated_at"`
	}
	type PlatformResponse struct {
		Platforms []PlatformInfo `json:"platforms"`
	}

	expected := []PlatformInfo{
		{
			PlatformName: "universalPlatform",
			Owner:        "admin",
		},
		{
			PlatformName: "teamplatform",
			Owner:        "admin",
		},
	}
	var actual PlatformResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (ChannelName) for each item in the response.
	for i, expectedPlatform := range expected {
		assert.Equal(t, expectedPlatform.PlatformName, actual.Platforms[i].PlatformName)
		assert.Equal(t, expectedPlatform.Owner, actual.Platforms[i].Owner)
	}
}

func TestFailedDeleteTeamUserPlatform(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/platform/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourcePlatforms, mongoDatabase), func(c *gin.Context) {
		handler.DeletePlatform(c)
	})

	// Create a DELETE request for the /channel/delete endpoint.
	req, err := http.NewRequest("DELETE", "/platform/delete?id="+idTeamPlatform, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusForbidden, w.Code)

	expected := `{"error":"Permission denied"}`
	assert.Equal(t, expected, w.Body.String())
}

var idTeamArch string

func TestArchCreateTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /channel/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/arch/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceArchs, mongoDatabase), func(c *gin.Context) {
		handler.CreateArch(c)
	})

	payload := `{
		"arch": "teamarch"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/create endpoint
	req, err := http.NewRequest("POST", "/arch/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	id, idExists := response["createArchResult.Created"]
	assert.True(t, idExists)
	idTeamArch = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, idTeamArch)
}

func TestListArchsUsingTeamUser(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/arch/list", func(c *gin.Context) {
		handler.ListArchs(c)
	})

	// Create a POST request for the /channel/list endpoint.
	req, err := http.NewRequest("GET", "/arch/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)
	type ArchInfo struct {
		ID         string `json:"ID"`
		ArchID     string `json:"ArchID"`
		Owner      string `json:"Owner"`
		Updated_at string `json:"Updated_at"`
	}
	type ArchResponse struct {
		Archs []ArchInfo `json:"archs"`
	}

	expected := []ArchInfo{
		{
			ArchID: "universalArch",
			Owner:  "admin",
		},
		{
			ArchID: "teamarch",
			Owner:  "admin",
		},
	}
	var actual ArchResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (ChannelName) for each item in the response.
	for i, expectedArch := range expected {
		assert.Equal(t, expectedArch.ArchID, actual.Archs[i].ArchID)
		assert.Equal(t, expectedArch.Owner, actual.Archs[i].Owner)
	}
}

func TestFailedDeleteTeamUserArch(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/arch/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceArchs, mongoDatabase), func(c *gin.Context) {
		handler.DeleteArch(c)
	})

	// Create a DELETE request for the /channel/delete endpoint.
	req, err := http.NewRequest("DELETE", "/arch/delete?id="+idTeamArch, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusForbidden, w.Code)

	expected := `{"error":"Permission denied"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestFailedUpdateTeamUser(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/user/update", utils.AuthMiddleware(), utils.AdminOnlyMiddleware(mongoDatabase), func(c *gin.Context) {
		handler.UpdateTeamUser(c)
	})

	type Permissions struct {
		Create   bool     `json:"create"`
		Delete   bool     `json:"delete"`
		Edit     bool     `json:"edit"`
		Download bool     `json:"download,omitempty"`
		Upload   bool     `json:"upload,omitempty"`
		Allowed  []string `json:"allowed"`
	}

	type Payload struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Permissions struct {
			Apps      Permissions `json:"apps"`
			Channels  Permissions `json:"channels"`
			Platforms Permissions `json:"platforms"`
			Archs     Permissions `json:"archs"`
		} `json:"permissions"`
	}

	payload := Payload{
		Username: "teamuser1",
		Password: "password123",
	}
	// It's unclear why, but if we pass a plain string in the array, everything works as expected. However, if we pass a variable containing a string value, it still exists throughout the process, but ends up being added to the database as an empty value.
	// There were many attempts to construct the request body using Sprintf, with new variables, or fetching the ID during the test — nothing helped.
	// The behavior is very strange. It seems that passing two identical values resolves the issue.
	// This has nothing to do with the application code — only one element from the array gets added to the database, so this quirk appears to relate specifically to the testing process.

	payload.Permissions.Apps = Permissions{
		Create: false, Delete: true, Edit: true, Download: true, Upload: false,
		Allowed: []string{idTestappApp, idTestappApp, idTeamApp},
	}
	payload.Permissions.Channels = Permissions{
		Create: false, Delete: true, Edit: true,
		Allowed: []string{idStableChannel, idStableChannel, idTeamChannel},
	}
	payload.Permissions.Platforms = Permissions{
		Create: false, Delete: true, Edit: true,
		Allowed: []string{platformId, platformId, idTeamPlatform},
	}
	payload.Permissions.Archs = Permissions{
		Create: false, Delete: true, Edit: true,
		Allowed: []string{archId, archId, idTeamArch},
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	jsonString := string(jsonBytes)

	fmt.Println("payload", jsonString)
	req, err := http.NewRequest("POST", "/user/update", bytes.NewBufferString(jsonString))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusForbidden, w.Code)

	// Parse the JSON response body to extract the token.
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"error":"Admin access required"}`
	assert.Equal(t, expected, w.Body.String())
}

var teamUserID string

func TestListTeamUsers(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/users/list", utils.AuthMiddleware(), utils.AdminOnlyMiddleware(mongoDatabase), func(c *gin.Context) {
		handler.ListTeamUsers(c)
	})

	req, err := http.NewRequest("GET", "/users/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response to get the team user ID
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Extract the team user ID from the response
	users := response["users"].([]interface{})
	teamUser := users[0].(map[string]interface{})
	teamUserID = teamUser["id"].(string)
	// Check that the teamUserID variable has been set
	assert.NotEmpty(t, teamUserID)
}

var adminID string

func TestWhoAmIAdmin(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/whoami", utils.AuthMiddleware(), func(c *gin.Context) {
		handler.Whoami(c)
	})

	req, err := http.NewRequest("GET", "/whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Extract the team user ID from the response
	adminID = response["id"].(string)
	adminName := response["username"].(string)
	isAdmin := response["is_admin"].(bool)
	// Check that the teamUserID variable has been set
	assert.NotEmpty(t, adminID)
	assert.NotEmpty(t, adminName)
	assert.True(t, isAdmin)
}

func TestWhoAmITeamUser(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/whoami", utils.AuthMiddleware(), func(c *gin.Context) {
		handler.Whoami(c)
	})

	req, err := http.NewRequest("GET", "/whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+teamUserToken)

	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Extract the team user ID from the response
	teamUserName := response["username"].(string)
	isAdmin := response["is_admin"].(bool)
	permissions := response["permissions"].(map[string]interface{})
	// Check that the teamUserID variable has been set
	assert.NotEmpty(t, teamUserName)
	assert.False(t, isAdmin)
	assert.NotNil(t, permissions)
	assert.Equal(t, 4, len(permissions))
}
func TestUpdateTeamUser(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/user/update", utils.AuthMiddleware(), utils.AdminOnlyMiddleware(mongoDatabase), func(c *gin.Context) {
		handler.UpdateTeamUser(c)
	})

	type Permissions struct {
		Create   bool     `json:"create"`
		Delete   bool     `json:"delete"`
		Edit     bool     `json:"edit"`
		Download bool     `json:"download,omitempty"`
		Upload   bool     `json:"upload,omitempty"`
		Allowed  []string `json:"allowed"`
	}

	type Payload struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		Permissions struct {
			Apps      Permissions `json:"apps"`
			Channels  Permissions `json:"channels"`
			Platforms Permissions `json:"platforms"`
			Archs     Permissions `json:"archs"`
		} `json:"permissions"`
	}

	payload := Payload{
		ID:       teamUserID,
		Username: "teamuser1",
		Password: "password123",
	}
	// It's unclear why, but if we pass a plain string in the array, everything works as expected. However, if we pass a variable containing a string value, it still exists throughout the process, but ends up being added to the database as an empty value.
	// There were many attempts to construct the request body using Sprintf, with new variables, or fetching the ID during the test — nothing helped.
	// The behavior is very strange. It seems that passing two identical values resolves the issue.
	// This has nothing to do with the application code — only one element from the array gets added to the database, so this quirk appears to relate specifically to the testing process.

	payload.Permissions.Apps = Permissions{
		Create: false, Delete: true, Edit: true, Download: true, Upload: false,
		Allowed: []string{idTestappApp, idTestappApp, idTeamApp},
	}
	payload.Permissions.Channels = Permissions{
		Create: false, Delete: true, Edit: true,
		Allowed: []string{idStableChannel, idStableChannel, idTeamChannel},
	}
	payload.Permissions.Platforms = Permissions{
		Create: false, Delete: true, Edit: true,
		Allowed: []string{platformId, platformId, idTeamPlatform},
	}
	payload.Permissions.Archs = Permissions{
		Create: false, Delete: true, Edit: true,
		Allowed: []string{archId, archId, idTeamArch},
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	jsonString := string(jsonBytes)

	fmt.Println("payload", jsonString)
	req, err := http.NewRequest("POST", "/user/update", bytes.NewBufferString(jsonString))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
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

	expected := `{"message":"Team user updated successfully"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestUpdateAppUsingTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/app/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
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
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
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

func TestUpdateChannelUsingTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /channel/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/channel/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceChannels, mongoDatabase), func(c *gin.Context) {
		handler.UpdateChannel(c)
	})

	payload := fmt.Sprintf(`{"id": "%s", 
		"channel":"newChannel"
	}`, idStableChannel)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/update endpoint
	req, err := http.NewRequest("POST", "/channel/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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

func TestUpdatePlatformUsingTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /platform/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourcePlatforms, mongoDatabase), func(c *gin.Context) {
		handler.UpdatePlatform(c)
	})

	payload := fmt.Sprintf(`{"id": "%s", 
		"platform":"newPlatform",
		"updaters": [
			{ "type": "manual", "default": true }
		]
	}`, platformId)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/update endpoint
	req, err := http.NewRequest("POST", "/platform/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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

	// Check for the presence of the "updatePlatformResult.Updated" key in the response
	updated, exists := response["updatePlatformResult.Updated"]
	assert.True(t, exists)
	assert.True(t, updated.(bool))
}

func TestUpdateArchUsingTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /arch/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/arch/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceArchs, mongoDatabase), func(c *gin.Context) {
		handler.UpdateArch(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s", 
		"arch":"newArch"
	}`, archId)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /arch/update endpoint
	req, err := http.NewRequest("POST", "/arch/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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

	// Check for the presence of the "updateArchResult.Updated" key in the response
	updated, exists := response["updateArchResult.Updated"]
	assert.True(t, exists)
	assert.True(t, updated.(bool))
}

func TestFailedAppCreateTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /app/create route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/app/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.CreateApp(c)
	})

	payload := `{
		"app_name": "teamapp2"
	}`
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /app/create endpoint
	req, err := http.NewRequest("POST", "/app/create", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status %d; got %d", http.StatusOK, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Check the response status code.
	assert.Equal(t, http.StatusForbidden, w.Code)

	expected := `{"error":"Permission denied"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestDeleteTeamUserApp(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/app/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.DeleteApp(c)
	})

	// Create a DELETE request for the /channel/delete endpoint.
	req, err := http.NewRequest("DELETE", "/app/delete?id="+idTeamApp, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deleteAppResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}
func TestDeleteTeamUserChannel(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/channel/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceChannels, mongoDatabase), func(c *gin.Context) {
		handler.DeleteChannel(c)
	})

	// Create a DELETE request for the /channel/delete endpoint.
	req, err := http.NewRequest("DELETE", "/channel/delete?id="+idTeamChannel, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deleteChannelResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}

func TestDeleteTeamUserPlatform(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/platform/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourcePlatforms, mongoDatabase), func(c *gin.Context) {
		handler.DeletePlatform(c)
	})

	// Create a DELETE request for the /channel/delete endpoint.
	req, err := http.NewRequest("DELETE", "/platform/delete?id="+idTeamPlatform, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deletePlatformResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}

func TestDeleteTeamUserArch(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /channel/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/arch/delete", utils.CheckPermission(utils.PermissionDelete, utils.ResourceArchs, mongoDatabase), func(c *gin.Context) {
		handler.DeleteArch(c)
	})

	// Create a DELETE request for the /channel/delete endpoint.
	req, err := http.NewRequest("DELETE", "/arch/delete?id="+idTeamArch, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	expected := `{"deleteArchResult.DeletedCount":1}`
	assert.Equal(t, expected, w.Body.String())
}

func TestFailedUpdateAdminUserUsingTeamUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /admin/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/admin/update", func(c *gin.Context) {
		handler.UpdateAdmin(c)
	})

	payload := fmt.Sprintf(`{"id": "%s", "username":"admin", "password":"password1234"}`, adminID)
	fmt.Println(payload)

	// Create a POST request to the /admin/update endpoint
	req, err := http.NewRequest("POST", "/admin/update", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	// Set the Content-Type header for application/json
	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status %d; got %d", http.StatusForbidden, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"error":"Username mismatch"}`
	assert.Equal(t, expected, w.Body.String())
}

// TestDeleteTeamUser tests deleting the team user
func TestDeleteTeamUser(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/user/delete", utils.AuthMiddleware(), utils.AdminOnlyMiddleware(mongoDatabase), func(c *gin.Context) {
		handler.DeleteTeamUser(c)
	})

	// Now delete the team user
	type DeleteTeamUserRequest struct {
		UserID string `json:"id"`
	}

	payload := DeleteTeamUserRequest{
		UserID: teamUserID,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	jsonString := string(jsonBytes)
	fmt.Println(jsonString)
	req, err := http.NewRequest("DELETE", "/user/delete", bytes.NewBufferString(jsonString))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)
	var response map[string]interface{}
	// Check the response status code
	assert.Equal(t, http.StatusOK, w.Code)
	fmt.Println("ITS HERE", w.Body.String())
	// Parse the response
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"message":"Team user deleted successfully"}`
	assert.Equal(t, expected, w.Body.String())
}

var uploadedAppIDsWithIntermediate []string

func TestMultipleUploadWithIntermediate(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
			AppName      string
			AppVersion   string
			ChannelName  string
			Published    bool
			Critical     bool
			Intermediate bool
			Platform     string
			Arch         string
		}{
			{"newApp", "0.0.6.135", "nightly", true, false, false, "secondPlatform", "secondArch"},
			{"newApp", "0.0.7.137", "nightly", true, false, true, "secondPlatform", "secondArch"},
			{"newApp", "0.0.8.136", "nightly", true, false, false, "secondPlatform", "secondArch"},
			{"newApp", "0.0.9.137", "nightly", true, true, true, "secondPlatform", "secondArch"},
			{"newApp", "0.0.10.138", "nightly", true, false, false, "secondPlatform", "secondArch"},
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
			payload := fmt.Sprintf(`{"app_name": "%s", "version": "%s", "channel": "%s", "publish": %v, "critical": %v, "intermediate": %v, "platform": "%s", "arch": "%s"}`, combo.AppName, combo.AppVersion, combo.ChannelName, combo.Published, combo.Critical, combo.Intermediate, combo.Platform, combo.Arch)
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
			fmt.Println("Response: ", response)
			id, idExists := response["uploadResult.Uploaded"]
			assert.True(t, idExists)

			// Check if the id already exists in the uploadedAppIDs array
			exists := false
			for _, val := range uploadedAppIDsWithIntermediate {
				if val == id {
					exists = true
					break
				}
			}

			// If id does not exist in the array, append it
			if !exists {
				fmt.Println("Adding ID: ", id)
				uploadedAppIDsWithIntermediate = append(uploadedAppIDsWithIntermediate, id.(string))
			}

			assert.True(t, idExists)
			assert.NotEmpty(t, id.(string))
		}
	}
}

func TestUpdateSpecificAppWithIntermediate(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	// Define the route for the update endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
			ID           string
			AppVersion   string
			ChannelName  string
			Published    bool
			Critical     bool
			Intermediate bool
			Platform     string
			Arch         string
			Changelog    string
		}{
			{uploadedAppIDsWithIntermediate[0], "0.0.6.135", "nightly", true, false, true, "secondPlatform", "secondArch", "### Changelog"},
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
			payload := fmt.Sprintf(`{"id": "%s", "app_name": "newApp", "version": "%s", "channel": "%s", "publish": %v, "critical": %v, "intermediate": %v, "platform": "%s", "arch": "%s", "changelog": "%s"}`, combo.ID, combo.AppVersion, combo.ChannelName, combo.Published, combo.Critical, combo.Intermediate, combo.Platform, combo.Arch, combo.Changelog)
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

func TestCheckVersionWithIntermediate(t *testing.T) {
	router := gin.Default()
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
		Owner        string
	}{
		{
			AppName:     "newApp",
			Version:     "0.0.6.135",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				// "changelog":                "### Changelog\n",
				"critical":                 false,
				"is_intermediate_required": true,
				"update_available":         true,
				"update_url_dmg":           fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.7.137.dmg"),
				"update_url_pkg":           fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.7.137.pkg"),
				"update_url":               fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.7.137"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "secondPlatform",
			Arch:         "secondArch",
			TestName:     "NightlyUpdateAvailable",
			Owner:        "admin",
		},
		{
			AppName:     "newApp",
			Version:     "0.0.7.137",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"critical":                 true,
				"is_intermediate_required": true,
				"update_available":         true,
				"update_url_dmg":           fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.9.137.dmg"),
				"update_url_pkg":           fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.9.137.pkg"),
				"update_url":               fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.9.137"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "secondPlatform",
			Arch:         "secondArch",
			TestName:     "NightlyUpdateAvailable",
			Owner:        "admin",
		},
		{
			AppName:     "newApp",
			Version:     "0.0.8.136",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"critical":                 true,
				"is_intermediate_required": true,
				"update_available":         true,
				"update_url_dmg":           fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.9.137.dmg"),
				"update_url_pkg":           fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.9.137.pkg"),
				"update_url":               fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.9.137"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "secondPlatform",
			Arch:         "secondArch",
			TestName:     "NightlyUpdateAvailable",
			Owner:        "admin",
		},
		{
			AppName:     "newApp",
			Version:     "0.0.9.137",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"critical":         false,
				"update_available": true,
				"update_url_dmg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.10.138.dmg"),
				"update_url_pkg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.10.138.pkg"),
				"update_url":       fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.10.138"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "secondPlatform",
			Arch:         "secondArch",
			TestName:     "StableUpdateAvailable",
			Owner:        "admin",
		},
		{
			AppName:     "newApp",
			Version:     "0.0.10.138",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"update_available": false,
				"update_url_dmg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.10.138.dmg"),
				"update_url_pkg":   fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.10.138.pkg"),
				"update_url":       fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.10.138"),
			},
			ExpectedCode: http.StatusOK,
			// Published:    false,
			Platform: "secondPlatform",
			Arch:     "secondArch",
			TestName: "StableUpdateAvailable",
			Owner:    "admin",
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.TestName, func(t *testing.T) {
			w := httptest.NewRecorder()

			// Create a GET request for checking the version.
			req, err := http.NewRequest("GET", fmt.Sprintf("/checkVersion?app_name=%s&version=%s&channel=%s&platform=%s&arch=%s&owner=%s", scenario.AppName, scenario.Version, scenario.ChannelName, scenario.Platform, scenario.Arch, scenario.Owner), nil)
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

func TestMultipleDeleteWithIntermediate(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	// Define the route for the /apps/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/apps/delete", func(c *gin.Context) {
		handler.DeleteSpecificVersionOfApp(c)
	})

	// Iterate over the uploadedAppIDs and send a DELETE request for each ID.
	for _, appID := range uploadedAppIDsWithIntermediate {
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/channel/update", func(c *gin.Context) {
		handler.UpdateChannel(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s", 
		"channel":"unstable"
	}`, idStableChannel)

	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /channel/update endpoint
	req, err := http.NewRequest("POST", "/channel/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/update", func(c *gin.Context) {
		handler.UpdatePlatform(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s", 
		"platform":"newPlatform",
		"updaters": [
			{ "type": "manual", "default": true }
		]
	}`, platformId)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /platform/update endpoint
	req, err := http.NewRequest("POST", "/platform/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/update", func(c *gin.Context) {
		handler.UpdatePlatform(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s", 
		"platform":"new * Platform",
		"updaters": [
			{ "type": "manual", "default": true }
		]
	}`, platformId)

	body := bytes.NewReader([]byte(payload))
	// Create a POST request to the /platform/update endpoint
	req, err := http.NewRequest("POST", "/platform/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 400).
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Check the response body for the desired error message.
	expectedErrorMessage := `{"error":"invalid platform name"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

func TestDeletePlatformWindows(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/platform/delete", func(c *gin.Context) {
		handler.DeletePlatform(c)
	})

	// Create a DELETE request for the /platform/delete endpoint.
	req, err := http.NewRequest("DELETE", "/platform/delete?id="+platformIdWindows, nil)
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

func TestDeletePlatformMacos(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/platform/delete", func(c *gin.Context) {
		handler.DeletePlatform(c)
	})

	// Create a DELETE request for the /platform/delete endpoint.
	req, err := http.NewRequest("DELETE", "/platform/delete?id="+platformIdMacos, nil)
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

func TestDeletePlatformMacosSquirrel(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/platform/delete", func(c *gin.Context) {
		handler.DeletePlatform(c)
	})

	// Create a DELETE request for the /platform/delete endpoint.
	req, err := http.NewRequest("DELETE", "/platform/delete?id="+platformIdMacosSquirrel, nil)
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

func TestListPlatformsWhenExist(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/list endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/arch/update", func(c *gin.Context) {
		handler.UpdateArch(c)
	})

	payload := fmt.Sprintf(`{
		"id": "%s", 
		"arch":"newArch"
	}`, archId)
	body := bytes.NewReader([]byte(payload))

	// Create a POST request to the /arch/update endpoint
	req, err := http.NewRequest("POST", "/arch/update", body)
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for JSON
	req.Header.Set("Content-Type", "application/json")

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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

func TestDeleteAppMetaUpdaters(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /app/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/app/delete", func(c *gin.Context) {
		handler.DeleteApp(c)
	})

	// Create a DELETE request for the /app/delete endpoint.
	req, err := http.NewRequest("DELETE", "/app/delete?id="+idTestappAppWithUpdaters, nil)
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

func TestDeletePublicAppMeta(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /app/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/app/delete", func(c *gin.Context) {
		handler.DeleteApp(c)
	})

	// Create a DELETE request for the /app/delete endpoint.
	req, err := http.NewRequest("DELETE", "/app/delete?id="+idPublicTestappApp, nil)
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

func TestFailedUpdateAdminUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /admin/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/admin/update", func(c *gin.Context) {
		handler.UpdateAdmin(c)
	})

	payload := fmt.Sprintf(`{"id": "%s", "username":"administrator", "password":"password1234"}`, adminID)
	fmt.Println(payload)

	// Create a POST request to the /admin/update endpoint
	req, err := http.NewRequest("POST", "/admin/update", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for application/json
	req.Header.Set("Content-Type", "application/json")

	// Serve the request using the Gin router
	router.ServeHTTP(w, req)
	logrus.Infoln("Response Body:", w.Body.String())
	// Check the response status code (expecting 200 OK)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status %d; got %d", http.StatusForbidden, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"error":"Username mismatch"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestUpdateAdminUser(t *testing.T) {
	// Initialize Gin router and recorder for the test
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the handler for the /admin/update route
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/admin/update", func(c *gin.Context) {
		handler.UpdateAdmin(c)
	})

	payload := fmt.Sprintf(`{"id": "%s", "username":"admin", "password":"password1234"}`, adminID)
	fmt.Println(payload)

	// Create a POST request to the /admin/update endpoint
	req, err := http.NewRequest("POST", "/admin/update", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}
	// Set the Authorization header.
	req.Header.Set("Authorization", "Bearer "+authToken)
	// Set the Content-Type header for application/json
	req.Header.Set("Content-Type", "application/json")

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

	expected := `{"message":"Admin updated successfully"}`
	assert.Equal(t, expected, w.Body.String())
}

func TestFailedLoginWithOldPassword(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
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

func TestSuccessfulLoginWithNewPassword(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/login", func(c *gin.Context) {
		handler.Login(c)
	})

	// Create a JSON payload for the request
	payload := `{"username": "admin", "password": "password1234"}`

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
