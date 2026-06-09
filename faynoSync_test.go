package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"faynoSync/mongod"
	"faynoSync/redisdb"
	"faynoSync/server/handler"
	"faynoSync/server/handler/info"
	"faynoSync/server/model"
	"faynoSync/server/utils"

	faynosync "github.com/ku9nov/faynosync-sdk-go"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

func assertSDKMatchesScenario(t *testing.T, expected map[string]interface{}, actual *faynosync.UpdateResponse) {
	t.Helper()

	require.Equal(t, expected["update_available"], actual.UpdateAvailable)
	require.Equal(t, expected["critical"], actual.Critical)
	if expectedIntermediate, ok := expected["is_intermediate_required"]; ok {
		require.Equal(t, expectedIntermediate, actual.IsIntermediateRequired)
	}
	if expectedRollback, ok := expected["possible_rollback"]; ok {
		rollbackField := reflect.ValueOf(actual).Elem().FieldByName("PossibleRollback")
		require.True(t, rollbackField.IsValid(), "expected field PossibleRollback to exist when possible_rollback is provided")
		require.Equal(t, reflect.Bool, rollbackField.Kind(), "expected field PossibleRollback to be bool when possible_rollback is provided")
		require.Equal(t, expectedRollback, rollbackField.Bool())
	}

	if expectedChangelog, ok := expected["changelog"]; ok {
		require.Equal(t, expectedChangelog, actual.Changelog)
	}

	if expectedURL, ok := expected["update_url"]; ok {
		require.Equal(t, expectedURL, actual.UpdateURL)
	}

	actualPackages := make(map[string]string, len(actual.PackageURLs))
	for _, pkg := range actual.PackageURLs {
		actualPackages[pkg.Package] = pkg.URL
	}

	for key, expectedValue := range expected {
		if !strings.HasPrefix(key, "update_url_") {
			continue
		}

		pkg := strings.TrimPrefix(key, "update_url_")
		require.Equal(t, expectedValue, actualPackages[pkg], "package URL mismatch for %s", pkg)
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
	s3Endpoint = viper.GetString("S3_ENDPOINT")
	s3Bucket = viper.GetString("S3_BUCKET_NAME")
	apiUrl = viper.GetString("API_URL")
	client, configDB = mongod.ConnectToDatabase(viper.GetString("MONGODB_URL_TESTS"))
	if err := mongod.RunMigrationsUp(client, configDB.Database); err != nil {
		panic(err)
	}
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
	payload := `{"app": "testapp", "private": "true", "tuf": "true", "reports": "true"}`
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

var keyValueReportKeyTestapp string

func TestListReportKeys(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/report-keys/list", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.ListReportKeys(c)
	})

	req, err := http.NewRequest("GET", "/report-keys/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	type ReportKeyResponse struct {
		ReportKeys []model.ReportKeyListItem `json:"report_keys"`
	}
	var actual ReportKeyResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}
	if !assert.Len(t, actual.ReportKeys, 1) {
		return
	}
	item := actual.ReportKeys[0]
	assert.Equal(t, "testapp", item.AppName)
	assert.True(t, strings.HasPrefix(item.KeyValue, utils.ReportKeyPrefix))
	assert.Len(t, item.KeyValue, len(utils.ReportKeyPrefix)+64)
	keyValueReportKeyTestapp = item.KeyValue
}

func TestRegenerateReportKey(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/report-keys/regenerate", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.RegenerateReportKey(c)
	})

	payload := `{"app_id": "` + idTestappApp + `"}`
	req, err := http.NewRequest("POST", "/report-keys/regenerate", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, idTestappApp, response["app_id"])
	assert.NotEqual(t, keyValueReportKeyTestapp, response["key_value"].(string))
	assert.True(t, strings.HasPrefix(response["key_value"].(string), utils.ReportKeyPrefix))
	assert.Len(t, response["key_value"].(string), len(utils.ReportKeyPrefix)+64)
	keyValueReportKeyTestapp = response["key_value"].(string)
}
func TestFailedRegenerateReportKeyWithSecondaryUser(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/report-keys/regenerate", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.RegenerateReportKey(c)
	})

	payload := `{"app_id": "` + idTestappApp + `"}`
	req, err := http.NewRequest("POST", "/report-keys/regenerate", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "app not found", response["error"].(string))
}
func TestListReportKeysWithSecondaryUser(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/report-keys/list", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.ListReportKeys(c)
	})

	req, err := http.NewRequest("GET", "/report-keys/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	type ReportKeyResponse struct {
		ReportKeys []model.ReportKeyListItem `json:"report_keys"`
	}
	var actual ReportKeyResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}
	if !assert.Len(t, actual.ReportKeys, 0) {
		t.Fatal("Expected 0 report keys")
	}
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
	payload := `{"app": "public testapp", "reports": "true", "cdn": "true"}`
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

var platformIdMacosTauri string

func TestPlatformCreateMacosTauri(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/platform/create", func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	payload := `{
		"platform": "macosTauri",
		"updaters": [
			{ "type": "manual", "default": false },
			{ "type": "tauri", "default": true }
		]
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
	platformIdMacosTauri = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, platformIdMacosTauri)
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
			{ "type": "electron-builder", "default": false },
			{ "type": "tauri", "default": false }
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
		Signature   string
	}{
		{"updaters", "0.0.1.137", "nightly", false, false, "macosSquirrel", "universalArch", "squirrel_darwin", "testapp.dmg", ""},
		{"updaters", "0.0.2.137", "nightly", true, false, "macosSquirrel", "universalArch", "squirrel_darwin", "test.zip", ""},
		{"updaters", "0.0.1.137", "nightly", false, false, "macosTauri", "universalArch", "tauri", "test.zip", ""},
		{"updaters", "0.0.2.137", "nightly", true, false, "macosTauri", "universalArch", "tauri", "test.zip", "dW50cnVzdGVkU2lnbmF0dXJlVGhhdExvb2tzTGlrZUFsb25nU3RyaW5n=="},
		{"updaters", "0.0.3.137", "nightly", false, false, "macos", "universalArch", "electron-builder", "testapp.dmg", ""},
		{"updaters", "0.0.4.137", "nightly", true, false, "macos", "universalArch", "electron-builder", "latest-mac.yml", ""},
		{"updaters", "0.0.5.137", "stable", false, true, "windows", "universalArch", "squirrel_windows", "test.exe", ""},
		{"updaters", "0.0.6.137", "stable", true, false, "windows", "universalArch", "squirrel_windows", "RELEASES", ""},
		{"updaters", "0.0.7.137", "stable", false, false, "windows", "universalArch", "electron-builder", "test.exe", ""},
		{"updaters", "0.0.8.137", "stable", true, false, "windows", "universalArch", "electron-builder", "latest.yml", ""},
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
		payload := fmt.Sprintf(`{"app_name": "%s", "version": "%s", "channel": "%s", "publish": %v, "critical": %v, "platform": "%s", "arch": "%s", "updater": "%s", "signature": "%s"}`, combo.AppName, combo.AppVersion, combo.ChannelName, combo.Published, combo.Critical, combo.Platform, combo.Arch, combo.Updater, combo.Signature)
		logrus.Infoln("Payload: ", payload)
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
			(combo.AppVersion == "0.0.7.137" && combo.FileName == "test.exe") ||
			(combo.AppVersion == "0.0.1.137" && combo.FileName == "test.zip")

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
			case "tauri":
				expectedErrorMsg = "tauri updater requires a signature parameter for update functionality. Please include a signature in your request"
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
				"url":              fmt.Sprintf("%s/%s", s3Endpoint, "updaters-admin/nightly/macosSquirrel/universalArch/updaters-0.0.2.137.zip"),
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
			Version:      "0.0.2.137",
			ChannelName:  "nightly",
			ExpectedJSON: map[string]interface{}{"status": "no_content"},
			ExpectedCode: http.StatusNoContent,
			Platform:     "macosTauri",
			Arch:         "universalArch",
			TestName:     "TauriUpdateNotAvailable",
			Owner:        "admin",
			Updater:      "tauri",
		},
		{
			AppName:     "updaters",
			Version:     "0.0.1.135",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"signature": "dW50cnVzdGVkU2lnbmF0dXJlVGhhdExvb2tzTGlrZUFsb25nU3RyaW5n==",
				"version":   "0.0.2.137",
				"url":       fmt.Sprintf("%s/%s", s3Endpoint, "updaters-admin/nightly/macosTauri/universalArch/updaters-0.0.2.137.zip"),
			},
			ExpectedCode: http.StatusOK,
			Platform:     "macosTauri",
			Arch:         "universalArch",
			TestName:     "TauriUpdateAvailable",
			Owner:        "admin",
			Updater:      "tauri",
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
				"update_url_yml":   fmt.Sprintf("%s/%s", s3Endpoint, "electron-builder/updaters-admin/0.0.4.137/nightly/macos/universalArch/latest-mac.yml"),
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
				"url":    fmt.Sprintf("%s/%s", s3Endpoint, "electron-builder/updaters-admin/0.0.8.137/stable/windows/universalArch/latest.yml"),
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

var cicdToken string
var cicdTokenID string
var cicdTokenSecondUserID string
var cicdTokenAdminAppID string
var cicdTokenSecondAdminAppID string

func TestTokenFlow01Create(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	appHandler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/token/create", utils.AdminOnlyMiddleware(mongoDatabase), func(c *gin.Context) {
		appHandler.CreateToken(c)
	})

	adminAppID := primitive.NewObjectID()
	secondAdminAppID := primitive.NewObjectID()
	collection := mongoDatabase.Collection("apps_meta")

	_, err := collection.InsertMany(context.TODO(), []interface{}{
		bson.M{"_id": adminAppID, "owner": "admin", "app_name": "token-flow-admin-app"},
		bson.M{"_id": secondAdminAppID, "owner": "administrator", "app_name": "token-flow-admin-second-app"},
	})
	assert.NoError(t, err)

	cicdTokenAdminAppID = adminAppID.Hex()
	cicdTokenSecondAdminAppID = secondAdminAppID.Hex()

	adminPayload := fmt.Sprintf(`{"name":"cicd-token-admin","allowed_apps":["%s"]}`, cicdTokenAdminAppID)
	adminReq, err := http.NewRequest("POST", "/token/create", bytes.NewBufferString(adminPayload))
	if err != nil {
		t.Fatal(err)
	}
	adminReq.Header.Set("Content-Type", "application/json")
	adminReq.Header.Set("Authorization", "Bearer "+authToken)
	adminW := httptest.NewRecorder()
	router.ServeHTTP(adminW, adminReq)
	assert.Equal(t, http.StatusCreated, adminW.Code)

	var adminResponse map[string]interface{}
	err = json.Unmarshal(adminW.Body.Bytes(), &adminResponse)
	if err != nil {
		t.Fatal(err)
	}

	tokenValue, tokenExists := adminResponse["token"]
	assert.True(t, tokenExists)
	cicdToken = tokenValue.(string)
	assert.NotEmpty(t, cicdToken)

	tokenIDValue, tokenIDExists := adminResponse["id"]
	assert.True(t, tokenIDExists)
	cicdTokenID = tokenIDValue.(string)
	assert.NotEmpty(t, cicdTokenID)

	secondPayload := fmt.Sprintf(`{"name":"cicd-token-second-admin","allowed_apps":["%s"]}`, cicdTokenSecondAdminAppID)
	secondReq, err := http.NewRequest("POST", "/token/create", bytes.NewBufferString(secondPayload))
	if err != nil {
		t.Fatal(err)
	}
	secondReq.Header.Set("Content-Type", "application/json")
	secondReq.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	secondW := httptest.NewRecorder()
	router.ServeHTTP(secondW, secondReq)
	assert.Equal(t, http.StatusCreated, secondW.Code)

	var secondResponse map[string]interface{}
	err = json.Unmarshal(secondW.Body.Bytes(), &secondResponse)
	if err != nil {
		t.Fatal(err)
	}

	secondTokenValue, secondTokenExists := secondResponse["token"]
	assert.True(t, secondTokenExists)
	secondToken := secondTokenValue.(string)
	assert.NotEmpty(t, secondToken)
	assert.NoError(t, os.Setenv("cicdTokenSecondUser", secondToken))

	secondTokenIDValue, secondTokenIDExists := secondResponse["id"]
	assert.True(t, secondTokenIDExists)
	cicdTokenSecondUserID = secondTokenIDValue.(string)
	assert.NotEmpty(t, cicdTokenSecondUserID)
}

func TestTokenCreateWithPastExpirationDate(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware(mongoDatabase))

	appHandler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/token/create", utils.AdminOnlyMiddleware(mongoDatabase), func(c *gin.Context) {
		appHandler.CreateToken(c)
	})

	adminPastExpiryAppID := primitive.NewObjectID()
	_, err := mongoDatabase.Collection("apps_meta").InsertOne(context.TODO(), bson.M{
		"_id":      adminPastExpiryAppID,
		"owner":    "admin",
		"app_name": "token-past-expiry-app",
	})
	assert.NoError(t, err)
	defer func() {
		_, cleanupErr := mongoDatabase.Collection("apps_meta").DeleteOne(context.TODO(), bson.M{"_id": adminPastExpiryAppID})
		assert.NoError(t, cleanupErr)
	}()

	pastTime := time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339Nano)
	payload := fmt.Sprintf(`{"name":"token-with-past-expiry","allowed_apps":["%s"],"expires_at":"%s"}`, adminPastExpiryAppID.Hex(), pastTime)
	req, err := http.NewRequest("POST", "/token/create", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, `{"error":"expires_at must be in the future"}`, w.Body.String())
}

func TestTokenExpiresImmediatelyAndReturnsUnauthorized(t *testing.T) {
	createRouter := gin.Default()
	createRouter.Use(utils.AuthMiddleware(mongoDatabase))

	appHandler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	createRouter.POST("/token/create", utils.AdminOnlyMiddleware(mongoDatabase), func(c *gin.Context) {
		appHandler.CreateToken(c)
	})

	adminShortExpiryAppID := primitive.NewObjectID()
	_, err := mongoDatabase.Collection("apps_meta").InsertOne(context.TODO(), bson.M{
		"_id":      adminShortExpiryAppID,
		"owner":    "admin",
		"app_name": "token-short-expiry-app",
	})
	assert.NoError(t, err)
	defer func() {
		_, cleanupErr := mongoDatabase.Collection("apps_meta").DeleteOne(context.TODO(), bson.M{"_id": adminShortExpiryAppID})
		assert.NoError(t, cleanupErr)
	}()

	expiresSoon := time.Now().Add(250 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	createPayload := fmt.Sprintf(`{"name":"token-short-expiry","allowed_apps":["%s"],"expires_at":"%s"}`, adminShortExpiryAppID.Hex(), expiresSoon)
	createReq, err := http.NewRequest("POST", "/token/create", bytes.NewBufferString(createPayload))
	if err != nil {
		t.Fatal(err)
	}
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "Bearer "+authToken)

	createW := httptest.NewRecorder()
	createRouter.ServeHTTP(createW, createReq)
	assert.Equal(t, http.StatusCreated, createW.Code)

	var createResponse map[string]interface{}
	err = json.Unmarshal(createW.Body.Bytes(), &createResponse)
	if err != nil {
		t.Fatal(err)
	}
	shortLivedToken, ok := createResponse["token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, shortLivedToken)

	time.Sleep(500 * time.Millisecond)
	useRouter := gin.Default()
	useRouter.Use(utils.AuthMiddleware(mongoDatabase))
	useRouter.POST("/test/upload", utils.CheckPermission(utils.PermissionUpload, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"result": "ok"})
	})

	useReq, err := http.NewRequest("POST", "/test/upload", nil)
	if err != nil {
		t.Fatal(err)
	}
	useReq.Header.Set("Authorization", "Bearer "+shortLivedToken)

	useW := httptest.NewRecorder()
	useRouter.ServeHTTP(useW, useReq)

	assert.Equal(t, http.StatusUnauthorized, useW.Code)
	assert.Equal(t, `{"error":"token expired"}`, useW.Body.String())
}

func TestTokenMiddlewareFlowForBothTokens(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware(mongoDatabase))

	router.POST("/test/app/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"result": "ok"})
	})
	router.POST("/test/upload", utils.CheckPermission(utils.PermissionUpload, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"result": "ok"})
	})
	router.GET("/test/token/list", utils.AdminOnlyMiddleware(mongoDatabase), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"result": "ok"})
	})

	secondToken := os.Getenv("cicdTokenSecondUser")
	assert.NotEmpty(t, cicdToken)
	assert.NotEmpty(t, secondToken)

	testTokens := []struct {
		name  string
		token string
	}{
		{name: "first api token", token: cicdToken},
		{name: "second api token", token: secondToken},
	}

	for _, tokenCase := range testTokens {
		t.Run(tokenCase.name, func(t *testing.T) {
			createReq, err := http.NewRequest("POST", "/test/app/create", nil)
			if err != nil {
				t.Fatal(err)
			}
			createReq.Header.Set("Authorization", "Bearer "+tokenCase.token)
			createW := httptest.NewRecorder()
			router.ServeHTTP(createW, createReq)
			assert.Equal(t, http.StatusForbidden, createW.Code)
			var createResponse map[string]interface{}
			err = json.Unmarshal(createW.Body.Bytes(), &createResponse)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, "API tokens are restricted to app upload", createResponse["error"])

			uploadReq, err := http.NewRequest("POST", "/test/upload", nil)
			if err != nil {
				t.Fatal(err)
			}
			uploadReq.Header.Set("Authorization", "Bearer "+tokenCase.token)
			uploadW := httptest.NewRecorder()
			router.ServeHTTP(uploadW, uploadReq)
			assert.Equal(t, http.StatusOK, uploadW.Code)

			adminOnlyReq, err := http.NewRequest("GET", "/test/token/list", nil)
			if err != nil {
				t.Fatal(err)
			}
			adminOnlyReq.Header.Set("Authorization", "Bearer "+tokenCase.token)
			adminOnlyW := httptest.NewRecorder()
			router.ServeHTTP(adminOnlyW, adminOnlyReq)
			assert.Equal(t, http.StatusForbidden, adminOnlyW.Code)
			var adminOnlyResponse map[string]interface{}
			err = json.Unmarshal(adminOnlyW.Body.Bytes(), &adminOnlyResponse)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, "Admin JWT is required", adminOnlyResponse["error"])
		})
	}
}

func TestTokenFlow02List(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	appHandler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/token/list", utils.AdminOnlyMiddleware(mongoDatabase), func(c *gin.Context) {
		appHandler.ListTokens(c)
	})

	adminReq, err := http.NewRequest("GET", "/token/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	adminReq.Header.Set("Authorization", "Bearer "+authToken)
	adminW := httptest.NewRecorder()
	router.ServeHTTP(adminW, adminReq)
	assert.Equal(t, http.StatusOK, adminW.Code)

	var adminResponse map[string]interface{}
	err = json.Unmarshal(adminW.Body.Bytes(), &adminResponse)
	if err != nil {
		t.Fatal(err)
	}

	adminTokens, ok := adminResponse["tokens"].([]interface{})
	assert.True(t, ok)
	adminTokenFound := false
	secondUserTokenVisibleForAdmin := false
	for _, token := range adminTokens {
		tokenMap, mapOk := token.(map[string]interface{})
		if !mapOk {
			continue
		}
		if tokenMap["id"] == cicdTokenID {
			adminTokenFound = true
		}
		if tokenMap["id"] == cicdTokenSecondUserID {
			secondUserTokenVisibleForAdmin = true
		}
	}
	assert.True(t, adminTokenFound)
	assert.False(t, secondUserTokenVisibleForAdmin)

	secondReq, err := http.NewRequest("GET", "/token/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	secondReq.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	secondW := httptest.NewRecorder()
	router.ServeHTTP(secondW, secondReq)
	assert.Equal(t, http.StatusOK, secondW.Code)

	var secondResponse map[string]interface{}
	err = json.Unmarshal(secondW.Body.Bytes(), &secondResponse)
	if err != nil {
		t.Fatal(err)
	}

	secondTokens, ok := secondResponse["tokens"].([]interface{})
	assert.True(t, ok)
	secondTokenFound := false
	adminTokenVisibleForSecondUser := false
	for _, token := range secondTokens {
		tokenMap, mapOk := token.(map[string]interface{})
		if !mapOk {
			continue
		}
		if tokenMap["id"] == cicdTokenSecondUserID {
			secondTokenFound = true
		}
		if tokenMap["id"] == cicdTokenID {
			adminTokenVisibleForSecondUser = true
		}
	}
	assert.True(t, secondTokenFound)
	assert.False(t, adminTokenVisibleForSecondUser)
	assert.NotEmpty(t, os.Getenv("cicdTokenSecondUser"))
}

func TestTokenFlow03Delete(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())

	appHandler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/token/delete", utils.AdminOnlyMiddleware(mongoDatabase), func(c *gin.Context) {
		appHandler.DeleteToken(c)
	})

	adminPayload := fmt.Sprintf(`{"id":"%s"}`, cicdTokenID)
	adminReq, err := http.NewRequest("DELETE", "/token/delete", bytes.NewBufferString(adminPayload))
	if err != nil {
		t.Fatal(err)
	}
	adminReq.Header.Set("Content-Type", "application/json")
	adminReq.Header.Set("Authorization", "Bearer "+authToken)
	adminW := httptest.NewRecorder()
	router.ServeHTTP(adminW, adminReq)
	assert.Equal(t, http.StatusOK, adminW.Code)

	secondPayload := fmt.Sprintf(`{"id":"%s"}`, cicdTokenSecondUserID)
	secondReq, err := http.NewRequest("DELETE", "/token/delete", bytes.NewBufferString(secondPayload))
	if err != nil {
		t.Fatal(err)
	}
	secondReq.Header.Set("Content-Type", "application/json")
	secondReq.Header.Set("Authorization", "Bearer "+authTokenSecondUser)
	secondW := httptest.NewRecorder()
	router.ServeHTTP(secondW, secondReq)
	assert.Equal(t, http.StatusOK, secondW.Code)

	idsForCleanup := []primitive.ObjectID{}
	if cicdTokenAdminAppID != "" {
		appID, parseErr := primitive.ObjectIDFromHex(cicdTokenAdminAppID)
		assert.NoError(t, parseErr)
		if parseErr == nil {
			idsForCleanup = append(idsForCleanup, appID)
		}
	}
	if cicdTokenSecondAdminAppID != "" {
		appID, parseErr := primitive.ObjectIDFromHex(cicdTokenSecondAdminAppID)
		assert.NoError(t, parseErr)
		if parseErr == nil {
			idsForCleanup = append(idsForCleanup, appID)
		}
	}
	if len(idsForCleanup) > 0 {
		_, err = mongoDatabase.Collection("apps_meta").DeleteMany(context.TODO(), bson.M{"_id": bson.M{"$in": idsForCleanup}})
		assert.NoError(t, err)
	}
}

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
	server := httptest.NewServer(router)
	defer server.Close()

	sdkClient := faynosync.NewClient(faynosync.Config{
		EdgeURL: s3Endpoint,
		BaseURL: server.URL,
	})

	decodeScenarioValue := func(raw string) string {
		decoded, err := url.QueryUnescape(raw)
		if err != nil {
			return raw
		}
		return decoded
	}

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
				"update_available":  false,
				"critical":          false,
				"possible_rollback": false,
				"update_url_dmg":    fmt.Sprintf("%s/%s", s3Endpoint, "public%20testapp-admin/nightly/universalPlatform/universalArch/public%20testapp-0.0.1.137.dmg"),
				"update_url_pkg":    fmt.Sprintf("%s/%s", s3Endpoint, "public%20testapp-admin/nightly/universalPlatform/universalArch/public%20testapp-0.0.1.137.pkg"),
				"update_url":        fmt.Sprintf("%s/%s", s3Endpoint, "public%20testapp-admin/nightly/universalPlatform/universalArch/public%20testapp-0.0.1.137"),
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
				"update_available":  false,
				"critical":          false,
				"possible_rollback": false,
				"update_url_dmg":    fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137.dmg"),
				"update_url_pkg":    fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137.pkg"),
				"update_url":        fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137"),
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
				"critical":          true,
				"possible_rollback": true,
				"changelog":         "### Changelog\n",
				"update_available":  false,
				"update_url_dmg":    fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137.dmg"),
				"update_url_pkg":    fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137.pkg"),
				"update_url":        fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.2.137"),
			},
			ExpectedCode: http.StatusOK,
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
				"update_available":  false,
				"critical":          false,
				"possible_rollback": false,
				"update_url_dmg":    fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137.dmg"),
				"update_url_pkg":    fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137.pkg"),
				"update_url":        fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137"),
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
				"update_available":  false,
				"critical":          true,
				"possible_rollback": true,
				"update_url_dmg":    fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137.dmg"),
				"update_url_pkg":    fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137.pkg"),
				"update_url":        fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fstable%2FuniversalPlatform%2FuniversalArch%2Ftestapp-0.0.4.137"),
			},
			ExpectedCode: http.StatusOK,
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

			sdkResp, err := sdkClient.CheckForUpdates(
				context.Background(),
				faynosync.CheckOptions{
					Owner:    decodeScenarioValue(scenario.Owner),
					AppName:  decodeScenarioValue(scenario.AppName),
					Version:  decodeScenarioValue(scenario.Version),
					Channel:  decodeScenarioValue(scenario.ChannelName),
					Platform: decodeScenarioValue(scenario.Platform),
					Arch:     decodeScenarioValue(scenario.Arch),
				},
			)
			require.NoError(t, err)
			assertSDKMatchesScenario(t, scenario.ExpectedJSON, sdkResp)
			expectedSource := faynosync.SourceAPI
			if scenario.AppName == "public%20testapp" && scenario.Version == "0.0.1.137" && scenario.ChannelName == "nightly" {
				expectedSource = faynosync.SourceEdge
			}
			require.Equal(t, expectedSource, sdkResp.Source)
		})
	}
}

func TestUpdateSpecificAppWithCDNPublishFalseToCheckS3ObjectDeleted(t *testing.T) {

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
			{uploadedAppIDs[0], "0.0.1.137", "nightly", false, true, "universalPlatform", "universalArch", "### Changelog"},
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
			payload := fmt.Sprintf(`{"id": "%s", "app_name": "public testapp", "version": "%s", "channel": "%s", "publish": %v, "critical": %v, "platform": "%s", "arch": "%s", "changelog": "%s"}`, combo.ID, combo.AppVersion, combo.ChannelName, combo.Published, combo.Critical, combo.Platform, combo.Arch, combo.Changelog)
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
			assert.Equal(t, http.StatusOK, w.Code)

			expected := `{"updatedResult.Updated":true}`
			assert.Equal(t, expected, w.Body.String())

			cdnResponseURL, err := url.Parse(s3Endpoint)
			require.NoError(t, err)
			cdnResponseURL = cdnResponseURL.JoinPath(
				"responses",
				"admin",
				"public testapp",
				combo.ChannelName,
				combo.Platform,
				combo.Arch,
				combo.AppVersion+".json",
			)

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cdnReq, err := http.NewRequestWithContext(ctx, http.MethodGet, cdnResponseURL.String(), nil)
			require.NoError(t, err)
			resp, err := http.DefaultClient.Do(cdnReq)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusNotFound, resp.StatusCode, "CDN response JSON should be deleted after publish=false update: %s", cdnResponseURL.String())
		}
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
	server := httptest.NewServer(router)
	defer server.Close()

	sdkClient := faynosync.NewClient(faynosync.Config{
		BaseURL: server.URL,
	})

	decodeScenarioValue := func(raw string) string {
		decoded, err := url.QueryUnescape(raw)
		if err != nil {
			return raw
		}
		return decoded
	}
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
				"critical":          false,
				"possible_rollback": true,
				"update_available":  false,
				"update_url_dmg":    fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "testapp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2Ftestapp-0.0.1.138.dmg"),
			},
			ExpectedCode: http.StatusOK,
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
			sdkResp, err := sdkClient.CheckForUpdates(
				context.Background(),
				faynosync.CheckOptions{
					Owner:    decodeScenarioValue(scenario.Owner),
					AppName:  decodeScenarioValue(scenario.AppName),
					Version:  decodeScenarioValue(scenario.Version),
					Channel:  decodeScenarioValue(scenario.ChannelName),
					Platform: decodeScenarioValue(scenario.Platform),
					Arch:     decodeScenarioValue(scenario.Arch),
					DeviceID: decodeScenarioValue(scenario.DeviceID),
				},
			)
			require.NoError(t, err)
			assertSDKMatchesScenario(t, scenario.ExpectedJSON, sdkResp)
		})
	}
}

func TestTelemetryWithVariousParams(t *testing.T) {
	if !viper.GetBool("ENABLE_TELEMETRY") || redisClient == nil {
		t.Skip("telemetry integration tests require ENABLE_TELEMETRY=true and Redis connection")
	}

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
					"total_requests":               float64(10),
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
					map[string]interface{}{"date": dailyStats[7], "total_requests": float64(10), "unique_clients": float64(1), "clients_using_latest_version": float64(0), "clients_outdated": float64(1)},
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
					"total_requests":               float64(10),
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
					map[string]interface{}{"date": dailyStats[7], "total_requests": float64(10), "unique_clients": float64(1), "clients_using_latest_version": float64(0), "clients_outdated": float64(1)},
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
					"total_requests":               float64(10),
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
					map[string]interface{}{"date": dailyStats[7], "total_requests": float64(10), "unique_clients": float64(1), "clients_using_latest_version": float64(0), "clients_outdated": float64(1)},
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
					"total_requests":               float64(10),
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
					map[string]interface{}{"date": dailyStats[7], "total_requests": float64(10), "unique_clients": float64(1), "clients_using_latest_version": float64(0), "clients_outdated": float64(1)},
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

	t.Run("Deduplicates repeated client IDs across week and month ranges", func(t *testing.T) {
		if !viper.GetBool("ENABLE_TELEMETRY") || redisClient == nil {
			t.Skip("redis telemetry backend is not configured")
		}
		ctx := context.Background()
		dedupApp := fmt.Sprintf("testapp-dedup-%d", time.Now().UTC().UnixNano())
		dedupClientID := "dedup-client-001"
		dedupVersion := "9.9.9"
		dateA := startDate.AddDate(0, 0, 1).Format("2006-01-02")
		dateB := startDate.AddDate(0, 0, 2).Format("2006-01-02")

		baseKey := fmt.Sprintf("stats:admin:%s", dedupApp)
		seededKeys := []string{
			fmt.Sprintf("%s:requests:%s", baseKey, dateA),
			fmt.Sprintf("%s:requests:%s", baseKey, dateB),
			fmt.Sprintf("%s:unique_clients:%s", baseKey, dateA),
			fmt.Sprintf("%s:unique_clients:%s", baseKey, dateB),
			fmt.Sprintf("%s:clients_using_latest_version:%s", baseKey, dateA),
			fmt.Sprintf("%s:clients_using_latest_version:%s", baseKey, dateB),
			fmt.Sprintf("%s:clients_outdated:%s", baseKey, dateA),
			fmt.Sprintf("%s:clients_outdated:%s", baseKey, dateB),
			fmt.Sprintf("%s:version_usage:%s:%s", baseKey, dateA, dedupVersion),
			fmt.Sprintf("%s:version_usage:%s:%s", baseKey, dateB, dedupVersion),
			fmt.Sprintf("%s:known_versions", baseKey),
		}

		t.Cleanup(func() {
			if len(seededKeys) > 0 {
				_ = redisClient.Del(ctx, seededKeys...).Err()
			}
		})

		assert.NoError(t, redisClient.Set(ctx, seededKeys[0], 3, 0).Err())
		assert.NoError(t, redisClient.Set(ctx, seededKeys[1], 2, 0).Err())
		assert.NoError(t, redisClient.SAdd(ctx, seededKeys[2], dedupClientID).Err())
		assert.NoError(t, redisClient.SAdd(ctx, seededKeys[3], dedupClientID).Err())
		assert.NoError(t, redisClient.SAdd(ctx, seededKeys[4], dedupClientID).Err())
		assert.NoError(t, redisClient.SAdd(ctx, seededKeys[5], dedupClientID).Err())
		assert.NoError(t, redisClient.SAdd(ctx, seededKeys[6], dedupClientID).Err())
		assert.NoError(t, redisClient.SAdd(ctx, seededKeys[7], dedupClientID).Err())
		assert.NoError(t, redisClient.SAdd(ctx, seededKeys[8], dedupClientID).Err())
		assert.NoError(t, redisClient.SAdd(ctx, seededKeys[9], dedupClientID).Err())
		assert.NoError(t, redisClient.SAdd(ctx, seededKeys[10], dedupVersion).Err())

		queryScenarios := []string{
			fmt.Sprintf("range=week&apps=%s", dedupApp),
			fmt.Sprintf("range=month&apps=%s", dedupApp),
		}

		for _, query := range queryScenarios {
			w := httptest.NewRecorder()
			req, err := http.NewRequest("GET", "/telemetry?"+query, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+authToken)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			var actual map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &actual)
			if err != nil {
				t.Fatalf("failed to parse response JSON: %v\nBody: %s", err, w.Body.String())
			}

			summary, ok := actual["summary"].(map[string]interface{})
			if !ok {
				t.Fatalf("summary is missing or invalid: %v", actual["summary"])
			}

			assert.Equal(t, float64(5), summary["total_requests"])
			assert.Equal(t, float64(1), summary["unique_clients"])
			assert.Equal(t, float64(1), summary["clients_using_latest_version"])
			assert.Equal(t, float64(1), summary["clients_outdated"])
			assert.Equal(t, float64(1), summary["total_active_apps"])

			versions, ok := actual["versions"].(map[string]interface{})
			if !ok {
				t.Fatalf("versions is missing or invalid: %v", actual["versions"])
			}

			assert.Equal(t, float64(1), versions["used_versions_count"])
			usage, ok := versions["usage"].([]interface{})
			if !ok || len(usage) != 1 {
				t.Fatalf("versions.usage is invalid: %v", versions["usage"])
			}
			usageEntry, ok := usage[0].(map[string]interface{})
			if !ok {
				t.Fatalf("versions.usage[0] is invalid: %v", usage[0])
			}
			assert.Equal(t, dedupVersion, usageEntry["version"])
			assert.Equal(t, float64(1), usageEntry["client_count"])
		}
	})
}

func TestTelemetryLuaEmitsArchAndChannelKeys(t *testing.T) {
	if !viper.GetBool("ENABLE_TELEMETRY") || redisClient == nil {
		t.Skip("redis telemetry backend is not configured")
	}

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	appHandler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/telemetry", func(c *gin.Context) {
		appHandler.GetTelemetry(c)
	})

	ctx := context.Background()
	admin := "admin"
	testApp := fmt.Sprintf("telemetry-raw-keys-%d", time.Now().UTC().UnixNano())
	clientID := "lua-key-client-1"
	testDate := time.Now().UTC().Format("2006-01-02")
	baseKey := fmt.Sprintf("stats:%s:%s", admin, testApp)

	keysToCleanup := []string{
		fmt.Sprintf("%s:requests:%s", baseKey, testDate),
		fmt.Sprintf("%s:unique_clients:%s", baseKey, testDate),
		fmt.Sprintf("%s:architectures:%s:arm64", baseKey, testDate),
		fmt.Sprintf("%s:channels:%s:stable", baseKey, testDate),
	}
	t.Cleanup(func() {
		_ = redisClient.Del(ctx, keysToCleanup...).Err()
	})

	assert.NoError(t, redisClient.Set(ctx, keysToCleanup[0], 1, 0).Err())
	assert.NoError(t, redisClient.SAdd(ctx, keysToCleanup[1], clientID).Err())
	assert.NoError(t, redisClient.SAdd(ctx, keysToCleanup[2], clientID).Err())
	assert.NoError(t, redisClient.SAdd(ctx, keysToCleanup[3], clientID).Err())

	w := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/telemetry?date=%s&apps=%s", testDate, testApp), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse telemetry response: %v\nBody: %s", err, w.Body.String())
	}

	architectures, ok := result["architectures"].([]interface{})
	if !ok || len(architectures) != 1 {
		t.Fatalf("unexpected architectures payload: %v", result["architectures"])
	}
	archEntry, ok := architectures[0].(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected architectures[0] payload: %v", architectures[0])
	}
	assert.Equal(t, "arm64", archEntry["arch"])
	_, hasArchPlatformKey := archEntry["platform"]
	assert.False(t, hasArchPlatformKey)

	channels, ok := result["channels"].([]interface{})
	if !ok || len(channels) != 1 {
		t.Fatalf("unexpected channels payload: %v", result["channels"])
	}
	channelEntry, ok := channels[0].(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected channels[0] payload: %v", channels[0])
	}
	assert.Equal(t, "stable", channelEntry["channel"])
	_, hasChannelPlatformKey := channelEntry["platform"]
	assert.False(t, hasChannelPlatformKey)
}

func TestTelemetryBeaconUsesAllowListAndExistingRedisKeys(t *testing.T) {
	if !viper.GetBool("ENABLE_TELEMETRY") || redisClient == nil {
		t.Skip("redis telemetry backend is not configured")
	}

	ctx := context.Background()
	owner := fmt.Sprintf("beacon-owner-%d", time.Now().UTC().UnixNano())
	appName := "beaconapp"
	channel := "stable"
	platform := "darwin"
	arch := "arm64"
	version := "1.2.3"
	dateStr := time.Now().UTC().Format("2006-01-02")
	baseKey := fmt.Sprintf("stats:%s:%s", owner, appName)
	keysToCleanup := []string{
		fmt.Sprintf("%s:requests:%s", baseKey, dateStr),
		fmt.Sprintf("%s:unique_clients:%s", baseKey, dateStr),
		fmt.Sprintf("%s:channels:%s:%s", baseKey, dateStr, channel),
		fmt.Sprintf("%s:platforms:%s:%s", baseKey, dateStr, platform),
		fmt.Sprintf("%s:architectures:%s:%s", baseKey, dateStr, arch),
		fmt.Sprintf("%s:known_versions", baseKey),
		fmt.Sprintf("%s:version_usage:%s:%s", baseKey, dateStr, version),
		fmt.Sprintf("%s:clients_using_latest_version:%s", baseKey, dateStr),
		fmt.Sprintf("%s:clients_outdated:%s", baseKey, dateStr),
	}

	metaCollection := mongoDatabase.Collection("apps_meta")
	appsCollection := mongoDatabase.Collection("apps")
	t.Cleanup(func() {
		_, _ = metaCollection.DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = appsCollection.DeleteMany(ctx, bson.M{"owner": owner})
		_ = redisClient.Del(ctx, keysToCleanup...).Err()
	})
	_ = redisClient.Del(ctx, keysToCleanup...).Err()
	_, _ = metaCollection.DeleteMany(ctx, bson.M{"owner": owner})
	_, _ = appsCollection.DeleteMany(ctx, bson.M{"owner": owner})

	appID := primitive.NewObjectID()
	channelID := primitive.NewObjectID()
	platformID := primitive.NewObjectID()
	archID := primitive.NewObjectID()
	now := primitive.NewDateTimeFromTime(time.Now().UTC())

	_, err := metaCollection.InsertMany(ctx, []interface{}{
		bson.M{"_id": appID, "app_name": appName, "owner": owner, "updated_at": now},
		bson.M{"_id": channelID, "channel_name": channel, "owner": owner, "updated_at": now},
		bson.M{"_id": platformID, "platform_name": platform, "owner": owner, "updated_at": now},
		bson.M{"_id": archID, "arch_id": arch, "owner": owner, "updated_at": now},
	})
	require.NoError(t, err)

	_, err = appsCollection.InsertOne(ctx, bson.M{
		"_id":        primitive.NewObjectID(),
		"app_id":     appID,
		"version":    version,
		"channel_id": channelID,
		"published":  true,
		"owner":      owner,
		"artifacts": []bson.M{
			{"platform": platformID, "arch": archID, "package": ".zip", "link": "https://example.com/beacon.zip"},
		},
		"updated_at": now,
	})
	require.NoError(t, err)
	require.NoError(t, info.ReloadTelemetryAllowList(ctx, mongoDatabase))

	router := gin.Default()
	appHandler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/telemetry/beacon", func(c *gin.Context) {
		appHandler.TelemetryBeacon(c)
	})

	validQuery := fmt.Sprintf(
		"/telemetry/beacon?owner=%s&app_name=%s&version=%s&channel=%s&platform=%s&arch=%s",
		url.QueryEscape(owner),
		url.QueryEscape(appName),
		url.QueryEscape(version),
		url.QueryEscape(channel),
		url.QueryEscape(platform),
		url.QueryEscape(arch),
	)

	w := httptest.NewRecorder()
	req, err := http.NewRequest("GET", validQuery+"&is_latest=true", nil)
	require.NoError(t, err)
	req.Header.Set("X-Device-ID", "beacon-device-latest")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)

	requestCount, err := redisClient.Get(ctx, keysToCleanup[0]).Int()
	require.NoError(t, err)
	assert.Equal(t, 1, requestCount)
	assert.Equal(t, int64(1), redisClient.SCard(ctx, keysToCleanup[1]).Val())
	assert.Equal(t, int64(1), redisClient.SCard(ctx, keysToCleanup[2]).Val())
	assert.Equal(t, int64(1), redisClient.SCard(ctx, keysToCleanup[3]).Val())
	assert.Equal(t, int64(1), redisClient.SCard(ctx, keysToCleanup[4]).Val())
	assert.Equal(t, int64(1), redisClient.SCard(ctx, keysToCleanup[6]).Val())
	assert.Equal(t, int64(1), redisClient.SCard(ctx, keysToCleanup[7]).Val())
	assert.Equal(t, int64(0), redisClient.SCard(ctx, keysToCleanup[8]).Val())

	w = httptest.NewRecorder()
	req, err = http.NewRequest("GET", validQuery+"&is_latest=false", nil)
	require.NoError(t, err)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
	requestCountAfterMissingDeviceID, err := redisClient.Get(ctx, keysToCleanup[0]).Int()
	require.NoError(t, err)
	assert.Equal(t, 1, requestCountAfterMissingDeviceID)

	w = httptest.NewRecorder()
	req, err = http.NewRequest("GET", validQuery, nil)
	require.NoError(t, err)
	req.Header.Set("X-Device-ID", "beacon-device-unknown-latest")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.False(t, redisClient.SIsMember(ctx, keysToCleanup[7], "beacon-device-unknown-latest").Val())
	assert.False(t, redisClient.SIsMember(ctx, keysToCleanup[8], "beacon-device-unknown-latest").Val())

	noVersionQuery := fmt.Sprintf(
		"/telemetry/beacon?owner=%s&app_name=%s&channel=%s&platform=%s&arch=%s",
		url.QueryEscape(owner),
		url.QueryEscape(appName),
		url.QueryEscape(channel),
		url.QueryEscape(platform),
		url.QueryEscape(arch),
	)

	w = httptest.NewRecorder()
	req, err = http.NewRequest("GET", noVersionQuery+"&is_latest=false", nil)
	require.NoError(t, err)
	req.Header.Set("X-Device-ID", "beacon-device-outdated-no-version")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.False(t, redisClient.SIsMember(ctx, keysToCleanup[6], "beacon-device-outdated-no-version").Val())
	assert.True(t, redisClient.SIsMember(ctx, keysToCleanup[8], "beacon-device-outdated-no-version").Val())

	w = httptest.NewRecorder()
	req, err = http.NewRequest("GET", strings.Replace(validQuery, "arch=arm64", "arch=x64", 1)+"&is_latest=false", nil)
	require.NoError(t, err)
	req.Header.Set("X-Device-ID", "beacon-device-invalid")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)

	requestCountAfterInvalid, err := redisClient.Get(ctx, keysToCleanup[0]).Int()
	require.NoError(t, err)
	assert.Equal(t, 3, requestCountAfterInvalid)
	assert.False(t, redisClient.SIsMember(ctx, keysToCleanup[8], "beacon-device-invalid").Val())
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
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status %d; got %d", http.StatusNotFound, w.Code)
	}

	// Parse the JSON response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"error":"app not found"}`
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

func TestListReportKeysTeamUserPermissionDenied(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/report-keys/list", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.ListReportKeys(c)
	})

	req, err := http.NewRequest("GET", "/report-keys/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	router.ServeHTTP(w, req)
	logrus.Infoln("w.Body.String()", w.Body.String())
	assert.Equal(t, http.StatusForbidden, w.Code)
	expected := `{"error":"Permission denied"}`
	assert.Equal(t, expected, w.Body.String())
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
		Reports    bool   `json:"Reports"`
		Tuf        bool   `json:"Tuf"`
	}
	type AppResponse struct {
		Apps []AppInfo `json:"apps"`
	}

	expected := []AppInfo{
		{
			AppName: "testapp",
			Reports: true,
			Tuf:     true,
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
		assert.Equal(t, expectedApp.Reports, actual.Apps[i].Reports)
		assert.Equal(t, expectedApp.Tuf, actual.Apps[i].Tuf)
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
func TestFailedRegenerateReportKeyWithTeamUser(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/report-keys/regenerate", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.RegenerateReportKey(c)
	})

	payload := `{"app_id": "` + idTestappApp + `"}`
	req, err := http.NewRequest("POST", "/report-keys/regenerate", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "Permission denied", response["error"].(string))
}

// ---------------------------------------------------------------------------
// Report ingestion / aggregation / storage integration helpers and tests.
// These run against the real Mongo, Redis and object storage configured for
// the suite. Every test isolates itself by using a unique event.reason (and
// therefore a unique groupHash), so assertions never depend on global counts.
// ---------------------------------------------------------------------------

const (
	rpVersion  = "1.0.0"
	rpChannel  = "stable"
	rpPlatform = "linux"
	rpArch     = "amd64"
	rpType     = "crash"
)

func reportAppName(t *testing.T, appIDHex string) string {
	oid, err := primitive.ObjectIDFromHex(appIDHex)
	require.NoError(t, err)
	var doc struct {
		AppName string `bson:"app_name"`
	}
	err = mongoDatabase.Collection("apps_meta").FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&doc)
	require.NoError(t, err)
	return doc.AppName
}

func reportKeyForApp(t *testing.T, appIDHex string) string {
	oid, err := primitive.ObjectIDFromHex(appIDHex)
	require.NoError(t, err)
	var doc struct {
		KeyValue string `bson:"key_value"`
	}
	err = mongoDatabase.Collection("report_keys").FindOne(context.TODO(), bson.M{"app_id": oid}).Decode(&doc)
	require.NoError(t, err)
	return doc.KeyValue
}

func computeReportGroupHash(name, version, channel, platform, arch, etype, reason string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{name, version, channel, platform, arch, etype, reason}, "|")))
	return hex.EncodeToString(sum[:])
}

func reportBody(name, version, channel, platform, arch, etype, reason string) string {
	return fmt.Sprintf(
		`{"application":{"name":"%s","version":"%s","channel":"%s"},"system":{"platform":"%s","arch":"%s"},"event":{"type":"%s","reason":"%s"}}`,
		name, version, channel, platform, arch, etype, reason,
	)
}

func reportBodyWithDetails(name, reason, encoding, contentType, payload string) string {
	return fmt.Sprintf(
		`{"application":{"name":"%s","version":"%s","channel":"%s"},"system":{"platform":"%s","arch":"%s"},"event":{"type":"%s","reason":"%s"},"details":{"encoding":"%s","content_type":"%s","payload":"%s"}}`,
		name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason, encoding, contentType, payload,
	)
}

func gzipBase64(t *testing.T, data []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func serveReportIngest(authHeader, deviceID, body string) *httptest.ResponseRecorder {
	router := gin.Default()
	h := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/reports/ingest", func(c *gin.Context) { h.IngestReport(c) })

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/reports/ingest", bytes.NewBufferString(body))
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if deviceID != "" {
		req.Header.Set("X-Device-ID", deviceID)
	}
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	return w
}

func ingestWithKey(key, deviceID, body string) *httptest.ResponseRecorder {
	return serveReportIngest("Bearer "+key, deviceID, body)
}

func getReportGroupDoc(t *testing.T, appIDHex, hash string) *model.ReportGroup {
	oid, err := primitive.ObjectIDFromHex(appIDHex)
	require.NoError(t, err)
	var g model.ReportGroup
	err = mongoDatabase.Collection("report_groups").FindOne(context.TODO(), bson.M{"app_id": oid, "groupHash": hash}).Decode(&g)
	if err == mongo.ErrNoDocuments {
		return nil
	}
	require.NoError(t, err)
	return &g
}

func countReportBlobDocs(t *testing.T, appIDHex, hash string) int64 {
	oid, err := primitive.ObjectIDFromHex(appIDHex)
	require.NoError(t, err)
	n, err := mongoDatabase.Collection("report_blobs").CountDocuments(context.TODO(), bson.M{"app_id": oid, "groupHash": hash})
	require.NoError(t, err)
	return n
}

// flushReportRateLimits clears only the report rate-limit counters so a test's
// fixed-window buckets start clean, without disturbing other Redis state.
func flushReportRateLimits(t *testing.T) {
	if redisClient == nil {
		return
	}
	keys, err := redisClient.Keys(context.TODO(), "reports:rl:*").Result()
	require.NoError(t, err)
	if len(keys) > 0 {
		require.NoError(t, redisClient.Del(context.TODO(), keys...).Err())
	}
}

// cleanupReportApp removes a test-created app and all of its report artifacts so
// later legacy tests (e.g. the "no report keys remain" assertion) are unaffected.
func cleanupReportApp(appIDHex string) {
	oid, err := primitive.ObjectIDFromHex(appIDHex)
	if err != nil {
		return
	}
	ctx := context.TODO()
	mongoDatabase.Collection("report_keys").DeleteMany(ctx, bson.M{"app_id": oid})
	mongoDatabase.Collection("report_groups").DeleteMany(ctx, bson.M{"app_id": oid})
	mongoDatabase.Collection("report_blobs").DeleteMany(ctx, bson.M{"app_id": oid})
	mongoDatabase.Collection("apps_meta").DeleteOne(ctx, bson.M{"_id": oid})
}

func createReportEnabledApp(t *testing.T, token, name string) string {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	h := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/app/create", utils.CheckPermission(utils.PermissionCreate, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		h.CreateApp(c)
	})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	dataPart, err := writer.CreateFormField("data")
	require.NoError(t, err)
	_, err = dataPart.Write([]byte(fmt.Sprintf(`{"app": "%s", "reports": "true"}`, name)))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req, _ := http.NewRequest("POST", "/app/create", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	id, ok := resp["createAppResult.Created"]
	require.True(t, ok, w.Body.String())
	appID := id.(string)
	t.Cleanup(func() { cleanupReportApp(appID) })
	return appID
}

func TestReportIngestAuth(t *testing.T) {
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	body := reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, "auth_probe")

	t.Run("missing header", func(t *testing.T) {
		w := serveReportIngest("", "dev-auth-1", body)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
	t.Run("non-bearer scheme", func(t *testing.T) {
		w := serveReportIngest("Basic "+key, "dev-auth-2", body)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
	t.Run("unknown key", func(t *testing.T) {
		w := ingestWithKey(utils.ReportKeyPrefix+strings.Repeat("0", 64), "dev-auth-3", body)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestReportIngestMissingDeviceID(t *testing.T) {
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	body := reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, "no_device")
	w := ingestWithKey(key, "", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReportIngestAppNameMismatch(t *testing.T) {
	key := reportKeyForApp(t, idTestappApp)
	// Valid app name that is not the key's application -> 403.
	body := reportBody("someotherapp", rpVersion, rpChannel, rpPlatform, rpArch, rpType, "mismatch")
	w := ingestWithKey(key, "dev-mismatch", body)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestReportIngestMalformedJSON(t *testing.T) {
	key := reportKeyForApp(t, idTestappApp)
	w := ingestWithKey(key, "dev-malformed", `{"application":`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReportIngestMissingRequiredFields(t *testing.T) {
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)

	full := map[string]string{
		"application.name":    name,
		"application.version": rpVersion,
		"application.channel": rpChannel,
		"system.platform":     rpPlatform,
		"system.arch":         rpArch,
		"event.type":          rpType,
		"event.reason":        "missing_fields",
	}

	for _, drop := range []string{
		"application.name", "application.version", "application.channel",
		"system.platform", "system.arch", "event.type", "event.reason",
	} {
		t.Run("missing "+drop, func(t *testing.T) {
			f := make(map[string]string, len(full))
			for k, v := range full {
				if k == drop {
					continue
				}
				f[k] = v
			}
			body := fmt.Sprintf(
				`{"application":{"name":"%s","version":"%s","channel":"%s"},"system":{"platform":"%s","arch":"%s"},"event":{"type":"%s","reason":"%s"}}`,
				f["application.name"], f["application.version"], f["application.channel"],
				f["system.platform"], f["system.arch"], f["event.type"], f["event.reason"],
			)
			w := ingestWithKey(key, "dev-missing-"+drop, body)
			assert.Equal(t, http.StatusBadRequest, w.Code, "dropping %s must be rejected", drop)
		})
	}
}

func TestReportIngestInvalidEventType(t *testing.T) {
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	body := reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, "explosion", "bad_type")
	w := ingestWithKey(key, "dev-badtype", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReportIngestInvalidEventReason(t *testing.T) {
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	for _, reason := range []string{"has space", "pipe|char", strings.Repeat("a", 129)} {
		body := reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)
		w := ingestWithKey(key, "dev-badreason", body)
		assert.Equalf(t, http.StatusBadRequest, w.Code, "reason %q must be rejected", reason)
	}
}

func TestReportIngestBodyTooLarge(t *testing.T) {
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)

	prev := viper.Get("REPORTS_MAX_BODY_BYTES")
	viper.Set("REPORTS_MAX_BODY_BYTES", 16)
	defer viper.Set("REPORTS_MAX_BODY_BYTES", prev)

	body := reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, "too_large")
	w := ingestWithKey(key, "dev-toolarge", body)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestReportIngestAggregation(t *testing.T) {
	flushReportRateLimits(t)
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	reason := "aggregation_count"
	hash := computeReportGroupHash(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)
	body := reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)

	const n = 3
	var firstSeen primitive.DateTime
	for i := 0; i < n; i++ {
		// Distinct device id each time to dodge the per-device+group hourly limit.
		w := ingestWithKey(key, fmt.Sprintf("dev-agg-%d", i), body)
		require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
		if i == 0 {
			firstSeen = getReportGroupDoc(t, idTestappApp, hash).Stats.FirstSeen
		}
		time.Sleep(5 * time.Millisecond)
	}

	g := getReportGroupDoc(t, idTestappApp, hash)
	require.NotNil(t, g)
	assert.Equal(t, int64(n), g.Stats.Count)
	assert.Equal(t, firstSeen, g.Stats.FirstSeen, "firstSeen must stay fixed")
	// Millisecond precision: lastSeen never moves backwards as the group accumulates.
	assert.GreaterOrEqual(t, int64(g.Stats.LastSeen), int64(firstSeen), "lastSeen must advance")
}

func TestReportIngestDistinctReasonDistinctGroup(t *testing.T) {
	flushReportRateLimits(t)
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)

	h1 := computeReportGroupHash(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, "distinct_a")
	h2 := computeReportGroupHash(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, "distinct_b")
	require.NotEqual(t, h1, h2)

	w1 := ingestWithKey(key, "dev-distinct-1", reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, "distinct_a"))
	w2 := ingestWithKey(key, "dev-distinct-2", reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, "distinct_b"))
	require.Equal(t, http.StatusAccepted, w1.Code)
	require.Equal(t, http.StatusAccepted, w2.Code)

	assert.NotNil(t, getReportGroupDoc(t, idTestappApp, h1))
	assert.NotNil(t, getReportGroupDoc(t, idTestappApp, h2))
}

func TestReportIngestTenantIsolation(t *testing.T) {
	flushReportRateLimits(t)
	appID1 := createReportEnabledApp(t, authToken, "test")
	appID2 := createReportEnabledApp(t, authTokenSecondUser, "test")
	require.NotEqual(t, appID1, appID2)

	key1 := reportKeyForApp(t, appID1)
	key2 := reportKeyForApp(t, appID2)

	reason := "tenant_isolation"
	// Identical dimensions (same app name "test") -> identical groupHash...
	hash := computeReportGroupHash("test", rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)
	body := reportBody("test", rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)

	require.Equal(t, http.StatusAccepted, ingestWithKey(key1, "dev-tenant-1", body).Code)
	require.Equal(t, http.StatusAccepted, ingestWithKey(key2, "dev-tenant-2", body).Code)

	// ...but two separate report_groups docs, scoped by app_id, counts never merge.
	g1 := getReportGroupDoc(t, appID1, hash)
	g2 := getReportGroupDoc(t, appID2, hash)
	require.NotNil(t, g1)
	require.NotNil(t, g2)
	assert.NotEqual(t, g1.AppID, g2.AppID)
	assert.Equal(t, int64(1), g1.Stats.Count)
	assert.Equal(t, int64(1), g2.Stats.Count)
	assert.NotEqual(t, g1.Owner, g2.Owner)
}

func TestReportRateLimitPerDevice(t *testing.T) {
	if redisClient == nil {
		t.Skip("rate limiting requires Redis (ENABLE_TELEMETRY)")
	}
	flushReportRateLimits(t)
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	reason := "rl_per_device"
	hash := computeReportGroupHash(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)
	body := reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)

	w1 := ingestWithKey(key, "dev-rl-same", body)
	require.Equal(t, http.StatusAccepted, w1.Code)
	w2 := ingestWithKey(key, "dev-rl-same", body)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)

	// The base count from the first (accepted) request is still present.
	g := getReportGroupDoc(t, idTestappApp, hash)
	require.NotNil(t, g)
	assert.Equal(t, int64(1), g.Stats.Count)
}

func TestReportRateLimitDifferentReasonSameDevice(t *testing.T) {
	if redisClient == nil {
		t.Skip("rate limiting requires Redis (ENABLE_TELEMETRY)")
	}
	flushReportRateLimits(t)
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)

	w1 := ingestWithKey(key, "dev-rl-multi", reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, "rl_reason_a"))
	w2 := ingestWithKey(key, "dev-rl-multi", reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, "rl_reason_b"))
	assert.Equal(t, http.StatusAccepted, w1.Code)
	assert.Equal(t, http.StatusAccepted, w2.Code, "different group must not share the per-device limit")
}

func TestReportRateLimitPerGroup(t *testing.T) {
	if redisClient == nil {
		t.Skip("rate limiting requires Redis (ENABLE_TELEMETRY)")
	}
	flushReportRateLimits(t)
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	reason := "rl_per_group"
	body := reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)

	// 30/min per group; distinct devices so only the per-group window trips.
	accepted, limited := 0, 0
	for i := 0; i < 31; i++ {
		w := ingestWithKey(key, fmt.Sprintf("dev-rlgrp-%d", i), body)
		switch w.Code {
		case http.StatusAccepted:
			accepted++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
		}
	}
	assert.Equal(t, 30, accepted)
	assert.Equal(t, 1, limited)
}

func TestReportRateLimitPerKey(t *testing.T) {
	if redisClient == nil {
		t.Skip("rate limiting requires Redis (ENABLE_TELEMETRY)")
	}
	flushReportRateLimits(t)
	prev := viper.Get("REPORTS_RATE_LIMIT_PER_KEY_PER_MINUTE")
	viper.Set("REPORTS_RATE_LIMIT_PER_KEY_PER_MINUTE", 2)
	defer viper.Set("REPORTS_RATE_LIMIT_PER_KEY_PER_MINUTE", prev)

	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)

	// Distinct devices and groups so only the per-key window can trip.
	codes := []int{}
	for i := 0; i < 3; i++ {
		body := reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, fmt.Sprintf("rl_key_%d", i))
		w := ingestWithKey(key, fmt.Sprintf("dev-rlkey-%d", i), body)
		codes = append(codes, w.Code)
	}
	assert.Equal(t, http.StatusAccepted, codes[0])
	assert.Equal(t, http.StatusAccepted, codes[1])
	assert.Equal(t, http.StatusTooManyRequests, codes[2])
}

func TestReportDetailsStored(t *testing.T) {
	flushReportRateLimits(t)
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	reason := "details_stored"
	hash := computeReportGroupHash(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)

	raw := []byte(`{"message":"expected sha256 != actual sha256","stack":"a\nb\nc"}`)
	payload := gzipBase64(t, raw)
	body := reportBodyWithDetails(name, reason, "gzip+base64", "application/json", payload)

	w := ingestWithKey(key, "dev-details-stored", body)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())

	var resp model.ReportIngestResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.StoredDetails)
	assert.Equal(t, hash, resp.GroupHash)

	g := getReportGroupDoc(t, idTestappApp, hash)
	require.NotNil(t, g)
	assert.Equal(t, int64(1), g.Stats.DetailsStored)

	oid, _ := primitive.ObjectIDFromHex(idTestappApp)
	var blob model.ReportBlob
	require.NoError(t, mongoDatabase.Collection("report_blobs").FindOne(context.TODO(), bson.M{"app_id": oid, "groupHash": hash}).Decode(&blob))

	bucket := viper.GetString("S3_BUCKET_NAME_PRIVATE")
	assert.Equal(t, bucket, blob.Storage.Bucket, "details must land in the private bucket")
	assert.Equal(t, "gzip", blob.Storage.Encoding)
	assert.Equal(t, int64(len(raw)), blob.Storage.DecompressedSize)

	// expiresAt ~= createdAt + REPORTS_BLOB_RETENTION_DAYS.
	retention := viper.GetInt("REPORTS_BLOB_RETENTION_DAYS")
	if retention <= 0 {
		retention = 30
	}
	delta := blob.ExpiresAt.Time().Sub(blob.CreatedAt.Time())
	assert.InDelta(t, float64(retention), delta.Hours()/24, 1.0)

	// The stored object holds the compressed bytes: download and decompress.
	storageClient, err := utils.NewStorageFactory(viper.GetViper()).CreateStorageClient()
	require.NoError(t, err)
	tmp := filepath.Join(t.TempDir(), "blob.json.gz")
	require.NoError(t, storageClient.DownloadObject(context.TODO(), bucket, blob.Storage.Key, tmp))
	f, err := os.Open(tmp)
	require.NoError(t, err)
	defer f.Close()
	zr, err := gzip.NewReader(f)
	require.NoError(t, err)
	got, err := io.ReadAll(zr)
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}

func TestReportDetailsUnsupportedEncoding(t *testing.T) {
	flushReportRateLimits(t)
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	reason := "details_bad_encoding"
	hash := computeReportGroupHash(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)

	payload := gzipBase64(t, []byte(`{}`))
	body := reportBodyWithDetails(name, reason, "zstd", "application/json", payload)
	w := ingestWithKey(key, "dev-details-enc", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	g := getReportGroupDoc(t, idTestappApp, hash)
	require.NotNil(t, g, "base count must be incremented even when details are rejected")
	assert.Equal(t, int64(1), g.Stats.Count)
	assert.Equal(t, int64(1), g.Stats.DetailsRejected)
	assert.Equal(t, int64(0), g.Stats.DetailsStored)
}

func TestReportDetailsCompressedTooLarge(t *testing.T) {
	flushReportRateLimits(t)
	prev := viper.Get("REPORTS_MAX_DETAILS_COMPRESSED_BYTES")
	viper.Set("REPORTS_MAX_DETAILS_COMPRESSED_BYTES", 16)
	defer viper.Set("REPORTS_MAX_DETAILS_COMPRESSED_BYTES", prev)

	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	reason := "details_compressed_big"
	hash := computeReportGroupHash(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)

	payload := gzipBase64(t, bytes.Repeat([]byte("abcdefgh"), 256))
	body := reportBodyWithDetails(name, reason, "gzip+base64", "application/json", payload)
	w := ingestWithKey(key, "dev-details-comp", body)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)

	g := getReportGroupDoc(t, idTestappApp, hash)
	require.NotNil(t, g)
	assert.Equal(t, int64(1), g.Stats.Count)
	assert.Equal(t, int64(1), g.Stats.DetailsRejected)
}

func TestReportDetailsZipBomb(t *testing.T) {
	flushReportRateLimits(t)
	prev := viper.Get("REPORTS_MAX_DETAILS_DECOMPRESSED_BYTES")
	viper.Set("REPORTS_MAX_DETAILS_DECOMPRESSED_BYTES", 1000)
	defer viper.Set("REPORTS_MAX_DETAILS_DECOMPRESSED_BYTES", prev)

	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	reason := "details_zip_bomb"
	hash := computeReportGroupHash(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)

	// Small compressed, large decompressed.
	payload := gzipBase64(t, bytes.Repeat([]byte("a"), 200000))
	body := reportBodyWithDetails(name, reason, "gzip+base64", "application/json", payload)
	w := ingestWithKey(key, "dev-details-bomb", body)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)

	g := getReportGroupDoc(t, idTestappApp, hash)
	require.NotNil(t, g)
	assert.Equal(t, int64(1), g.Stats.Count, "base count preserved")
	assert.Equal(t, int64(1), g.Stats.DetailsRejected)
}

func TestReportBlobRetention(t *testing.T) {
	flushReportRateLimits(t)
	prev := viper.Get("REPORTS_MAX_BLOBS_PER_GROUP")
	viper.Set("REPORTS_MAX_BLOBS_PER_GROUP", 2)
	defer viper.Set("REPORTS_MAX_BLOBS_PER_GROUP", prev)

	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	reason := "blob_retention"
	hash := computeReportGroupHash(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)

	for i := 0; i < 4; i++ {
		payload := gzipBase64(t, []byte(fmt.Sprintf(`{"n":%d}`, i)))
		body := reportBodyWithDetails(name, reason, "gzip+base64", "application/json", payload)
		w := ingestWithKey(key, fmt.Sprintf("dev-retention-%d", i), body)
		require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
		time.Sleep(5 * time.Millisecond)
	}

	assert.Equal(t, int64(2), countReportBlobDocs(t, idTestappApp, hash), "only the 2 newest blobs are retained")
}

func setAppReports(t *testing.T, token, appIDHex, appName string, enabled bool) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	h := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/app/update", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		h.UpdateApp(c)
	})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	dataPart, err := writer.CreateFormField("data")
	require.NoError(t, err)
	_, err = dataPart.Write([]byte(fmt.Sprintf(`{"id": "%s", "app": "%s", "reports": "%t"}`, appIDHex, appName, enabled)))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req, _ := http.NewRequest("POST", "/app/update", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestReportIngestDisablingReportsRevokesKey(t *testing.T) {
	flushReportRateLimits(t)
	appID := createReportEnabledApp(t, authToken, "lifecycleapp")
	key := reportKeyForApp(t, appID)
	body := reportBody("lifecycleapp", rpVersion, rpChannel, rpPlatform, rpArch, rpType, "lifecycle")

	// Key works while reports are enabled.
	require.Equal(t, http.StatusAccepted, ingestWithKey(key, "dev-lifecycle", body).Code)

	// Disabling reports deletes the report key (handler syncs the lifecycle).
	setAppReports(t, authToken, appID, "lifecycleapp", false)

	// The old key no longer resolves -> 401.
	w := ingestWithKey(key, "dev-lifecycle", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
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

// At this point the team user has apps.download and allowed_apps = [testapp, teamApp],
// so the read API becomes exercisable for both admin and a scoped team user.

func serveListReportGroups(token, rawQuery string) *httptest.ResponseRecorder {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	h := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/reports/groups", utils.CheckPermission(utils.PermissionDownload, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		h.ListReportGroups(c)
	})

	url := "/reports/groups"
	if rawQuery != "" {
		url += "?" + rawQuery
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func serveListReportBlobs(token, groupHash string) *httptest.ResponseRecorder {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	h := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/reports/groups/:groupHash/blobs", utils.CheckPermission(utils.PermissionDownload, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		h.ListReportGroupBlobs(c)
	})

	req, _ := http.NewRequest("GET", "/reports/groups/"+groupHash+"/blobs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestReportGroupsAdminScopingAndFilters(t *testing.T) {
	flushReportRateLimits(t)
	key := reportKeyForApp(t, idTestappApp)
	name := reportAppName(t, idTestappApp)
	reason := "admin_filter_unique"
	require.Equal(t, http.StatusAccepted, ingestWithKey(key, "dev-adminfilter", reportBody(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)).Code)

	w := serveListReportGroups(authToken, "app="+name+"&reason="+reason+"&type="+rpType+"&page=1&limit=5")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp model.PaginatedReportGroups
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(1), resp.Total, "unique reason filter must narrow to exactly one group")
	assert.Equal(t, int64(1), resp.Page)
	assert.Equal(t, int64(5), resp.Limit)
	require.Len(t, resp.Items, 1)
	assert.Equal(t, reason, resp.Items[0].Event.Reason)
	assert.NotContains(t, w.Body.String(), `"owner"`, "owner must not be serialized")
}

func TestReportGroupsTeamUserAllowedAndDenied(t *testing.T) {
	flushReportRateLimits(t)

	// Allowed: a group under testapp (admin owner, in the team user's allowed_apps).
	testappKey := reportKeyForApp(t, idTestappApp)
	testappName := reportAppName(t, idTestappApp)
	allowedReason := "team_allowed"
	require.Equal(t, http.StatusAccepted, ingestWithKey(testappKey, "dev-team-allowed", reportBody(testappName, rpVersion, rpChannel, rpPlatform, rpArch, rpType, allowedReason)).Code)

	// Denied: a group under "public testapp" (same owner, NOT in allowed_apps).
	publicKey := reportKeyForApp(t, idPublicTestappApp)
	publicName := reportAppName(t, idPublicTestappApp)
	deniedReason := "team_denied"
	require.Equal(t, http.StatusAccepted, ingestWithKey(publicKey, "dev-team-denied", reportBody(publicName, rpVersion, rpChannel, rpPlatform, rpArch, rpType, deniedReason)).Code)

	wAllowed := serveListReportGroups(teamUserToken, "reason="+allowedReason)
	require.Equal(t, http.StatusOK, wAllowed.Code, wAllowed.Body.String())
	var allowed model.PaginatedReportGroups
	require.NoError(t, json.Unmarshal(wAllowed.Body.Bytes(), &allowed))
	assert.Equal(t, int64(1), allowed.Total, "team user must see groups of an allowed app")

	wDenied := serveListReportGroups(teamUserToken, "reason="+deniedReason)
	require.Equal(t, http.StatusOK, wDenied.Code, wDenied.Body.String())
	var denied model.PaginatedReportGroups
	require.NoError(t, json.Unmarshal(wDenied.Body.Bytes(), &denied))
	assert.Equal(t, int64(0), denied.Total, "team user must not see groups of a non-allowed app")
}

func TestReportGroupBlobsPresigned(t *testing.T) {
	// Reuses the blob stored by TestReportDetailsStored.
	name := reportAppName(t, idTestappApp)
	hash := computeReportGroupHash(name, rpVersion, rpChannel, rpPlatform, rpArch, rpType, "details_stored")

	w := serveListReportBlobs(authToken, hash)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		Items []map[string]interface{} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.GreaterOrEqual(t, len(resp.Items), 1)

	item := resp.Items[0]
	url, _ := item["url"].(string)
	assert.True(t, strings.HasPrefix(url, "http"), "presigned url must be resolvable, got %q", url)

	_, hasOwner := item["owner"]
	assert.False(t, hasOwner, "owner must be absent from blob JSON")
	storage, _ := item["storage"].(map[string]interface{})
	require.NotNil(t, storage)
	_, hasBucket := storage["bucket"]
	assert.False(t, hasBucket, "storage.bucket must be absent from blob JSON")
}

func TestReportGroupBlobsCrossOwnerEmpty(t *testing.T) {
	flushReportRateLimits(t)

	// Second owner stores a blob under an app the admin does not own.
	appID := createReportEnabledApp(t, authTokenSecondUser, "owner2reports")
	key := reportKeyForApp(t, appID)
	reason := "cross_owner_blob"
	hash := computeReportGroupHash("owner2reports", rpVersion, rpChannel, rpPlatform, rpArch, rpType, reason)

	payload := gzipBase64(t, []byte(`{"secret":"owner2"}`))
	body := reportBodyWithDetails("owner2reports", reason, "gzip+base64", "application/json", payload)
	require.Equal(t, http.StatusAccepted, ingestWithKey(key, "dev-cross-owner", body).Code)
	require.Equal(t, int64(1), countReportBlobDocs(t, appID, hash))

	// Admin requests the same hash -> no cross-owner leak.
	w := serveListReportBlobs(authToken, hash)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Items []map[string]interface{} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Empty(t, resp.Items)
}

func TestReportGroupBlobsInvalidHash(t *testing.T) {
	for _, bad := range []string{"nothexvalue", strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		w := serveListReportBlobs(authToken, bad)
		assert.Equalf(t, http.StatusBadRequest, w.Code, "hash %q must be rejected", bad)
	}
}

func TestRegenerateReportKeyTeamUser(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.POST("/report-keys/regenerate", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.RegenerateReportKey(c)
	})

	payload := `{"app_id": "` + idTestappApp + `"}`
	req, err := http.NewRequest("POST", "/report-keys/regenerate", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, idTestappApp, response["app_id"])
	assert.NotEqual(t, keyValueReportKeyTestapp, response["key_value"].(string))
	assert.True(t, strings.HasPrefix(response["key_value"].(string), utils.ReportKeyPrefix))
	assert.Len(t, response["key_value"].(string), len(utils.ReportKeyPrefix)+64)
	// keyValueReportKeyTestapp = response["key_value"].(string)
}

func TestListReportKeysAdminUserBeforeTeamUser(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/report-keys/list", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.ListReportKeys(c)
	})

	req, err := http.NewRequest("GET", "/report-keys/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	type ReportKeyResponse struct {
		ReportKeys []model.ReportKeyListItem `json:"report_keys"`
	}
	var actual ReportKeyResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}
	if !assert.Len(t, actual.ReportKeys, 2) {
		t.Fatal("Expected 2 report keys")
	}
	for _, item := range actual.ReportKeys {
		assert.Contains(t, []string{"testapp", "public testapp"}, item.AppName)
		assert.True(t, strings.HasPrefix(item.KeyValue, utils.ReportKeyPrefix))
		assert.Len(t, item.KeyValue, len(utils.ReportKeyPrefix)+64)
	}
}

func TestListReportKeysTeamUser(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/report-keys/list", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.ListReportKeys(c)
	})

	req, err := http.NewRequest("GET", "/report-keys/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+teamUserToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	type ReportKeyResponse struct {
		ReportKeys []model.ReportKeyListItem `json:"report_keys"`
	}
	var actual ReportKeyResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}
	if !assert.Len(t, actual.ReportKeys, 1) {
		return
	}
	item := actual.ReportKeys[0]
	assert.Equal(t, "testapp", item.AppName)
	assert.True(t, strings.HasPrefix(item.KeyValue, utils.ReportKeyPrefix))
	assert.Len(t, item.KeyValue, len(utils.ReportKeyPrefix)+64)
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
	server := httptest.NewServer(router)
	defer server.Close()

	sdkClient := faynosync.NewClient(faynosync.Config{
		BaseURL: server.URL,
	})

	decodeScenarioValue := func(raw string) string {
		decoded, err := url.QueryUnescape(raw)
		if err != nil {
			return raw
		}
		return decoded
	}
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
				"update_available":  false,
				"critical":          false,
				"possible_rollback": false,
				"update_url_dmg":    fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.10.138.dmg"),
				"update_url_pkg":    fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.10.138.pkg"),
				"update_url":        fmt.Sprintf("%s/%s%s", apiUrl, "download?key=", "newApp-admin%2Fnightly%2FsecondPlatform%2FsecondArch%2FnewApp-0.0.10.138"),
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
			sdkResp, err := sdkClient.CheckForUpdates(
				context.Background(),
				faynosync.CheckOptions{
					Owner:    decodeScenarioValue(scenario.Owner),
					AppName:  decodeScenarioValue(scenario.AppName),
					Version:  decodeScenarioValue(scenario.Version),
					Channel:  decodeScenarioValue(scenario.ChannelName),
					Platform: decodeScenarioValue(scenario.Platform),
					Arch:     decodeScenarioValue(scenario.Arch),
				},
			)
			require.NoError(t, err)
			assertSDKMatchesScenario(t, scenario.ExpectedJSON, sdkResp)
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

func TestDeletePlatformMacosTauri(t *testing.T) {

	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	// Define the route for the /platform/delete endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.DELETE("/platform/delete", func(c *gin.Context) {
		handler.DeletePlatform(c)
	})

	// Create a DELETE request for the /platform/delete endpoint.
	req, err := http.NewRequest("DELETE", "/platform/delete?id="+platformIdMacosTauri, nil)
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
	payload := fmt.Sprintf(`{"id": "%s", "app":"newApp", "tuf": "false", "reports": "false"}`, idTestappApp)
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

func TestListReportKeysNoValuesAfterUpdateAppReportsToFalse(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/report-keys/list", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.ListReportKeys(c)
	})

	req, err := http.NewRequest("GET", "/report-keys/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	type ReportKeyResponse struct {
		ReportKeys []model.ReportKeyListItem `json:"report_keys"`
	}
	var actual ReportKeyResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}
	if !assert.Len(t, actual.ReportKeys, 1) {
		return
	}
	item := actual.ReportKeys[0]
	assert.Equal(t, "public testapp", item.AppName)
	assert.True(t, strings.HasPrefix(item.KeyValue, utils.ReportKeyPrefix))
	assert.Len(t, item.KeyValue, len(utils.ReportKeyPrefix)+64)
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
		Reports    bool   `json:"Reports"`
		Tuf        bool   `json:"Tuf"`
		Updated_at string `json:"Updated_at"`
	}
	type AppResponse struct {
		Apps []AppInfo `json:"apps"`
	}

	expected := []AppInfo{
		{
			AppName: "newApp",
			Reports: false,
			Tuf:     false,
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
		assert.Equal(t, expectedApp.Reports, actual.Apps[i].Reports)
		assert.Equal(t, expectedApp.Tuf, actual.Apps[i].Tuf)
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
func TestListReportKeysNoValues(t *testing.T) {
	router := gin.Default()
	router.Use(utils.AuthMiddleware())
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase, redisClient, viper.GetBool("PERFORMANCE_MODE"))
	router.GET("/report-keys/list", utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, mongoDatabase), func(c *gin.Context) {
		handler.ListReportKeys(c)
	})

	req, err := http.NewRequest("GET", "/report-keys/list", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	type ReportKeyResponse struct {
		ReportKeys []model.ReportKeyListItem `json:"report_keys"`
	}
	var actual ReportKeyResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}
	if !assert.Len(t, actual.ReportKeys, 0) {
		t.Fatal("Expected 0 report keys")
	}
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
