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
	"testing"

	"faynoSync/mongod"
	db "faynoSync/mongod"
	"faynoSync/server/handler"
	"faynoSync/server/model"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

var (
	client        *mongo.Client
	appDB         db.AppRepository
	mongoDatabase *mongo.Database
	configDB      connstring.ConnString
	s3Endpoint    string
	apiKey        string
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
	client, configDB = mongod.ConnectToDatabase(viper.GetString("MONGODB_URL_TESTS"), flagMap)
	appDB = mongod.NewAppRepository(&configDB, client)
	mongoDatabase = client.Database(configDB.Database)
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
	log.Println("Successfully removed admin user.")
	client.Disconnect(context.Background())
	log.Println("MongoDB is disconnected.")
	removeFile("testapp.dmg")
	removeFile("testapp.pkg")
}

func TestHealthCheck(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
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

func TestSignUp(t *testing.T) {
	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.POST("/signup", func(c *gin.Context) {
		handler.SignUp(c)
	})

	payload := `{"username": "admin", "password": "password", "api_key": "UHp3aKb40fwpoKZluZByWQ"}`
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

var authToken string

func TestLogin(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
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

var uploadedFirstApp string

func TestUpload(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
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
	writer.Close()

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("POST", "/upload?app_name=testapp&version=0.0.1", body)
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
	// Check that the "token" key exists in the response.
	id, idExists := response["uploadResult.Uploaded"]
	assert.True(t, idExists)

	uploadedFirstApp = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, uploadedFirstApp)
}

func TestUploadDuplicateApp(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
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
	writer.Close()

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("POST", "/upload?app_name=testapp&version=0.0.1", body)
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
	expectedErrorMessage := `{"error":"app with this name, version, and extension already exists"}`
	assert.Equal(t, expectedErrorMessage, w.Body.String())
}

func TestDeleteApp(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.DELETE("/deleteApp", func(c *gin.Context) {
		handler.DeleteApp(c)
	})

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("DELETE", "/deleteApp?id="+uploadedFirstApp, nil)
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

func TestListChannels(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.GET("/listChannels", func(c *gin.Context) {
		handler.ListChannels(c)
	})

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("GET", "/listChannels", nil)
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

	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.POST("/createChannel", func(c *gin.Context) {
		handler.CreateChannel(c)
	})

	req, err := http.NewRequest("POST", "/createChannel?channel=nightly", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	// Check that the "token" key exists in the response.
	id, idExists := response["createChannelResult.Created"]
	assert.True(t, idExists)
	idNightlyChannel = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, idNightlyChannel)
}

func TestChannelCreateStable(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.POST("/createChannel", func(c *gin.Context) {
		handler.CreateChannel(c)
	})

	req, err := http.NewRequest("POST", "/createChannel?channel=stable", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	// Check that the "token" key exists in the response.
	id, idExists := response["createChannelResult.Created"]
	assert.True(t, idExists)
	idStableChannel = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, idStableChannel)
}

func TestUploadAppWithoutChannel(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
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
	writer.Close()

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("POST", "/upload?app_name=testapp&version=0.0.1", body)
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
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.GET("/listPlatforms", func(c *gin.Context) {
		handler.ListPlatforms(c)
	})

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("GET", "/listPlatforms", nil)
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
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.POST("/createPlatform", func(c *gin.Context) {
		handler.CreatePlatform(c)
	})

	req, err := http.NewRequest("POST", "/createPlatform?platform=universalPlatform", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	// Check that the "token" key exists in the response.
	id, idExists := response["createPlatformResult.Created"]
	assert.True(t, idExists)
	platformId = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, platformId)
}

func TestUploadAppWithoutPlatform(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
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
	writer.Close()

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("POST", "/upload?app_name=testapp&version=0.0.1&channel=nightly", body)
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
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.GET("/listArchs", func(c *gin.Context) {
		handler.ListArchs(c)
	})

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("GET", "/listArchs", nil)
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
	w := httptest.NewRecorder()

	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.POST("/createArch", func(c *gin.Context) {
		handler.CreateArch(c)
	})

	req, err := http.NewRequest("POST", "/createArch?arch=universalArch", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Serve the request using the Gin router.
	router.ServeHTTP(w, req)

	// Check the response status code.
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	// Check that the "token" key exists in the response.
	id, idExists := response["createArchResult.Created"]
	assert.True(t, idExists)
	archId = id.(string)
	assert.True(t, idExists)
	assert.NotEmpty(t, archId)
}

func TestUploadAppWithoutArch(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
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
	writer.Close()

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("POST", "/upload?app_name=testapp&version=0.0.1&channel=nightly&platform=universalPlatform", body)
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

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.POST("/upload", func(c *gin.Context) {
		handler.UploadApp(c)
	})

	// Create a file to upload (you can replace this with a test file path).
	filePaths := []string{"testapp.dmg", "testapp.pkg"}
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
			Platform    string
			Arch        string
		}{
			{"0.0.1", "nightly", true, "universalPlatform", "universalArch"},
			{"0.0.2", "nightly", true, "universalPlatform", "universalArch"},
			{"0.0.3", "nightly", false, "universalPlatform", "universalArch"},
			{"0.0.4", "stable", true, "universalPlatform", "universalArch"},
			{"0.0.5", "stable", false, "universalPlatform", "universalArch"},
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
			writer.Close()
			// Create a POST request for the upload endpoint with the current combination.
			req, err := http.NewRequest("POST", fmt.Sprintf("/upload?app_name=testapp&version=%s&channel=%s&publish=%v&platform=%s&arch=%s", combo.AppVersion, combo.ChannelName, combo.Published, combo.Platform, combo.Arch), body)
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

			// Check that the "token" key exists in the response.
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

func TestSearch(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.GET("/search", func(c *gin.Context) {
		handler.GetAppByName(c)
	})

	// Create a POST request for the upload endpoint.
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
		ID         string           `json:"ID"`
		AppName    string           `json:"AppName"`
		Version    string           `json:"Version"`
		Channel    string           `json:"Channel"`
		Published  bool             `json:"Published"`
		Artifacts  []model.Artifact `json:"Artifacts" bson:"artifacts"`
		Updated_at string           `json:"Updated_at"`
	}
	type AppResponse struct {
		Apps []AppInfo `json:"apps"`
	}

	expected := []AppInfo{
		{
			AppName:   "testapp",
			Version:   "0.0.1",
			Channel:   "nightly",
			Published: true,
			Artifacts: []model.Artifact{
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
			},
		},
		{
			AppName:   "testapp",
			Version:   "0.0.2",
			Channel:   "nightly",
			Published: true,
			Artifacts: []model.Artifact{
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
			},
		},
		{
			AppName:   "testapp",
			Version:   "0.0.3",
			Channel:   "nightly",
			Published: false,
			Artifacts: []model.Artifact{
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
			},
		},
		{
			AppName:   "testapp",
			Version:   "0.0.4",
			Channel:   "stable",
			Published: true,
			Artifacts: []model.Artifact{
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
			},
		},
		{
			AppName:   "testapp",
			Version:   "0.0.5",
			Channel:   "stable",
			Published: false,
			Artifacts: []model.Artifact{
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
			},
		},
	}

	var actual AppResponse
	err = json.Unmarshal(w.Body.Bytes(), &actual)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the relevant fields (AppName, Version, Channel) for each item in the response.
	for i, expectedApp := range expected {
		assert.Equal(t, expectedApp.AppName, actual.Apps[i].AppName)
		assert.Equal(t, expectedApp.Version, actual.Apps[i].Version)
		assert.Equal(t, expectedApp.Channel, actual.Apps[i].Channel)
		assert.Equal(t, expectedApp.Published, actual.Apps[i].Published)
		for j, expectedArtifact := range expectedApp.Artifacts {
			assert.Equal(t, expectedArtifact.Platform, actual.Apps[i].Artifacts[j].Platform)
			assert.Equal(t, expectedArtifact.Arch, actual.Apps[i].Artifacts[j].Arch)
			assert.Equal(t, expectedArtifact.Package, actual.Apps[i].Artifacts[j].Package)
		}
	}
}

func TestCheckVersion(t *testing.T) {
	router := gin.Default()
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
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
			Version:     "0.0.1",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"update_available": true,
				"update_url_dmg":   fmt.Sprintf("%s/testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.dmg", s3Endpoint),
				"update_url_pkg":   fmt.Sprintf("%s/testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.pkg", s3Endpoint),
			},
			ExpectedCode: http.StatusOK,
			Published:    false,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.2",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"update_available": false,
				"update_url_dmg":   fmt.Sprintf("%s/testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.dmg", s3Endpoint),
				"update_url_pkg":   fmt.Sprintf("%s/testapp/nightly/universalPlatform/universalArch/testapp-0.0.2.pkg", s3Endpoint),
			},
			ExpectedCode: http.StatusOK,
			Published:    true,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.3",
			ChannelName: "nightly",
			ExpectedJSON: map[string]interface{}{
				"error": "requested version 0.0.3 is newer than the latest version available",
			},
			ExpectedCode: http.StatusInternalServerError,
			Published:    false,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "NightlyUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.4",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"update_available": false,
				"update_url_dmg":   fmt.Sprintf("%s/testapp/stable/universalPlatform/universalArch/testapp-0.0.4.dmg", s3Endpoint),
				"update_url_pkg":   fmt.Sprintf("%s/testapp/stable/universalPlatform/universalArch/testapp-0.0.4.pkg", s3Endpoint),
			},
			ExpectedCode: http.StatusOK,
			Published:    true,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "StableUpdateAvailable",
		},
		{
			AppName:     "testapp",
			Version:     "0.0.5",
			ChannelName: "stable",
			ExpectedJSON: map[string]interface{}{
				"error": "requested version 0.0.5 is newer than the latest version available",
			},
			ExpectedCode: http.StatusInternalServerError,
			Published:    false,
			Platform:     "universalPlatform",
			Arch:         "universalArch",
			TestName:     "StableUpdateAvailable",
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.TestName, func(t *testing.T) {
			w := httptest.NewRecorder()

			// Create a GET request for checking the version.
			req, err := http.NewRequest("GET", fmt.Sprintf("/checkVersion?app_name=%s&version=%s&channel=%s&publish=%v&platform=%s&arch=%s", scenario.AppName, scenario.Version, scenario.ChannelName, scenario.Published, scenario.Platform, scenario.Arch), nil)
			if err != nil {
				t.Fatal(err)
			}

			// Set the Authorization header.
			req.Header.Set("Authorization", "Bearer "+authToken)
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

	// Define the route for the deleteApp endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.DELETE("/deleteApp", func(c *gin.Context) {
		handler.DeleteApp(c)
	})

	// Iterate over the uploadedAppIDs and send a DELETE request for each ID.
	for _, appID := range uploadedAppIDs {
		w := httptest.NewRecorder()

		req, err := http.NewRequest("DELETE", "/deleteApp?id="+appID, nil)
		if err != nil {
			t.Fatal(err)
		}

		// Set the Authorization header.
		req.Header.Set("Authorization", "Bearer "+authToken)
		// Serve the request using the Gin router.
		router.ServeHTTP(w, req)

		// Check the response status code for each request.
		assert.Equal(t, http.StatusOK, w.Code)

		expected := `{"deleteAppResult.DeletedCount":1}`
		assert.Equal(t, expected, w.Body.String())
	}
}

func TestListChannelsWhenExist(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.GET("/listChannels", func(c *gin.Context) {
		handler.ListChannels(c)
	})

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("GET", "/listChannels", nil)
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
			ChannelName: "stable",
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
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.DELETE("/deleteChannel", func(c *gin.Context) {
		handler.DeleteChannel(c)
	})

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("DELETE", "/deleteChannel?id="+idNightlyChannel, nil)
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
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.DELETE("/deleteChannel", func(c *gin.Context) {
		handler.DeleteChannel(c)
	})

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("DELETE", "/deleteChannel?id="+idStableChannel, nil)
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

func TestListPlatformsWhenExist(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.GET("/listPlatforms", func(c *gin.Context) {
		handler.ListPlatforms(c)
	})

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("GET", "/listPlatforms", nil)
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
			PlatformName: "universalPlatform",
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
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.DELETE("/deletePlatform", func(c *gin.Context) {
		handler.DeletePlatform(c)
	})

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("DELETE", "/deletePlatform?id="+platformId, nil)
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

func TestListArchsWhenExist(t *testing.T) {

	router := gin.Default()
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.GET("/listArchs", func(c *gin.Context) {
		handler.ListArchs(c)
	})

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("GET", "/listArchs", nil)
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
	type PlatformResponse struct {
		Archs []ArchInfo `json:"archs"`
	}

	expected := []ArchInfo{
		{
			ArchID: "universalArch",
		},
	}
	var actual PlatformResponse
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
	w := httptest.NewRecorder()

	// Define the route for the upload endpoint.
	handler := handler.NewAppHandler(client, appDB, mongoDatabase)
	router.DELETE("/deleteArch", func(c *gin.Context) {
		handler.DeleteArch(c)
	})

	// Create a POST request for the upload endpoint.
	req, err := http.NewRequest("DELETE", "/deleteArch?id="+archId, nil)
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
