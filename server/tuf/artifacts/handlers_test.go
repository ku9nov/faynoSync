package artifacts

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/tuf/tasks"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// === Notice ===

// For testing these handlers, I eventually decided to use a real MongoDB instance in unit tests, at least to some extent. I deliberately avoided mocking MongoDB values, because that would have introduced additional complexity and potential maintenance issues. At the same time, covering the entire TUF functionality with full integration tests would be overly complicated and heavy.

// As a compromise, I chose to use a real database specifically for tests.

// By default, simply running these tests will result in most of them being skipped. However, if a test database is available, the tests can be executed against it by setting the following environment variable:

// export MONGODB_URL_TESTS=mongodb://root:MheCk6sSKB1m4xKNw5I@localhost/cb_faynosync_db_tests?authSource=admin

// (This value is taken from .env.example.)

// After that, running:

// go test ./server/tuf/artifacts/... -v

// will execute the tests using the database.

// This approach may remain as is, may later be extended to other tests, or may be removed entirely and rewritten as proper integration tests. At the moment, this is an intentional intermediate solution, and the final direction has not been decided yet.

// === End of Notice ===

// To verify: Change request URL or method in PostPublishArtifacts; test will fail (wrong response).
func makePostPublishArtifactsContext(username string, payload interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var body *bytes.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		body = bytes.NewReader(raw)
		c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/artifacts/publish", body)
		c.Request.Header.Set("Content-Type", "application/json")
	} else {
		c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/artifacts/publish", nil)
	}
	if username != "" {
		c.Set("username", username)
	}
	return c, w
}

// To verify: Change request URL or method in PostDeleteArtifacts; test will fail (wrong response).
func makePostDeleteArtifactsContext(username string, payload interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var body *bytes.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		body = bytes.NewReader(raw)
		c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/artifacts/delete", body)
		c.Request.Header.Set("Content-Type", "application/json")
	} else {
		c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/artifacts/delete", nil)
	}
	if username != "" {
		c.Set("username", username)
	}
	return c, w
}

func waitForTaskTerminalState(t *testing.T, redisClient *redis.Client, taskID string, timeout time.Duration) {
	t.Helper()
	ctx := context.Background()
	taskKey := "task:" + taskID
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := redisClient.Get(ctx, taskKey).Result()
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		var status tasks.TaskStatus
		if err := json.Unmarshal([]byte(data), &status); err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if status.State == tasks.TaskStateSuccess || status.State == tasks.TaskStateFailure {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for task %s to reach terminal state", taskID)
}

// To verify: In PostPublishArtifacts remove GetUsernameFromContext check or return 200 on error; test will fail (wrong status).
func TestPostPublishArtifacts_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	c, w := makePostPublishArtifactsContext("", PublishArtifactsPayload{AppID: "507f1f77bcf86cd799439011", Version: "1.0.0"})
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostPublishArtifacts(c, redisClient, nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 when username is missing from context")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
	t.Logf("Inputs: username=empty; Result: code=%d, body=%v", w.Code, body)
}

// To verify: In PostPublishArtifacts change ShouldBindJSON error handling to return 200 or different message; test will fail.
func TestPostPublishArtifacts_InvalidPayload_ReturnsBadRequest(t *testing.T) {
	c, w := makePostPublishArtifactsContext("owner", nil)
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostPublishArtifacts(c, redisClient, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when payload is invalid or missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Invalid payload", "error message must mention invalid payload")
	t.Logf("Inputs: body=empty; Result: code=%d, body=%v", w.Code, body)
}

// To verify: In PostPublishArtifacts change missing app_id/version validation or ObjectIDFromHex error handling; test will fail.
func TestPostPublishArtifacts_MissingAppID_ReturnsBadRequest(t *testing.T) {
	c, w := makePostPublishArtifactsContext("owner", map[string]string{"version": "1.0.0"})
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostPublishArtifacts(c, redisClient, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.NotEmpty(t, body["error"])
	t.Logf("Inputs: app_id=missing; Result: code=%d", w.Code)
}

// To verify: In PostPublishArtifacts remove or change ObjectIDFromHex error handling for invalid app_id; test will fail (wrong status).
func TestPostPublishArtifacts_InvalidAppID_ReturnsBadRequest(t *testing.T) {
	c, w := makePostPublishArtifactsContext("owner", PublishArtifactsPayload{AppID: "not-a-hex-id", Version: "1.0.0"})
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostPublishArtifacts(c, redisClient, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when app_id is not a valid ObjectID hex")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Invalid app_id", "error message must mention invalid app_id")
	t.Logf("Inputs: app_id=not-a-hex-id; Result: code=%d, body=%v", w.Code, body)
}

// mongoTestDB connects to Mongo when MONGODB_URL_TESTS is set and returns the database; otherwise skips the test.
// Mongo is not mocked so tests that need it run against a real DB when available.
func mongoTestDB(t *testing.T) *mongo.Database {
	t.Helper()
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	flagMap := map[string]interface{}{"migration": false, "rollback": false}
	client, configDB := mongod.ConnectToDatabase(mongoURL, flagMap)
	t.Cleanup(func() {
		_ = client.Disconnect(context.Background())
	})
	return client.Database(configDB.Database)
}

// To verify: In PostPublishArtifacts change FindOne (apps) ErrNoDocuments handling to return 200 or different status; test will fail.
func TestPostPublishArtifacts_AppNotFound_ReturnsNotFound(t *testing.T) {
	db := mongoTestDB(t)
	appID := primitive.NewObjectID()
	c, w := makePostPublishArtifactsContext("owner", PublishArtifactsPayload{AppID: appID.Hex(), Version: "1.0.0"})
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	// No document inserted in apps -> FindOne returns ErrNoDocuments

	PostPublishArtifacts(c, redisClient, db)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when app version is not found")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "not found", "error message must mention not found")
	t.Logf("Inputs: app_id=%s, version=1.0.0; Result: code=%d", appID.Hex(), w.Code)
}

// To verify: In PostPublishArtifacts change apps_meta FindOne error handling to return 200 or different status; test will fail.
func TestPostPublishArtifacts_AppMetaNotFound_ReturnsInternalServerError(t *testing.T) {
	db := mongoTestDB(t)
	appID := primitive.NewObjectID()
	owner := "test-owner-meta-missing"
	ctx := context.Background()
	appsColl := db.Collection("apps")
	_, err := appsColl.InsertOne(ctx, bson.M{
		"app_id":  appID,
		"version": "1.0.0",
		"owner":   owner,
		"artifacts": []model.Artifact{
			{Link: "http://api.example.com/download?key=app%2Fv1%2Ffile.bin", Hashes: map[string]string{"sha256": "abc"}, Length: 100, TufSigned: false},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
	})
	// Do not insert apps_meta -> FindOne on apps_meta returns ErrNoDocuments

	c, w := makePostPublishArtifactsContext(owner, PublishArtifactsPayload{AppID: appID.Hex(), Version: "1.0.0"})
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	oldAPI := viper.GetViper().GetString("API_URL")
	viper.GetViper().Set("API_URL", "http://api.example.com")
	defer viper.GetViper().Set("API_URL", oldAPI)

	PostPublishArtifacts(c, redisClient, db)

	assert.Equal(t, http.StatusInternalServerError, w.Code, "Expected 500 when app metadata is not found")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Failed to find app metadata", body["error"])
	t.Logf("Inputs: app_id=%s, owner=%s; Result: code=%d", appID.Hex(), owner, w.Code)
}

// To verify: In PostPublishArtifacts change the condition len(tufArtifacts) == 0 or the error message; test will fail.
func TestPostPublishArtifacts_NoValidArtifactsAfterConversion_ReturnsBadRequest(t *testing.T) {
	db := mongoTestDB(t)
	appID := primitive.NewObjectID()
	owner := "test-owner-no-valid"
	ctx := context.Background()
	appsColl := db.Collection("apps")
	metaColl := db.Collection("apps_meta")
	// Artifact with no hashes so ConvertMongoArtifactToTUF fails
	_, err := appsColl.InsertOne(ctx, bson.M{
		"app_id":  appID,
		"version": "1.0.0",
		"owner":   owner,
		"artifacts": []model.Artifact{
			{Link: "http://api.example.com/download?key=app%2Fv1%2Ffile.bin", Hashes: nil, Length: 100, TufSigned: false},
		},
	})
	require.NoError(t, err)
	_, err = metaColl.InsertOne(ctx, bson.M{"_id": appID, "owner": owner, "app_name": "TestApp"})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = metaColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	oldAPI := viper.GetViper().GetString("API_URL")
	viper.GetViper().Set("API_URL", "http://api.example.com")
	defer viper.GetViper().Set("API_URL", oldAPI)

	c, w := makePostPublishArtifactsContext(owner, PublishArtifactsPayload{AppID: appID.Hex(), Version: "1.0.0"})
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostPublishArtifacts(c, redisClient, db)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when no artifacts convert successfully")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "No valid artifacts to publish", body["error"])
	t.Logf("Inputs: app with artifact (no hashes); Result: code=%d", w.Code)
}

// To verify: In PostPublishArtifacts change the condition len(unsignedArtifacts) == 0 or the response message; test will fail.
func TestPostPublishArtifacts_AllArtifactsAlreadySigned_ReturnsOK(t *testing.T) {
	db := mongoTestDB(t)
	appID := primitive.NewObjectID()
	owner := "test-owner-all-signed"
	ctx := context.Background()
	appsColl := db.Collection("apps")
	metaColl := db.Collection("apps_meta")
	_, err := appsColl.InsertOne(ctx, bson.M{
		"app_id":  appID,
		"version": "1.0.0",
		"owner":   owner,
		"artifacts": []model.Artifact{
			{Link: "http://api.example.com/download?key=app%2Fv1%2Ffile.bin", Hashes: map[string]string{"sha256": "abc"}, Length: 100, TufSigned: true},
		},
	})
	require.NoError(t, err)
	_, err = metaColl.InsertOne(ctx, bson.M{"_id": appID, "owner": owner, "app_name": "TestApp"})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = metaColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	c, w := makePostPublishArtifactsContext(owner, PublishArtifactsPayload{AppID: appID.Hex(), Version: "1.0.0"})
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostPublishArtifacts(c, redisClient, db)

	assert.Equal(t, http.StatusOK, w.Code, "Expected 200 when all artifacts are already signed")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "All artifacts are already signed", body["message"])
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, appID.Hex(), data["app_id"])
	assert.Equal(t, "1.0.0", data["version"])
	t.Logf("Inputs: app_id=%s, owner=%s; Result: code=%d, message=%s", appID.Hex(), owner, w.Code, body["message"])
}

// To verify: In PostPublishArtifacts change StatusAccepted, response message, or data shape (task_id, artifacts); test will fail.
func TestPostPublishArtifacts_PublishStarted_ReturnsAccepted(t *testing.T) {
	db := mongoTestDB(t)
	appID := primitive.NewObjectID()
	owner := "test-owner-publish-started"
	appName := "TestAppPublish"
	ctx := context.Background()
	appsColl := db.Collection("apps")
	metaColl := db.Collection("apps_meta")
	_, err := appsColl.InsertOne(ctx, bson.M{
		"app_id":  appID,
		"version": "1.0.0",
		"owner":   owner,
		"artifacts": []model.Artifact{
			{Link: "http://api.example.com/download?key=app%2Fv1%2Ffile.bin", Hashes: map[string]string{"sha256": "abc"}, Length: 100, TufSigned: false},
		},
	})
	require.NoError(t, err)
	_, err = metaColl.InsertOne(ctx, bson.M{"_id": appID, "owner": owner, "app_name": appName})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = metaColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	oldAPI := viper.GetViper().GetString("API_URL")
	viper.GetViper().Set("API_URL", "http://api.example.com")
	defer viper.GetViper().Set("API_URL", oldAPI)

	c, w := makePostPublishArtifactsContext(owner, PublishArtifactsPayload{AppID: appID.Hex(), Version: "1.0.0"})
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	// Bootstrap key so AddArtifacts goroutine can progress past first check (S3 may still fail in background)
	mr.Set("BOOTSTRAP_"+owner+"_"+appName, "done")

	PostPublishArtifacts(c, redisClient, db)

	assert.Equal(t, http.StatusAccepted, w.Code, "Expected 202 when publish is started")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Artifact(s) publishing started", body["message"])
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok, "response must contain data")
	assert.Equal(t, appID.Hex(), data["app_id"])
	assert.Equal(t, "1.0.0", data["version"])
	assert.NotEmpty(t, data["task_id"], "task_id must be returned")
	assert.NotNil(t, data["artifacts"], "artifacts list must be present")
	taskID, ok := data["task_id"].(string)
	require.True(t, ok, "task_id must be string")
	waitForTaskTerminalState(t, redisClient, taskID, 5*time.Second)
	t.Logf("Inputs: app_id=%s, owner=%s; Result: code=%d, task_id=%v", appID.Hex(), owner, w.Code, data["task_id"])
}

// --- PostDeleteArtifacts tests ---

// To verify: In PostDeleteArtifacts remove GetUsernameFromContext check or return 200 on error; test will fail (wrong status).
func TestPostDeleteArtifacts_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	payload := DeleteArtifactsPayload{
		AppID:             "507f1f77bcf86cd799439011",
		AppName:           "MyApp",
		Version:           "1.0.0",
		ArtifactsToDelete: []string{"0"},
	}
	c, w := makePostDeleteArtifactsContext("", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostDeleteArtifacts(c, redisClient, nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
	t.Logf("Inputs: username=empty; Result: code=%d", w.Code)
}

// To verify: In PostDeleteArtifacts change ShouldBindJSON error handling; test will fail.
func TestPostDeleteArtifacts_InvalidPayload_ReturnsBadRequest(t *testing.T) {
	c, w := makePostDeleteArtifactsContext("owner", nil)
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostDeleteArtifacts(c, redisClient, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Invalid payload")
	t.Logf("Inputs: body=empty; Result: code=%d", w.Code)
}

// To verify: In PostDeleteArtifacts remove or change ObjectIDFromHex error handling for invalid app_id; test will fail.
func TestPostDeleteArtifacts_InvalidAppID_ReturnsBadRequest(t *testing.T) {
	payload := DeleteArtifactsPayload{
		AppID:             "not-a-hex-id",
		AppName:           "MyApp",
		Version:           "1.0.0",
		ArtifactsToDelete: []string{"0"},
	}
	c, w := makePostDeleteArtifactsContext("owner", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostDeleteArtifacts(c, redisClient, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Invalid app_id")
	t.Logf("Inputs: app_id=not-a-hex-id; Result: code=%d", w.Code)
}

// To verify: In PostDeleteArtifacts change FindOne (apps) ErrNoDocuments handling; test will fail (wrong status).
func TestPostDeleteArtifacts_AppNotFound_ReturnsNotFound(t *testing.T) {
	db := mongoTestDB(t)
	appID := primitive.NewObjectID()
	payload := DeleteArtifactsPayload{
		AppID:             appID.Hex(),
		AppName:           "MyApp",
		Version:           "1.0.0",
		ArtifactsToDelete: []string{"0"},
	}
	c, w := makePostDeleteArtifactsContext("owner", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	// No document in apps with this _id -> FindOne returns ErrNoDocuments

	PostDeleteArtifacts(c, redisClient, db)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "not found")
	t.Logf("Inputs: app_id=%s; Result: code=%d", appID.Hex(), w.Code)
}

// To verify: In PostDeleteArtifacts change apps_meta FindOne error handling; test will fail (wrong status).
func TestPostDeleteArtifacts_AppMetaNotFound_ReturnsInternalServerError(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-delete-meta-missing"
	appsColl := db.Collection("apps")
	_, err := appsColl.InsertOne(ctx, bson.M{
		"_id":     appID,
		"app_id":  appID,
		"version": "1.0.0",
		"owner":   owner,
		"artifacts": []model.Artifact{
			{Link: "http://api.example.com/download?key=app%2Fv1%2Ffile.bin", Hashes: map[string]string{"sha256": "abc"}, Length: 100, TufSigned: true},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
	})
	// Do not insert apps_meta

	payload := DeleteArtifactsPayload{
		AppID:             appID.Hex(),
		AppName:           "TestApp",
		Version:           "1.0.0",
		ArtifactsToDelete: []string{"0"},
	}
	c, w := makePostDeleteArtifactsContext(owner, payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	oldAPI := viper.GetViper().GetString("API_URL")
	viper.GetViper().Set("API_URL", "http://api.example.com")
	defer viper.GetViper().Set("API_URL", oldAPI)

	PostDeleteArtifacts(c, redisClient, db)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Failed to find app metadata", body["error"])
	t.Logf("Inputs: app_id=%s; Result: code=%d", appID.Hex(), w.Code)
}

// To verify: In PostDeleteArtifacts change the condition len(artifactsToDelete) == 0 or the error message; test will fail.
func TestPostDeleteArtifacts_NoValidArtifactsToDelete_ReturnsBadRequest(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-delete-unsigned"
	appsColl := db.Collection("apps")
	metaColl := db.Collection("apps_meta")
	// Artifact with TufSigned: false so it is skipped
	_, err := appsColl.InsertOne(ctx, bson.M{
		"_id":     appID,
		"app_id":  appID,
		"version": "1.0.0",
		"owner":   owner,
		"artifacts": []model.Artifact{
			{Link: "http://api.example.com/download?key=app%2Fv1%2Ffile.bin", Hashes: map[string]string{"sha256": "abc"}, Length: 100, TufSigned: false},
		},
	})
	require.NoError(t, err)
	_, err = metaColl.InsertOne(ctx, bson.M{"_id": appID, "owner": owner, "app_name": "TestApp"})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = metaColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	payload := DeleteArtifactsPayload{
		AppID:             appID.Hex(),
		AppName:           "TestApp",
		Version:           "1.0.0",
		ArtifactsToDelete: []string{"0"},
	}
	c, w := makePostDeleteArtifactsContext(owner, payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostDeleteArtifacts(c, redisClient, db)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "No valid artifacts to delete (all must be TUF signed)", body["error"])
	t.Logf("Inputs: artifact not TUF signed; Result: code=%d", w.Code)
}

// To verify: In PostDeleteArtifacts change the condition len(tufArtifacts) == 0 or the error message; test will fail.
func TestPostDeleteArtifacts_NoValidArtifactsAfterConversion_ReturnsBadRequest(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-delete-convert-fail"
	appsColl := db.Collection("apps")
	metaColl := db.Collection("apps_meta")
	// TufSigned: true but no hashes so ConvertMongoArtifactToTUF fails
	_, err := appsColl.InsertOne(ctx, bson.M{
		"_id":     appID,
		"app_id":  appID,
		"version": "1.0.0",
		"owner":   owner,
		"artifacts": []model.Artifact{
			{Link: "http://api.example.com/download?key=app%2Fv1%2Ffile.bin", Hashes: nil, Length: 100, TufSigned: true},
		},
	})
	require.NoError(t, err)
	_, err = metaColl.InsertOne(ctx, bson.M{"_id": appID, "owner": owner, "app_name": "TestApp"})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = metaColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	oldAPI := viper.GetViper().GetString("API_URL")
	viper.GetViper().Set("API_URL", "http://api.example.com")
	defer viper.GetViper().Set("API_URL", oldAPI)

	payload := DeleteArtifactsPayload{
		AppID:             appID.Hex(),
		AppName:           "TestApp",
		Version:           "1.0.0",
		ArtifactsToDelete: []string{"0"},
	}
	c, w := makePostDeleteArtifactsContext(owner, payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostDeleteArtifacts(c, redisClient, db)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "No valid artifacts to delete", body["error"])
	t.Logf("Inputs: artifact fails conversion; Result: code=%d", w.Code)
}

// To verify: In PostDeleteArtifacts change StatusAccepted, response message, or data shape (task_id, artifacts); test will fail.
func TestPostDeleteArtifacts_DeletionStarted_ReturnsAccepted(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-delete-started"
	appName := "TestAppDelete"
	appsColl := db.Collection("apps")
	metaColl := db.Collection("apps_meta")
	_, err := appsColl.InsertOne(ctx, bson.M{
		"_id":     appID,
		"app_id":  appID,
		"version": "1.0.0",
		"owner":   owner,
		"artifacts": []model.Artifact{
			{Link: "http://api.example.com/download?key=app%2Fv1%2Ffile.bin", Hashes: map[string]string{"sha256": "abc"}, Length: 100, TufSigned: true},
		},
	})
	require.NoError(t, err)
	_, err = metaColl.InsertOne(ctx, bson.M{"_id": appID, "owner": owner, "app_name": appName})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = metaColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	oldAPI := viper.GetViper().GetString("API_URL")
	viper.GetViper().Set("API_URL", "http://api.example.com")
	defer viper.GetViper().Set("API_URL", oldAPI)

	payload := DeleteArtifactsPayload{
		AppID:             appID.Hex(),
		AppName:           appName,
		Version:           "1.0.0",
		ArtifactsToDelete: []string{"0"},
	}
	c, w := makePostDeleteArtifactsContext(owner, payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+owner+"_"+appName, "done")

	PostDeleteArtifacts(c, redisClient, db)

	assert.Equal(t, http.StatusAccepted, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Artifact(s) deletion started", body["message"])
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, appID.Hex(), data["app_id"])
	assert.Equal(t, "1.0.0", data["version"])
	assert.NotEmpty(t, data["task_id"])
	assert.NotNil(t, data["artifacts"])
	taskID, ok := data["task_id"].(string)
	require.True(t, ok, "task_id must be string")
	waitForTaskTerminalState(t, redisClient, taskID, 5*time.Second)
	t.Logf("Inputs: app_id=%s, owner=%s; Result: code=%d, task_id=%v", appID.Hex(), owner, w.Code, data["task_id"])
}

// --- updateAllArtifactsTUFStatus tests ---

// To verify: In updateAllArtifactsTUFStatus change $set keys (artifacts.$.tuf_signed, artifacts.$.tuf_task_id) or filter; test will fail (wrong document state).
func TestUpdateAllArtifactsTUFStatus_UpdatesMatchingArtifact_SetsSignedAndTaskID(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-update-status"
	version := "1.0.0"
	link := "http://api.example.com/download?key=app%2Fv1%2Ffile.bin"
	platformID := primitive.NewObjectID()
	archID := primitive.NewObjectID()
	pkg := "dmg"

	artifact := model.Artifact{
		Link:      link,
		Platform:  platformID,
		Arch:      archID,
		Package:   pkg,
		TufSigned: false,
		TufTaskID: nil,
	}

	appsColl := db.Collection("apps")
	_, err := appsColl.InsertOne(ctx, bson.M{
		"app_id":    appID,
		"version":   version,
		"owner":     owner,
		"artifacts": []model.Artifact{artifact},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	taskID := "task-123"
	updateAllArtifactsTUFStatus(ctx, db, appID, version, owner, []model.Artifact{artifact}, true, &taskID)

	var doc struct {
		Artifacts []model.Artifact `bson:"artifacts"`
	}
	err = appsColl.FindOne(ctx, bson.M{"app_id": appID, "version": version, "owner": owner}).Decode(&doc)
	require.NoError(t, err)
	require.Len(t, doc.Artifacts, 1)
	assert.True(t, doc.Artifacts[0].TufSigned, "tuf_signed must be set to true")
	require.NotNil(t, doc.Artifacts[0].TufTaskID, "tuf_task_id must be set")
	assert.Equal(t, taskID, *doc.Artifacts[0].TufTaskID)
	t.Logf("Inputs: artifact link=%s; Result: tuf_signed=%t, tuf_task_id=%s", link, doc.Artifacts[0].TufSigned, *doc.Artifacts[0].TufTaskID)
}

// To verify: In updateAllArtifactsTUFStatus change $elemMatch filter (link, platform, arch, package); test will fail (document would be modified).
func TestUpdateAllArtifactsTUFStatus_NoMatchingArtifact_DoesNotModify(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-no-match"
	version := "1.0.0"
	linkA := "http://api.example.com/download?key=app%2Fv1%2FfileA.bin"
	platformID := primitive.NewObjectID()
	archID := primitive.NewObjectID()

	artifactInDB := model.Artifact{
		Link:      linkA,
		Platform:  platformID,
		Arch:      archID,
		Package:   "pkgA",
		TufSigned: false,
	}

	appsColl := db.Collection("apps")
	_, err := appsColl.InsertOne(ctx, bson.M{
		"app_id":    appID,
		"version":   version,
		"owner":     owner,
		"artifacts": []model.Artifact{artifactInDB},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	// Pass artifact with different link so $elemMatch does not match
	artifactOther := model.Artifact{Link: "http://other.com/file.bin", Platform: platformID, Arch: archID, Package: "pkgA"}
	updateAllArtifactsTUFStatus(ctx, db, appID, version, owner, []model.Artifact{artifactOther}, true, ptrString("task-456"))

	var doc struct {
		Artifacts []model.Artifact `bson:"artifacts"`
	}
	err = appsColl.FindOne(ctx, bson.M{"app_id": appID, "version": version, "owner": owner}).Decode(&doc)
	require.NoError(t, err)
	require.Len(t, doc.Artifacts, 1)
	assert.False(t, doc.Artifacts[0].TufSigned, "artifact must remain unchanged when no match")
	assert.Nil(t, doc.Artifacts[0].TufTaskID)
	t.Logf("Inputs: non-matching artifact link; Result: tuf_signed unchanged=%t", doc.Artifacts[0].TufSigned)
}

// To verify: In updateAllArtifactsTUFStatus add a panic or change loop so empty artifacts is not a no-op; test would panic or fail.
func TestUpdateAllArtifactsTUFStatus_EmptyArtifacts_NoPanic(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-empty"
	version := "1.0.0"

	updateAllArtifactsTUFStatus(ctx, db, appID, version, owner, nil, true, nil)
	updateAllArtifactsTUFStatus(ctx, db, appID, version, owner, []model.Artifact{}, true, ptrString("task"))

	// No panic and no error; nothing to assert except we get here
	t.Logf("Empty artifacts slice: no panic")
}

// To verify: In updateAllArtifactsTUFStatus change update to apply to wrong element or skip second artifact; test will fail (one artifact not updated).
func TestUpdateAllArtifactsTUFStatus_MultipleArtifacts_UpdatesAll(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-multi"
	version := "2.0.0"
	platformID := primitive.NewObjectID()
	archID := primitive.NewObjectID()

	a1 := model.Artifact{Link: "http://api.example.com/download?key=app%2Fv2%2Fa.bin", Platform: platformID, Arch: archID, Package: "p1", TufSigned: false}
	a2 := model.Artifact{Link: "http://api.example.com/download?key=app%2Fv2%2Fb.bin", Platform: platformID, Arch: archID, Package: "p2", TufSigned: false}

	appsColl := db.Collection("apps")
	_, err := appsColl.InsertOne(ctx, bson.M{
		"app_id":    appID,
		"version":   version,
		"owner":     owner,
		"artifacts": []model.Artifact{a1, a2},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	taskID := "task-multi"
	updateAllArtifactsTUFStatus(ctx, db, appID, version, owner, []model.Artifact{a1, a2}, true, &taskID)

	var doc struct {
		Artifacts []model.Artifact `bson:"artifacts"`
	}
	err = appsColl.FindOne(ctx, bson.M{"app_id": appID, "version": version, "owner": owner}).Decode(&doc)
	require.NoError(t, err)
	require.Len(t, doc.Artifacts, 2)
	assert.True(t, doc.Artifacts[0].TufSigned)
	assert.True(t, doc.Artifacts[1].TufSigned)
	require.NotNil(t, doc.Artifacts[0].TufTaskID)
	require.NotNil(t, doc.Artifacts[1].TufTaskID)
	assert.Equal(t, taskID, *doc.Artifacts[0].TufTaskID)
	assert.Equal(t, taskID, *doc.Artifacts[1].TufTaskID)
	t.Logf("Inputs: 2 artifacts; Result: both tuf_signed=true, task_id set")
}

// --- updateArtifactsTUFStatusToDeleted tests ---

// To verify: In updateArtifactsTUFStatusToDeleted change $set (artifacts.$.tuf_signed to false, artifacts.$.tuf_task_id) or filter; test will fail (wrong document state).
func TestUpdateArtifactsTUFStatusToDeleted_UpdatesMatchingArtifact_SetsSignedFalseAndTaskID(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-to-deleted"
	version := "1.0.0"
	link := "http://api.example.com/download?key=app%2Fv1%2Fdel.bin"
	platformID := primitive.NewObjectID()
	archID := primitive.NewObjectID()
	pkg := "dmg"

	artifact := model.Artifact{
		Link:      link,
		Platform:  platformID,
		Arch:      archID,
		Package:   pkg,
		TufSigned: true,
		TufTaskID: ptrString("old-task"),
	}

	appsColl := db.Collection("apps")
	_, err := appsColl.InsertOne(ctx, bson.M{
		"app_id":    appID,
		"version":   version,
		"owner":     owner,
		"artifacts": []model.Artifact{artifact},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	taskID := "task-deleted-123"
	updateArtifactsTUFStatusToDeleted(ctx, db, appID, version, owner, []model.Artifact{artifact}, &taskID)

	var doc struct {
		Artifacts []model.Artifact `bson:"artifacts"`
	}
	err = appsColl.FindOne(ctx, bson.M{"app_id": appID, "version": version, "owner": owner}).Decode(&doc)
	require.NoError(t, err)
	require.Len(t, doc.Artifacts, 1)
	assert.False(t, doc.Artifacts[0].TufSigned, "tuf_signed must be set to false (deleted)")
	require.NotNil(t, doc.Artifacts[0].TufTaskID)
	assert.Equal(t, taskID, *doc.Artifacts[0].TufTaskID)
	t.Logf("Inputs: artifact link=%s; Result: tuf_signed=%t, tuf_task_id=%s", link, doc.Artifacts[0].TufSigned, *doc.Artifacts[0].TufTaskID)
}

// To verify: In updateArtifactsTUFStatusToDeleted change $elemMatch filter; test will fail (document would be modified).
func TestUpdateArtifactsTUFStatusToDeleted_NoMatchingArtifact_DoesNotModify(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-to-deleted-no-match"
	version := "1.0.0"
	linkA := "http://api.example.com/download?key=app%2Fv1%2FfileA.bin"
	platformID := primitive.NewObjectID()
	archID := primitive.NewObjectID()

	artifactInDB := model.Artifact{
		Link:      linkA,
		Platform:  platformID,
		Arch:      archID,
		Package:   "pkgA",
		TufSigned: true,
	}

	appsColl := db.Collection("apps")
	_, err := appsColl.InsertOne(ctx, bson.M{
		"app_id":    appID,
		"version":   version,
		"owner":     owner,
		"artifacts": []model.Artifact{artifactInDB},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	artifactOther := model.Artifact{Link: "http://other.com/file.bin", Platform: platformID, Arch: archID, Package: "pkgA"}
	updateArtifactsTUFStatusToDeleted(ctx, db, appID, version, owner, []model.Artifact{artifactOther}, ptrString("task-456"))

	var doc struct {
		Artifacts []model.Artifact `bson:"artifacts"`
	}
	err = appsColl.FindOne(ctx, bson.M{"app_id": appID, "version": version, "owner": owner}).Decode(&doc)
	require.NoError(t, err)
	require.Len(t, doc.Artifacts, 1)
	assert.True(t, doc.Artifacts[0].TufSigned, "artifact must remain unchanged when no match")
	assert.Nil(t, doc.Artifacts[0].TufTaskID)
	t.Logf("Inputs: non-matching artifact link; Result: tuf_signed unchanged=%t", doc.Artifacts[0].TufSigned)
}

// To verify: In updateArtifactsTUFStatusToDeleted add panic or change loop for empty artifacts; test would panic or fail.
func TestUpdateArtifactsTUFStatusToDeleted_EmptyArtifacts_NoPanic(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-to-deleted-empty"
	version := "1.0.0"

	updateArtifactsTUFStatusToDeleted(ctx, db, appID, version, owner, nil, nil)
	updateArtifactsTUFStatusToDeleted(ctx, db, appID, version, owner, []model.Artifact{}, ptrString("task"))

	t.Logf("Empty artifacts slice: no panic")
}

// To verify: In updateArtifactsTUFStatusToDeleted change update or skip second artifact; test will fail (one artifact not updated).
func TestUpdateArtifactsTUFStatusToDeleted_MultipleArtifacts_UpdatesAll(t *testing.T) {
	db := mongoTestDB(t)
	ctx := context.Background()
	appID := primitive.NewObjectID()
	owner := "test-owner-to-deleted-multi"
	version := "2.0.0"
	platformID := primitive.NewObjectID()
	archID := primitive.NewObjectID()

	a1 := model.Artifact{Link: "http://api.example.com/download?key=app%2Fv2%2Fa.bin", Platform: platformID, Arch: archID, Package: "p1", TufSigned: true}
	a2 := model.Artifact{Link: "http://api.example.com/download?key=app%2Fv2%2Fb.bin", Platform: platformID, Arch: archID, Package: "p2", TufSigned: true}

	appsColl := db.Collection("apps")
	_, err := appsColl.InsertOne(ctx, bson.M{
		"app_id":    appID,
		"version":   version,
		"owner":     owner,
		"artifacts": []model.Artifact{a1, a2},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = appsColl.DeleteMany(ctx, bson.M{"owner": owner})
	})

	taskID := "task-deleted-multi"
	updateArtifactsTUFStatusToDeleted(ctx, db, appID, version, owner, []model.Artifact{a1, a2}, &taskID)

	var doc struct {
		Artifacts []model.Artifact `bson:"artifacts"`
	}
	err = appsColl.FindOne(ctx, bson.M{"app_id": appID, "version": version, "owner": owner}).Decode(&doc)
	require.NoError(t, err)
	require.Len(t, doc.Artifacts, 2)
	assert.False(t, doc.Artifacts[0].TufSigned)
	assert.False(t, doc.Artifacts[1].TufSigned)
	require.NotNil(t, doc.Artifacts[0].TufTaskID)
	require.NotNil(t, doc.Artifacts[1].TufTaskID)
	assert.Equal(t, taskID, *doc.Artifacts[0].TufTaskID)
	assert.Equal(t, taskID, *doc.Artifacts[1].TufTaskID)
	t.Logf("Inputs: 2 artifacts; Result: both tuf_signed=false, task_id set")
}

func ptrString(s string) *string {
	return &s
}
