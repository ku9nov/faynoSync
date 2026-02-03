package metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"faynoSync/server/tuf/models"
	"faynoSync/server/tuf/tasks"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// To verify: Change URL query "appName" or JSON body binding in PostMetadataSignDelete; test will fail (wrong status/body).
func makePostMetadataSignDeleteContext(username string, appName string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/tuf/v1/metadata/sign/delete"
	if appName != "" {
		url += "?appName=" + appName
	}
	var bodyReader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		bodyReader = bytes.NewReader(raw)
		c.Request = httptest.NewRequest(http.MethodPost, url, bodyReader)
		c.Request.Header.Set("Content-Type", "application/json")
	} else {
		c.Request = httptest.NewRequest(http.MethodPost, url, nil)
	}
	if username != "" {
		c.Set("username", username)
	}
	return c, w
}

// To verify: In PostMetadataSignDelete remove GetUsernameFromContext check or return 200 on error; test will fail (wrong status).
func TestPostMetadataSignDelete_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	payload := models.MetadataSignDeletePayload{Role: "root"}
	c, w := makePostMetadataSignDeleteContext("", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostMetadataSignDelete(c, client)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 when username is missing from context")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
}

// To verify: In PostMetadataSignDelete change appName empty check to return 200 or remove it; test will fail (wrong status).
func TestPostMetadataSignDelete_MissingAppName_ReturnsBadRequest(t *testing.T) {
	payload := models.MetadataSignDeletePayload{Role: "root"}
	c, w := makePostMetadataSignDeleteContext("admin", "", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostMetadataSignDelete(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when appName is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "appName query parameter is required", body["error"])
}

// To verify: In PostMetadataSignDelete remove nil Redis check or return 200; test will fail (wrong status or panic).
func TestPostMetadataSignDelete_NilRedis_ReturnsServiceUnavailable(t *testing.T) {
	payload := models.MetadataSignDeletePayload{Role: "root"}
	c, w := makePostMetadataSignDeleteContext("admin", "myapp", payload)

	PostMetadataSignDelete(c, nil)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Expected 503 when Redis client is nil")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Redis client is not available", body["error"])
}

// To verify: In PostMetadataSignDelete ignore ShouldBindJSON error or return 200; test will fail (wrong status).
func TestPostMetadataSignDelete_InvalidPayload_ReturnsBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/metadata/sign/delete?appName=myapp", bytes.NewReader([]byte("not json")))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "admin")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostMetadataSignDelete(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when body is invalid JSON")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Invalid payload format")
}

// To verify: In PostMetadataSignDelete remove missing-role check in ShouldBindJSON; test will fail (wrong status).
func TestPostMetadataSignDelete_MissingRoleInPayload_ReturnsBadRequest(t *testing.T) {
	c, w := makePostMetadataSignDeleteContext("admin", "myapp", map[string]interface{}{})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostMetadataSignDelete(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when role is missing in payload")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Invalid payload format")
}

// To verify: In PostMetadataSignDelete remove signing-key-missing branch (err == redis.Nil || signingStatus == ""); test will fail (wrong status).
func TestPostMetadataSignDelete_SigningKeyMissing_ReturnsNotFound(t *testing.T) {
	payload := models.MetadataSignDeletePayload{Role: "snapshot"}
	c, w := makePostMetadataSignDeleteContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostMetadataSignDelete(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when signing key is missing in Redis")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "No signing process")
	assert.Contains(t, body["error"], "not in a signing process")
}

// To verify: In PostMetadataSignDelete change condition to only check redis.Nil and not empty signingStatus; test will fail (wrong status).
func TestPostMetadataSignDelete_SigningKeyEmpty_ReturnsNotFound(t *testing.T) {
	payload := models.MetadataSignDeletePayload{Role: "timestamp"}
	c, w := makePostMetadataSignDeleteContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("TIMESTAMP_SIGNING_admin_myapp", "")

	PostMetadataSignDelete(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when signing key value is empty")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "No signing process")
}

// To verify: In PostMetadataSignDelete change response status from 202 or response message/body; test will fail (wrong status or body).
func TestPostMetadataSignDelete_Success_NonRoot_ReturnsAcceptedWithTaskID(t *testing.T) {
	payload := models.MetadataSignDeletePayload{Role: "snapshot"}
	c, w := makePostMetadataSignDeleteContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("SNAPSHOT_SIGNING_admin_myapp", "pending")

	PostMetadataSignDelete(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code, "Expected 202 when delete is accepted")
	var resp models.MetadataSignDeleteResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Data.TaskID, "Response should contain task_id")
	assert.False(t, resp.Data.LastUpdate.IsZero(), "Response should contain last_update")
	assert.Equal(t, "Metadata sign delete accepted.", resp.Message)

	// Allow goroutine to run: delete signing key and save task success
	time.Sleep(100 * time.Millisecond)
	ctx := context.Background()
	_, err := client.Get(ctx, "SNAPSHOT_SIGNING_admin_myapp").Result()
	assert.Error(t, err, "Signing key should be deleted by goroutine")
	taskKey := "task:" + resp.Data.TaskID
	taskJSON, err := client.Get(ctx, taskKey).Result()
	require.NoError(t, err, "Task status should be stored in Redis")
	var status tasks.TaskStatus
	require.NoError(t, json.Unmarshal([]byte(taskJSON), &status))
	assert.Equal(t, tasks.TaskStateSuccess, status.State, "Task should finish with SUCCESS")
	require.NotNil(t, status.Result)
	require.NotNil(t, status.Result.Status)
	assert.True(t, *status.Result.Status)
}

// To verify: In PostMetadataSignDelete change ROOT_SIGNING key format or Del(signingKey) logic; test will fail (key not deleted or wrong key).
func TestPostMetadataSignDelete_Success_RoleKeyFormat(t *testing.T) {
	payload := models.MetadataSignDeletePayload{Role: "root"}
	c, w := makePostMetadataSignDeleteContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	signingKey := "ROOT_SIGNING_admin_myapp"
	mr.Set(signingKey, "pending")

	PostMetadataSignDelete(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code)
	time.Sleep(100 * time.Millisecond)
	ctx := context.Background()
	_, err := client.Get(ctx, signingKey).Result()
	assert.Error(t, err, "ROOT_SIGNING_admin_myapp should be deleted")
}

// To verify: In PostMetadataSignDelete remove root+bootstrap branch (payload.Role == "root" and bootstrap prefix "signing-"); test will fail (bootstrap key not deleted).
func TestPostMetadataSignDelete_Success_RootWithBootstrap_DeletesBootstrapKey(t *testing.T) {
	payload := models.MetadataSignDeletePayload{Role: "root"}
	c, w := makePostMetadataSignDeleteContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("ROOT_SIGNING_admin_myapp", "pending")
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")

	PostMetadataSignDelete(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code)
	time.Sleep(100 * time.Millisecond)
	ctx := context.Background()
	_, err := client.Get(ctx, "ROOT_SIGNING_admin_myapp").Result()
	assert.Error(t, err, "Signing key should be deleted")
	bootstrapVal, err := client.Get(ctx, "BOOTSTRAP_admin_myapp").Result()
	assert.Error(t, err, "Bootstrap key with signing- prefix should be deleted")
	_ = bootstrapVal
}

// To verify: In PostMetadataSignDelete change bootstrap branch to not check HasPrefix(bootstrapValue, "signing-"); test will fail (bootstrap key wrongly deleted or not).
func TestPostMetadataSignDelete_Success_RootBootstrapNotSigningPrefix_KeepsBootstrapKey(t *testing.T) {
	payload := models.MetadataSignDeletePayload{Role: "root"}
	c, w := makePostMetadataSignDeleteContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("ROOT_SIGNING_admin_myapp", "pending")
	mr.Set("BOOTSTRAP_admin_myapp", "done")

	PostMetadataSignDelete(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code)
	time.Sleep(100 * time.Millisecond)
	ctx := context.Background()
	val, err := client.Get(ctx, "BOOTSTRAP_admin_myapp").Result()
	require.NoError(t, err)
	assert.Equal(t, "done", val, "Bootstrap key without signing- prefix should not be deleted")
	_ = err
}
