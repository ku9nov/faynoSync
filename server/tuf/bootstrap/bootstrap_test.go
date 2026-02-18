package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"faynoSync/server/tuf/models"
	"faynoSync/server/tuf/tasks"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	originalListMetadataForBootstrap := listMetadataForBootstrap
	listMetadataForBootstrap = func(ctx context.Context, adminName, appName, prefix string) ([]string, error) {
		return []string{}, nil
	}

	code := m.Run()
	listMetadataForBootstrap = originalListMetadataForBootstrap
	os.Exit(code)
}

func mockListMetadataForBootstrap(t *testing.T, files []string, err error) {
	t.Helper()
	originalListMetadataForBootstrap := listMetadataForBootstrap
	listMetadataForBootstrap = func(ctx context.Context, adminName, appName, prefix string) ([]string, error) {
		return files, err
	}
	t.Cleanup(func() {
		listMetadataForBootstrap = originalListMetadataForBootstrap
	})
}

// To verify: Change c.Query("appName") in GetBootstrapStatus to c.Query("app") to make appName-related tests fail.
func makeGetBootstrapStatusContext(username string, appName string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/tuf/v1/bootstrap"
	if appName != "" {
		url += "?appName=" + appName
	}
	c.Request = httptest.NewRequest(http.MethodGet, url, nil)
	if username != "" {
		c.Set("username", username)
	}
	return c, w
}

// To verify: In GetBootstrapStatus remove the GetUsernameFromContext check or return 200 on error; test will fail (wrong status).
func TestGetBootstrapStatus_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	c, w := makeGetBootstrapStatusContext("", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	GetBootstrapStatus(c, client)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 when username is missing from context")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
}

// To verify: In GetBootstrapStatus change the appName empty check to return 200 or remove it; test will fail (wrong status).
func TestGetBootstrapStatus_MissingAppName_ReturnsBadRequest(t *testing.T) {
	c, w := makeGetBootstrapStatusContext("admin", "")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	GetBootstrapStatus(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when appName is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "appName query parameter is required", body["error"])
}

// To verify: In GetBootstrapStatus change nil redisClient branch to return different status; test will fail (wrong status).
func TestGetBootstrapStatus_NilRedis_ReturnsOK_AvailableForBootstrap(t *testing.T) {
	c, w := makeGetBootstrapStatusContext("admin", "myapp")

	GetBootstrapStatus(c, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok, "response must contain data")
	assert.Equal(t, false, data["bootstrap"], "bootstrap should be false when repo not initialized and no Redis lock")
	assert.Equal(t, "System available for bootstrap.", body["message"])
}

// To verify: In GetBootstrapStatus remove Redis Get for bootstrap key or change key format; test will fail (wrong bootstrap/id).
func TestGetBootstrapStatus_WithRedis_NoBootstrapKey_ReturnsOK_AvailableForBootstrap(t *testing.T) {
	c, w := makeGetBootstrapStatusContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	GetBootstrapStatus(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, data["bootstrap"])
	assert.Equal(t, "System available for bootstrap.", body["message"])
	redisLocks, ok := data["redis_locks"].(map[string]interface{})
	require.True(t, ok)
	assert.Empty(t, redisLocks["bootstrap_lock"])
}

// To verify: In GetBootstrapStatus change condition !strings.HasPrefix(bootstrapValue, "pre-") to always true; test will fail (wrong message).
func TestGetBootstrapStatus_WithRedis_BootstrapCompleted_ReturnsOK_AlreadyCompleted(t *testing.T) {
	c, w := makeGetBootstrapStatusContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")

	GetBootstrapStatus(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, data["bootstrap"])
	assert.Equal(t, "done", data["id"])
	assert.Equal(t, "Bootstrap already completed for this admin.", body["message"])
	redisLocks, ok := data["redis_locks"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "done", redisLocks["bootstrap_lock"])
}

// To verify: In GetBootstrapStatus remove HasPrefix check so pre- value is treated as completed; test will fail (bootstrap true, wrong message).
func TestGetBootstrapStatus_WithRedis_BootstrapPreLock_ReturnsOK_AvailableForBootstrap(t *testing.T) {
	c, w := makeGetBootstrapStatusContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "pre-task-123")

	GetBootstrapStatus(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, data["bootstrap"], "pre- prefix means bootstrap in progress, not completed")
	assert.Equal(t, "pre-task-123", data["id"])
	assert.Equal(t, "System available for bootstrap.", body["message"])
	redisLocks, ok := data["redis_locks"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "pre-task-123", redisLocks["bootstrap_lock"])
}

// To verify: In GetBootstrapStatus remove Keys(ctx, "pre-*") call or change pattern; test will fail (pre_locks empty or wrong).
func TestGetBootstrapStatus_WithRedis_PreLocks_ReturnsOK_IncludesPreLocks(t *testing.T) {
	c, w := makeGetBootstrapStatusContext("owner", "app1")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("pre-lock-1", "val1")
	mr.Set("pre-lock-2", "val2")

	GetBootstrapStatus(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	redisLocks, ok := data["redis_locks"].(map[string]interface{})
	require.True(t, ok)
	preLocks, ok := redisLocks["pre_locks"].([]interface{})
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(preLocks), 2, "pre_locks should include keys matching pre-*")
}

// To verify: In GetBootstrapStatus change bootstrap key construction; test will fail (key not found, bootstrap false).
func TestGetBootstrapStatus_WithRedis_BootstrapKeyFormat_AdminAndAppName(t *testing.T) {
	c, w := makeGetBootstrapStatusContext("user1", "myApp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mr.Set("BOOTSTRAP_user1_myApp", "completed")

	GetBootstrapStatus(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, data["bootstrap"])
	assert.Equal(t, "completed", data["id"])
}

func TestGetBootstrapStatus_WithPersistedRootMetadata_ReturnsAlreadyCompleted(t *testing.T) {
	mockListMetadataForBootstrap(t, []string{"1.root.json"}, nil)
	c, w := makeGetBootstrapStatusContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	GetBootstrapStatus(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, data["bootstrap"])
	assert.Equal(t, "Bootstrap already completed for this admin.", body["message"])
}

func TestGetBootstrapStatus_PersistentMetadataCheckFails_ReturnsServiceUnavailable(t *testing.T) {
	mockListMetadataForBootstrap(t, nil, assert.AnError)
	c, w := makeGetBootstrapStatusContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	GetBootstrapStatus(c, client)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Failed to determine bootstrap state from persistent metadata", body["error"])
}

// --- PostBootstrap helpers and tests ---

// To verify: Change c.ShouldBindJSON or URL in PostBootstrap; test will fail (wrong status or body).
func makePostBootstrapContext(username string, payload interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var bodyReader *bytes.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			panic(err)
		}
		bodyReader = bytes.NewReader(raw)
		c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/bootstrap", bodyReader)
		c.Request.Header.Set("Content-Type", "application/json")
	} else {
		c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/bootstrap", nil)
	}
	if username != "" {
		c.Set("username", username)
	}
	return c, w
}

// validMinimalBootstrapPayload returns a minimal valid payload for PostBootstrap (202 Accepted path).
func validMinimalBootstrapPayload() *models.BootstrapPayload {
	return &models.BootstrapPayload{
		AppName: "myapp",
		Settings: models.Settings{
			Roles: models.RolesData{
				Root: models.RoleExpiration{Expiration: 365},
			},
		},
		Metadata: map[string]models.RootMetadata{
			"root": {
				Signatures: []models.Signature{},
				Signed:     models.Signed{},
			},
		},
	}
}

// To verify: In PostBootstrap remove GetUsernameFromContext check or return 202 on error; test will fail (wrong status).
func TestPostBootstrap_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	c, w := makePostBootstrapContext("", validMinimalBootstrapPayload())
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 when username is missing from context")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
}

// To verify: In PostBootstrap remove ShouldBindJSON error check or return 202; test will fail (wrong status).
func TestPostBootstrap_InvalidJSON_ReturnsBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/bootstrap", bytes.NewReader([]byte("not json")))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "admin")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when body is invalid JSON")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Invalid payload format")
}

// To verify: In PostBootstrap remove payload.AppName empty check or return 202; test will fail (wrong status).
func TestPostBootstrap_MissingAppName_ReturnsBadRequest(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	payload.AppName = ""
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	errMsg, _ := body["error"].(string)
	assert.Contains(t, errMsg, "AppName", "Error should mention AppName (binding or explicit check)")
}

// To verify: In PostBootstrap remove settings.roles.root.expiration == 0 check or return 202; test will fail (wrong status).
func TestPostBootstrap_MissingRootExpiration_ReturnsBadRequest(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	payload.Settings.Roles.Root.Expiration = 0
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Missing required field: settings.roles.root.expiration", body["error"])
}

// To verify: In PostBootstrap remove len(payload.Metadata) == 0 check or return 202; test will fail (wrong status).
func TestPostBootstrap_EmptyMetadata_ReturnsBadRequest(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	payload.Metadata = nil
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Missing required field: metadata", body["error"])
}

// To verify: In PostBootstrap remove payload.Metadata[\"root\"] check or return 202; test will fail (wrong status).
func TestPostBootstrap_MissingMetadataRoot_ReturnsBadRequest(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	payload.Metadata = map[string]models.RootMetadata{"other": {}}
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Missing required field: metadata.root", body["error"])
}

// To verify: In PostBootstrap remove preLockExists > 0 check (or Exists for preLockKey); test will fail (wrong status).
func TestPostBootstrap_RedisPreLockExists_ReturnsConflict(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "pre-task-123")
	mr.Set("pre-task-123", "task-123") // pre-lock key exists

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusConflict, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Bootstrap already in progress for this admin and app", body["error"])
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "pre-task-123", data["task_id"])
	assert.Equal(t, "in_progress", data["status"])
}

// To verify: In PostBootstrap remove settingsExists > 0 check; test will fail (wrong status).
func TestPostBootstrap_RedisSettingsExists_ReturnsConflict(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "pre-task-456")
	mr.Set("bootstrap:settings:pre-task-456", "{}") // settings key exists

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusConflict, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Bootstrap already in progress for this admin and app", body["error"])
}

// To verify: In PostBootstrap remove branch for bootstrapValue without \"pre-\" prefix (already completed); test will fail (wrong status).
func TestPostBootstrap_RedisBootstrapCompleted_ReturnsConflict(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done") // no pre- prefix, completed

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusConflict, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Bootstrap already completed for this admin and app", body["error"])
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "completed", data["status"])
}

// To verify: In PostBootstrap change stale lock cleanup (Failure/Errored/Revoked/Pending) to return 409; test will fail (wrong status).
func TestPostBootstrap_RedisStalePreLock_Failure_CleansUpAndAccepts(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "pre-stale-task")
	// No pre-stale-task key, no bootstrap:settings:pre-stale-task — so preLockExists==0, settingsExists==0
	taskStatusJSON, _ := json.Marshal(tasks.TaskStatus{State: tasks.TaskStateFailure})
	mr.Set("task:stale-task", string(taskStatusJSON))

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code, "Stale pre-lock with Failure state should be cleaned up and bootstrap accepted")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "Bootstrap accepted")
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, data["task_id"])
}

// To verify: In PostBootstrap change case tasks.TaskStateSuccess (no pre/settings) to continue; test will fail (wrong status).
func TestPostBootstrap_RedisStalePreLock_Success_ReturnsConflict(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "pre-done-task")
	taskStatusJSON, _ := json.Marshal(tasks.TaskStatus{State: tasks.TaskStateSuccess})
	mr.Set("task:done-task", string(taskStatusJSON))

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusConflict, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Bootstrap already completed for this admin and app", body["error"])
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "completed", data["status"])
}

// To verify: In PostBootstrap remove pre-lock loop that checks bootstrap:settings and BOOTSTRAP; test may fail (wrong conflict).
func TestPostBootstrap_RedisPreLockWithSettingsForSameAdminApp_ReturnsConflict(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("pre-other-task", "other-task")
	mr.Set("bootstrap:settings:other-task", "{}")
	mr.Set("BOOTSTRAP_admin_myapp", "other-task") // same admin/app

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusConflict, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Bootstrap already in progress for this admin and app", body["error"])
}

func TestPostBootstrap_PersistedRootMetadataExists_ReturnsConflict(t *testing.T) {
	mockListMetadataForBootstrap(t, []string{"2.root.json", "timestamp.json"}, nil)
	payload := validMinimalBootstrapPayload()
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusConflict, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "System already has root metadata. Bootstrap already completed.", body["error"])
}

func TestPostBootstrap_PersistentMetadataCheckFails_ReturnsServiceUnavailable(t *testing.T) {
	mockListMetadataForBootstrap(t, nil, assert.AnError)
	payload := validMinimalBootstrapPayload()
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Failed to determine bootstrap state from persistent metadata", body["error"])
}

// To verify: In PostBootstrap change StatusAccepted to StatusOK or change message; test will fail (wrong code or message).
func TestPostBootstrap_ValidPayload_NoLock_ReturnsAccepted(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	c, w := makePostBootstrapContext("admin", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostBootstrap(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Bootstrap accepted and started in background", body["message"])
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, data["task_id"])
	assert.NotEmpty(t, data["last_update"])
}

// To verify: In PostBootstrap remove nil redisClient guard; test will fail (wrong status/message).
func TestPostBootstrap_NilRedis_ValidPayload_ReturnsServiceUnavailable(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	c, w := makePostBootstrapContext("admin", payload)

	PostBootstrap(c, nil)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Redis client is not available", body["error"])
}

// --- preLockBootstrap tests ---

// To verify: In preLockBootstrap allow nil redisClient as success; test will fail (must return not acquired).
func TestPreLockBootstrap_NilRedis_ReturnsNotAcquired(t *testing.T) {
	acquired, existing := preLockBootstrap(nil, "task-1", "admin", "myapp")
	assert.False(t, acquired)
	assert.Equal(t, "", existing)
}

// To verify: In preLockBootstrap change pre-lock key format "pre-" + taskID; test will fail (wrong key or value).
func TestPreLockBootstrap_WithRedis_SetsPreLockKey(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "task-abc"
	adminName := "admin"
	appName := "myapp"

	acquired, existing := preLockBootstrap(client, taskID, adminName, appName)
	assert.True(t, acquired)
	assert.Equal(t, "", existing)

	preLockKey := "pre-" + taskID
	val, err := client.Get(client.Context(), preLockKey).Result()
	require.NoError(t, err)
	assert.Equal(t, taskID, val, "pre-lock key value should be taskID")
}

// To verify: In preLockBootstrap change BOOTSTRAP key or value format; test will fail (wrong key or value).
func TestPreLockBootstrap_WithRedis_SetsBootstrapKey(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "task-xyz"
	adminName := "owner"
	appName := "app1"

	acquired, existing := preLockBootstrap(client, taskID, adminName, appName)
	assert.True(t, acquired)
	assert.Equal(t, "", existing)

	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	val, err := client.Get(client.Context(), bootstrapKey).Result()
	require.NoError(t, err)
	assert.Equal(t, "pre-"+taskID, val, "BOOTSTRAP key value should be pre-<taskID>")
}

// To verify: In preLockBootstrap change bootstrap key construction; test will fail (key not found).
func TestPreLockBootstrap_WithRedis_BootstrapKeyFormat(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	acquired, existing := preLockBootstrap(client, "tid", "user1", "myApp")
	assert.True(t, acquired)
	assert.Equal(t, "", existing)

	val, err := client.Get(client.Context(), "BOOTSTRAP_user1_myApp").Result()
	require.NoError(t, err)
	assert.Equal(t, "pre-tid", val)
}

// To verify: In preLockBootstrap replace SetNX with Set; test will fail (second call overwrites lock).
func TestPreLockBootstrap_WithRedis_BootstrapKeyAlreadyExists_ReturnsNotAcquired(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	adminName := "admin"
	appName := "myapp"
	existingValue := "pre-existing-task"
	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	mr.Set(bootstrapKey, existingValue)

	acquired, existing := preLockBootstrap(client, "new-task", adminName, appName)

	assert.False(t, acquired)
	assert.Equal(t, existingValue, existing)
	val, err := client.Get(client.Context(), bootstrapKey).Result()
	require.NoError(t, err)
	assert.Equal(t, existingValue, val, "existing lock value must not be overwritten")
	_, err = client.Get(client.Context(), "pre-new-task").Result()
	require.Error(t, err, "pre-lock key should not be created when lock acquisition fails")
}

// --- bootstrap (internal) tests ---

// To verify: In bootstrap remove nil checks for redisClient in UpdateTaskState/saveSettings path; test may panic or behave differently.
func TestBootstrap_NilRedis_NoPanic(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	bootstrap(nil, "task-nil", "admin", "myapp", payload)
}

// To verify: In bootstrap change failure path to not call releaseBootstrapLock; test will fail (keys still present).
func TestBootstrap_FinalizeFails_ReleasesLock(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "task-fail"
	adminName := "admin"
	appName := "myapp"
	acquired, existing := preLockBootstrap(client, taskID, adminName, appName)
	assert.True(t, acquired)
	assert.Equal(t, "", existing)
	payload := validMinimalBootstrapPayload()
	// Minimal payload causes BootstrapOnlineRoles to fail, so bootstrapFinalize returns false

	bootstrap(client, taskID, adminName, appName, payload)

	// releaseBootstrapLock should have deleted pre-<taskID> and BOOTSTRAP_<admin>_<app>
	_, err := client.Get(client.Context(), "pre-"+taskID).Result()
	require.Error(t, err, "pre-lock key should be deleted after bootstrap failure")
	_, err = client.Get(client.Context(), "BOOTSTRAP_"+adminName+"_"+appName).Result()
	require.Error(t, err, "BOOTSTRAP key should be deleted after bootstrap failure")
}

// To verify: In bootstrap change failure path to not call SaveTaskStatus(FAILURE, ...); test will fail (wrong state).
func TestBootstrap_FinalizeFails_SavesFailureState(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "task-state"
	adminName := "owner"
	appName := "app1"
	payload := validMinimalBootstrapPayload()
	// Ensure task exists (bootstrap does UpdateTaskState(Started/Running) then SaveTaskStatus(FAILURE))
	taskName := tasks.TaskNameBootstrap
	tasks.SaveTaskStatus(client, taskID, tasks.TaskStatePending, &tasks.TaskResult{Task: &taskName})

	bootstrap(client, taskID, adminName, appName, payload)

	taskData, err := client.Get(client.Context(), "task:"+taskID).Result()
	require.NoError(t, err)
	var status tasks.TaskStatus
	require.NoError(t, json.Unmarshal([]byte(taskData), &status))
	assert.Equal(t, tasks.TaskStateFailure, status.State, "task state should be FAILURE when finalize fails")
	require.NotNil(t, status.Result)
	require.NotNil(t, status.Result.Error)
	assert.Contains(t, *status.Result.Error, "Bootstrap failed")
}

// To verify: In bootstrap change order (e.g. skip UpdateTaskState Started/Running); test will fail (wrong intermediate state or final state).
func TestBootstrap_WithRedis_UpdatesTaskStateThenSavesFailure(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "task-flow"
	adminName := "u"
	appName := "a"
	payload := validMinimalBootstrapPayload()

	bootstrap(client, taskID, adminName, appName, payload)

	taskData, err := client.Get(client.Context(), "task:"+taskID).Result()
	require.NoError(t, err)
	var status tasks.TaskStatus
	require.NoError(t, json.Unmarshal([]byte(taskData), &status))
	assert.Equal(t, tasks.TaskStateFailure, status.State)
	assert.Equal(t, tasks.TaskNameBootstrap, *status.Result.Task)
}

// --- bootstrapFinalize (internal) tests ---

// To verify: In bootstrapFinalize remove nil check for redisClient in the cleanup block; test still passes (we return false before that block).
func TestBootstrapFinalize_NilRedis_ReturnsFalse(t *testing.T) {
	payload := validMinimalBootstrapPayload()
	got := bootstrapFinalize(nil, "task-nil", "admin", "myapp", payload)
	assert.False(t, got, "bootstrapFinalize should return false when BootstrapOnlineRoles fails (nil Redis)")
}

// To verify: In bootstrapFinalize change BootstrapOnlineRoles error handling to return true; test will fail (wrong return).
func TestBootstrapFinalize_BootstrapOnlineRolesFails_ReturnsFalse(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	payload := validMinimalBootstrapPayload()

	got := bootstrapFinalize(client, "task-fail", "admin", "myapp", payload)

	assert.False(t, got, "bootstrapFinalize should return false when BootstrapOnlineRoles fails")
}

// To verify: In bootstrapFinalize remove early return on BootstrapOnlineRoles error; test will fail (keys would be modified).
func TestBootstrapFinalize_BootstrapOnlineRolesFails_DoesNotModifyRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "task-no-modify"
	adminName := "owner"
	appName := "app1"
	mr.Set("pre-"+taskID, taskID)
	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	originalValue := "pre-" + taskID
	mr.Set(bootstrapKey, originalValue)
	payload := validMinimalBootstrapPayload()

	bootstrapFinalize(client, taskID, adminName, appName, payload)

	val, err := client.Get(client.Context(), bootstrapKey).Result()
	require.NoError(t, err)
	assert.Equal(t, originalValue, val, "BOOTSTRAP key should be unchanged when BootstrapOnlineRoles fails")
}

// To verify: In bootstrapFinalize change pre-lock key format "pre-" + taskID; test will fail (key not deleted).
func TestBootstrapFinalize_WithRedis_SuccessPath_KeyFormats(t *testing.T) {
	t.Skip("Success path requires metadata.BootstrapOnlineRoles to succeed (valid root + keys on disk); key formats covered by releaseBootstrapLock tests")
}

// --- releaseBootstrapLock (internal) tests ---

// To verify: In releaseBootstrapLock remove nil redisClient check; test may panic when client is nil.
func TestReleaseBootstrapLock_NilRedis_NoPanic(t *testing.T) {
	releaseBootstrapLock(nil, "task-1", "admin", "myapp")
}

// To verify: In releaseBootstrapLock change or skip any Del; test will fail (key still present).
func TestReleaseBootstrapLock_WithRedis_DeletesAllKeys(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "task-clean"
	adminName := "admin"
	appName := "myapp"
	preLockKey := "pre-" + taskID
	settingsWithPre := "bootstrap:settings:pre-" + taskID
	settingsWithoutPre := "bootstrap:settings:" + taskID
	bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
	mr.Set(preLockKey, taskID)
	mr.Set(settingsWithPre, "{}")
	mr.Set(settingsWithoutPre, "{}")
	mr.Set(bootstrapKey, "pre-"+taskID)

	releaseBootstrapLock(client, taskID, adminName, appName)

	_, err := client.Get(client.Context(), preLockKey).Result()
	require.Error(t, err, "pre-lock key should be deleted")
	_, err = client.Get(client.Context(), settingsWithPre).Result()
	require.Error(t, err, "bootstrap:settings:pre-<taskID> should be deleted")
	_, err = client.Get(client.Context(), settingsWithoutPre).Result()
	require.Error(t, err, "bootstrap:settings:<taskID> should be deleted")
	_, err = client.Get(client.Context(), bootstrapKey).Result()
	require.Error(t, err, "BOOTSTRAP key should be deleted")
}

// To verify: In releaseBootstrapLock change key format for pre-lock or BOOTSTRAP_; test will fail (key not deleted).
func TestReleaseBootstrapLock_WithRedis_KeyFormats(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "tid-123"
	adminName := "user1"
	appName := "myApp"
	mr.Set("pre-"+taskID, "x")
	mr.Set("BOOTSTRAP_"+adminName+"_"+appName, "pre-"+taskID)

	releaseBootstrapLock(client, taskID, adminName, appName)

	_, err := client.Get(client.Context(), "pre-"+taskID).Result()
	require.Error(t, err)
	_, err = client.Get(client.Context(), "BOOTSTRAP_"+adminName+"_"+appName).Result()
	require.Error(t, err)
}

// To verify: In releaseBootstrapLock change settings key format; test will fail (key not deleted).
func TestReleaseBootstrapLock_WithRedis_SettingsKeyFormats(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "task-settings"
	mr.Set("bootstrap:settings:pre-"+taskID, "{}")
	mr.Set("bootstrap:settings:"+taskID, "{}")

	releaseBootstrapLock(client, taskID, "a", "b")

	_, err := client.Get(client.Context(), "bootstrap:settings:pre-"+taskID).Result()
	require.Error(t, err)
	_, err = client.Get(client.Context(), "bootstrap:settings:"+taskID).Result()
	require.Error(t, err)
}

// To verify: In releaseBootstrapLock return early on Del error; test would still pass (miniredis Del succeeds).
// Missing keys: Del on non-existent key returns no error in go-redis, so releaseBootstrapLock completes.
func TestReleaseBootstrapLock_WithRedis_MissingKeys_NoError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	releaseBootstrapLock(client, "task-missing", "admin", "app")
}

// --- getTaskStatusFromRedis (internal) tests ---

// To verify: In getTaskStatusFromRedis remove nil redisClient check; test will panic when client is nil.
func TestGetTaskStatusFromRedis_NilRedis_ReturnsPending(t *testing.T) {
	got := getTaskStatusFromRedis(nil, "task-1")
	assert.Equal(t, tasks.TaskStatePending, got)
}

// To verify: In getTaskStatusFromRedis change redis.Nil branch to return different state; test will fail (wrong state).
func TestGetTaskStatusFromRedis_KeyNotFound_ReturnsPending(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	got := getTaskStatusFromRedis(client, "nonexistent-task")

	assert.Equal(t, tasks.TaskStatePending, got)
}

// To verify: In getTaskStatusFromRedis change key format "task:" + taskID; test will fail (key not found, returns Pending).
func TestGetTaskStatusFromRedis_WithRedis_KeyFormat(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "task-123"
	taskStatusJSON, _ := json.Marshal(tasks.TaskStatus{State: tasks.TaskStateSuccess})
	mr.Set("task:"+taskID, string(taskStatusJSON))

	got := getTaskStatusFromRedis(client, taskID)

	assert.Equal(t, tasks.TaskStateSuccess, got)
}

// To verify: In getTaskStatusFromRedis change unmarshal error handling to return different state; test will fail (wrong state).
func TestGetTaskStatusFromRedis_InvalidJSON_ReturnsPending(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("task:bad-json", "not valid json")

	got := getTaskStatusFromRedis(client, "bad-json")

	assert.Equal(t, tasks.TaskStatePending, got)
}

// To verify: In getTaskStatusFromRedis remove return of taskStatus.State; test will fail (wrong state).
func TestGetTaskStatusFromRedis_WithRedis_ReturnsStoredState(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "task-failure"
	taskStatusJSON, _ := json.Marshal(tasks.TaskStatus{State: tasks.TaskStateFailure})
	mr.Set("task:"+taskID, string(taskStatusJSON))

	got := getTaskStatusFromRedis(client, taskID)

	assert.Equal(t, tasks.TaskStateFailure, got)
}
