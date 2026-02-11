package config

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"faynoSync/server/tuf/models"
	"faynoSync/server/tuf/tasks"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// To verify: Change c.Query("appName") in GetConfig to c.Query("app") to make appName-related tests fail.
func makeGetConfigContext(appName string, username string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/tuf/v1/config"
	if appName != "" {
		url += "?appName=" + appName
	}
	c.Request = httptest.NewRequest(http.MethodGet, url, nil)
	if username != "" {
		c.Set("username", username)
	}
	return c, w
}

// To verify: In GetConfig remove the GetUsernameFromContext check or return 200 on error; test will fail (wrong status).
func TestGetConfig_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	c, w := makeGetConfigContext("appName", "") // username not set
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	GetConfig(c, client)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 when username is missing from context")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
}

// To verify: In GetConfig change the appName empty check to return 200 or remove it; test will fail (wrong status).
func TestGetConfig_MissingAppName_ReturnsBadRequest(t *testing.T) {
	c, w := makeGetConfigContext("", "owner") // appName empty
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	GetConfig(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when appName is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "appName query parameter is required", body["error"])
}

// To verify: In GetConfig change the bootstrap-missing branch to return 200; test will fail (wrong status).
func TestGetConfig_BootstrapMissing_ReturnsNotFound(t *testing.T) {
	c, w := makeGetConfigContext("appName", "owner")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	GetConfig(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap key is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "No Repository Settings/Config found")
	assert.Contains(t, body["error"], "bootstrap")
}

// To verify: In GetConfig remove the bootstrapValue == "" condition; test will fail (wrong status).
func TestGetConfig_BootstrapEmpty_ReturnsNotFound(t *testing.T) {
	c, w := makeGetConfigContext("appName", "owner")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "")

	GetConfig(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap value is empty")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "No Repository Settings/Config found")
}

// To verify: In GetConfig change StatusOK to StatusCreated or change Message; test will fail (wrong code or message).
func TestGetConfig_Success_BootstrapOnly_ReturnsOK(t *testing.T) {
	c, w := makeGetConfigContext("appName", "owner")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")

	GetConfig(c, client)

	assert.Equal(t, http.StatusOK, w.Code, "Expected 200 when bootstrap is set")
	var resp models.GetConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Current Settings", resp.Message)
	assert.NotNil(t, resp.Data)
	assert.Equal(t, "done", resp.Data["bootstrap"])
}

// To verify: In GetConfig change strconv.Atoi for integer settings or the key lowercasing; test will fail (wrong value type or key).
func TestGetConfig_Success_WithIntSettings_ParsesIntegers(t *testing.T) {
	c, w := makeGetConfigContext("appName", "owner")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")
	mr.Set("ROOT_EXPIRATION_owner_appName", "365")
	mr.Set("ROOT_THRESHOLD_owner_appName", "2")

	GetConfig(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp models.GetConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "done", resp.Data["bootstrap"])

	assert.Equal(t, float64(365), resp.Data["root_expiration"])
	assert.Equal(t, float64(2), resp.Data["root_threshold"])
}

// To verify: In GetConfig change the "true"/"false" branch to store string instead of bool; test will fail (wrong type).
func TestGetConfig_Success_WithBoolSettings_ParsesBooleans(t *testing.T) {
	c, w := makeGetConfigContext("appName", "owner")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")
	mr.Set("TARGETS_ONLINE_KEY_owner_appName", "true")

	GetConfig(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp models.GetConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp.Data["targets_online_key"])
}

// To verify: In GetConfig change the else branch (string value) to parse as int; test will fail (wrong type or key).
func TestGetConfig_Success_WithStringSettings_PreservesString(t *testing.T) {
	c, w := makeGetConfigContext("appName", "owner")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")
	mr.Set("NUMBER_OF_DELEGATED_BINS_owner_appName", "five") // non-numeric string

	GetConfig(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp models.GetConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "five", resp.Data["number_of_delegated_bins"])
}

// To verify: In GetConfig change Scan pattern or role_expiration assignment; test will fail (missing role_expiration).
func TestGetConfig_Success_WithCustomRoleExpiration_IncludesRoleExpiration(t *testing.T) {
	c, w := makeGetConfigContext("appName", "owner")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")

	mr.Set("DELEGATED_EXPIRATION_owner_appName", "30")

	GetConfig(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp models.GetConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(30), resp.Data["role_expiration"])
}

// To verify: In GetConfig change the bootstrap Get error handling to return 200 on Redis error; test will fail (wrong status).
func TestGetConfig_RedisErrorOnBootstrapGet_ReturnsNotFound(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close() // cause Get to fail
	c, w := makeGetConfigContext("appName", "owner")

	GetConfig(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when Redis Get for bootstrap fails")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "No Repository Settings/Config found")
}

// To verify: Change c.Query("appName") or c.ShouldBindJSON in PutConfig to break appName/binding; tests will fail.
func makePutConfigContext(appName string, username string, payload interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/tuf/v1/config"
	if appName != "" {
		url += "?appName=" + appName
	}
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			panic(err)
		}
	}
	if body == nil {
		body = []byte("{}")
	}
	c.Request = httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	if username != "" {
		c.Set("username", username)
	}
	return c, w
}

// To verify: In PutConfig remove the GetUsernameFromContext check or return 202 on error; test will fail (wrong status).
func TestPutConfig_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	c, w := makePutConfigContext("appName", "", &models.PutConfigPayload{
		Settings: models.SettingsPayload{Expiration: map[string]int{"targets": 365}},
	})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PutConfig(c, client)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 when username is missing from context")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
}

// To verify: In PutConfig change the appName empty check to return 202; test will fail (wrong status).
func TestPutConfig_MissingAppName_ReturnsBadRequest(t *testing.T) {
	c, w := makePutConfigContext("", "owner", &models.PutConfigPayload{
		Settings: models.SettingsPayload{Expiration: map[string]int{"targets": 365}},
	})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PutConfig(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when appName is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "appName query parameter is required", body["error"])
}

// To verify: In PutConfig change the bootstrap-missing branch to return 202; test will fail (wrong status).
func TestPutConfig_BootstrapMissing_ReturnsNotFound(t *testing.T) {
	c, w := makePutConfigContext("appName", "owner", &models.PutConfigPayload{
		Settings: models.SettingsPayload{Expiration: map[string]int{"targets": 365}},
	})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PutConfig(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap key is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "No Repository Settings/Config found")
}

// To verify: In PutConfig change ShouldBindJSON error branch to return 202; test will fail (wrong status).
func TestPutConfig_InvalidJSON_ReturnsBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/tuf/v1/config?appName=appName", bytes.NewReader([]byte("not json")))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "owner")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")

	PutConfig(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when payload is invalid JSON")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Invalid payload format")
}

// To verify: In PutConfig remove the empty Expiration check or return 202; test will fail (wrong status).
func TestPutConfig_EmptyExpiration_ReturnsBadRequest(t *testing.T) {
	c, w := makePutConfigContext("appName", "owner", &models.PutConfigPayload{
		Settings: models.SettingsPayload{Expiration: map[string]int{}},
	})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")

	PutConfig(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when no role provided for expiration")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "No role provided for expiration policy change", body["error"])
}

// To verify: In PutConfig change redisClient.Set key or value; test will fail (wrong key/value in Redis).
func TestPutConfig_Success_ValidRole_UpdatesRedisAndReturns202(t *testing.T) {
	c, w := makePutConfigContext("appName", "owner", &models.PutConfigPayload{
		Settings: models.SettingsPayload{Expiration: map[string]int{"targets": 365}},
	})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")
	mr.Set("TARGETS_EXPIRATION_owner_appName", "90") // existing value

	PutConfig(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code, "Expected 202 on success")
	var resp models.PutConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Settings successfully submitted.", resp.Message)
	assert.NotEmpty(t, resp.Data.TaskID)
	val, err := mr.Get("TARGETS_EXPIRATION_owner_appName")
	require.NoError(t, err)
	assert.Equal(t, "365", val, "Redis expiration key should be updated to new value")
}

// To verify: In PutConfig change SaveTaskStatus key prefix or skip call; test will fail (task key not found or wrong state).
func TestPutConfig_Success_TaskSavedToRedis(t *testing.T) {
	c, w := makePutConfigContext("appName", "owner", &models.PutConfigPayload{
		Settings: models.SettingsPayload{Expiration: map[string]int{"snapshot": 30}},
	})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")
	mr.Set("SNAPSHOT_EXPIRATION_owner_appName", "60")

	PutConfig(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code)
	var resp models.PutConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	taskKey := "task:" + resp.Data.TaskID
	raw, err := mr.Get(taskKey)
	require.NoError(t, err, "Task status should be saved to Redis under task:<task_id>")
	var taskStatus tasks.TaskStatus
	require.NoError(t, json.Unmarshal([]byte(raw), &taskStatus))
	assert.Equal(t, tasks.TaskStateSuccess, taskStatus.State)
	require.NotNil(t, taskStatus.Result)
	assert.Equal(t, "Update Settings Succeeded", *taskStatus.Result.Message)
}

// To verify: In PutConfig add "bins" to validOnlineRoles or remove invalid role check; test will fail (wrong invalid_roles).
func TestPutConfig_InvalidRole_NotUpdated_InvalidRolesList(t *testing.T) {
	c, w := makePutConfigContext("appName", "owner", &models.PutConfigPayload{
		Settings: models.SettingsPayload{Expiration: map[string]int{"bins": 30, "root": 365}},
	})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")

	PutConfig(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code)
	var resp models.PutConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	// Both bins and root are invalid; no role updated
	taskKey := "task:" + resp.Data.TaskID
	raw, err := mr.Get(taskKey)
	require.NoError(t, err)
	var taskStatus tasks.TaskStatus
	require.NoError(t, json.Unmarshal([]byte(raw), &taskStatus))
	details := taskStatus.Result.Details
	invalidRoles, ok := details["invalid_roles"].([]interface{})
	require.True(t, ok)
	assert.Len(t, invalidRoles, 2, "Both bins and root should be in invalid_roles")
	assert.Contains(t, invalidRoles, "bins")
	assert.Contains(t, invalidRoles, "root")
}

// To verify: In PutConfig skip the Redis Get check for existing expiration key; test will fail (role would be "updated" or wrong invalid list).
func TestPutConfig_RoleNotInRedis_InvalidRoles(t *testing.T) {
	c, w := makePutConfigContext("appName", "owner", &models.PutConfigPayload{
		Settings: models.SettingsPayload{Expiration: map[string]int{"targets": 365}},
	})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")

	PutConfig(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code)
	taskKey := ""
	var resp models.PutConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	taskKey = "task:" + resp.Data.TaskID
	raw, err := mr.Get(taskKey)
	require.NoError(t, err)
	var taskStatus tasks.TaskStatus
	require.NoError(t, json.Unmarshal([]byte(raw), &taskStatus))
	details := taskStatus.Result.Details
	updatedRoles, ok := details["updated_roles"].([]interface{})
	require.True(t, ok)
	assert.Len(t, updatedRoles, 0, "targets should be invalid because key does not exist in Redis")
	invalidRoles, ok := details["invalid_roles"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, invalidRoles, "targets")
}

// To verify: In PutConfig change message when len(updatedRoles)==0 and len(invalidRoles)>0; test will fail (wrong message or status).
func TestPutConfig_AllInvalid_UpdateSettingsFailed(t *testing.T) {
	c, w := makePutConfigContext("appName", "owner", &models.PutConfigPayload{
		Settings: models.SettingsPayload{Expiration: map[string]int{"bins": 30}},
	})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")

	PutConfig(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code)
	var resp models.PutConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	raw, err := mr.Get("task:" + resp.Data.TaskID)
	require.NoError(t, err)
	var taskStatus tasks.TaskStatus
	require.NoError(t, json.Unmarshal([]byte(raw), &taskStatus))
	assert.Equal(t, "Update Settings Failed", *taskStatus.Result.Message)
	require.NotNil(t, taskStatus.Result.Error)
	assert.Equal(t, "No valid roles were updated", *taskStatus.Result.Error)
	require.NotNil(t, taskStatus.Result.Status)
	assert.False(t, *taskStatus.Result.Status)
}

// To verify: In PutConfig change valid role update logic so both roles use same key; test will fail (wrong Redis values).
func TestPutConfig_PartialSuccess_SomeValidSomeInvalid(t *testing.T) {
	c, w := makePutConfigContext("appName", "owner", &models.PutConfigPayload{
		Settings: models.SettingsPayload{
			Expiration: map[string]int{
				"targets":  365,
				"snapshot": 30,
				"bins":     7, // invalid role
			},
		},
	})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_owner_appName", "done")
	mr.Set("TARGETS_EXPIRATION_owner_appName", "90")
	mr.Set("SNAPSHOT_EXPIRATION_owner_appName", "60")

	PutConfig(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code)
	targetsVal, err := mr.Get("TARGETS_EXPIRATION_owner_appName")
	require.NoError(t, err)
	assert.Equal(t, "365", targetsVal)
	snapshotVal, err := mr.Get("SNAPSHOT_EXPIRATION_owner_appName")
	require.NoError(t, err)
	assert.Equal(t, "30", snapshotVal)
	var resp models.PutConfigResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	raw, err := mr.Get("task:" + resp.Data.TaskID)
	require.NoError(t, err)
	var taskStatus tasks.TaskStatus
	require.NoError(t, json.Unmarshal([]byte(raw), &taskStatus))
	details := taskStatus.Result.Details
	updatedRoles, ok := details["updated_roles"].([]interface{})
	require.True(t, ok)
	assert.Len(t, updatedRoles, 2)
	assert.Contains(t, updatedRoles, "targets")
	assert.Contains(t, updatedRoles, "snapshot")
	invalidRoles, ok := details["invalid_roles"].([]interface{})
	require.True(t, ok)
	assert.Len(t, invalidRoles, 1)
	assert.Contains(t, invalidRoles, "bins")
}
