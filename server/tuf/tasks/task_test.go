package tasks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeGetTaskContext creates a gin context for GET /task with optional task_id query param.
// To verify: Change c.Query("task_id") in GetTask to return "" to make tests that expect task_id fail.
func makeGetTaskContext(taskID string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/tuf/v1/task"
	if taskID != "" {
		url += "?task_id=" + taskID
	}
	c.Request = httptest.NewRequest(http.MethodGet, url, nil)
	return c, w
}

// To verify: Modify GetTask to return 200 instead of 400 when task_id is missing (e.g. remove the empty check)
func TestGetTask_MissingTaskID_ReturnsBadRequest(t *testing.T) {
	c, w := makeGetTaskContext("")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	GetTask(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when task_id is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "task_id query parameter is required", body["error"])
}

// To verify: Modify GetTask to not check redisClient == nil; test will fail (wrong status or no error key)
func TestGetTask_NilRedisClient_ReturnsServiceUnavailable(t *testing.T) {
	c, w := makeGetTaskContext("task-123")

	GetTask(c, nil)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Expected 503 when Redis client is nil")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Redis client is not available", body["error"])
}

// To verify: In GetTask change redis.Nil branch to return state SUCCESS or another state; test will fail
func TestGetTask_TaskNotFound_ReturnsPending(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	c, w := makeGetTaskContext("nonexistent-task")

	GetTask(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "nonexistent-task", resp.Data.TaskID)
	assert.Equal(t, TaskStatePending, resp.Data.State)
	assert.Nil(t, resp.Data.Result)
	assert.Equal(t, "Task state.", resp.Message)
}

// To verify: In GetTask change the non-nil err branch to return 200; test will fail
func TestGetTask_RedisError_ReturnsInternalServerError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close() // cause Get to fail
	c, w := makeGetTaskContext("task-123")

	GetTask(c, client)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Failed to retrieve task status", body["error"])
}

// To verify: In GetTask change json.Unmarshal error branch to return 200; test will fail
func TestGetTask_InvalidJSONInRedis_ReturnsInternalServerError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("task:bad-json", "not valid json {{{")
	c, w := makeGetTaskContext("bad-json")

	GetTask(c, client)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Failed to parse task status", body["error"])
}

// To verify: In GetTask change the success response (e.g. state or task_id); test will fail
func TestGetTask_ValidTaskSuccess_ReturnsTaskState(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	status := true
	ts := TaskStatus{
		State: TaskStateSuccess,
		Result: &TaskResult{
			Status: &status,
		},
	}
	data, err := json.Marshal(ts)
	require.NoError(t, err)
	mr.Set("task:success-task", string(data))
	c, w := makeGetTaskContext("success-task")

	GetTask(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "success-task", resp.Data.TaskID)
	assert.Equal(t, TaskStateSuccess, resp.Data.State)
	require.NotNil(t, resp.Data.Result)
	require.NotNil(t, resp.Data.Result.Status)
	assert.True(t, *resp.Data.Result.Status)
}

// To verify: In GetTask remove the special case that sets state to ERRORED when State==SUCCESS and Status==false; test will fail (state will stay SUCCESS)
func TestGetTask_SuccessWithStatusFalse_ReturnsErrored(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	statusFalse := false
	ts := TaskStatus{
		State: TaskStateSuccess,
		Result: &TaskResult{
			Status: &statusFalse,
		},
	}
	data, err := json.Marshal(ts)
	require.NoError(t, err)
	mr.Set("task:success-false-task", string(data))
	c, w := makeGetTaskContext("success-false-task")

	GetTask(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "success-false-task", resp.Data.TaskID)
	assert.Equal(t, TaskStateErrored, resp.Data.State, "SUCCESS with status false should be mapped to ERRORED")
	require.NotNil(t, resp.Data.Result)
	require.NotNil(t, resp.Data.Result.Status)
	assert.False(t, *resp.Data.Result.Status)
}

// To verify: In GetTask change response message or omit result; test will fail
func TestGetTask_ResultWithErrorString_ReturnsResultWithError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	errMsg := "something went wrong"
	ts := TaskStatus{
		State: TaskStateErrored,
		Result: &TaskResult{
			Error: &errMsg,
		},
	}
	data, err := json.Marshal(ts)
	require.NoError(t, err)
	mr.Set("task:error-task", string(data))
	c, w := makeGetTaskContext("error-task")

	GetTask(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "error-task", resp.Data.TaskID)
	assert.Equal(t, TaskStateErrored, resp.Data.State)
	require.NotNil(t, resp.Data.Result)
	require.NotNil(t, resp.Data.Result.Error)
	assert.Equal(t, "something went wrong", *resp.Data.Result.Error)
}

// To verify: In GetTask change key prefix from "task:" to something else; test will fail (task not found -> PENDING with wrong key semantics)
func TestGetTask_UsesCorrectRedisKey(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ts := TaskStatus{State: TaskStateReceived, Result: &TaskResult{}}
	data, err := json.Marshal(ts)
	require.NoError(t, err)
	mr.Set("task:my-id", string(data))
	c, w := makeGetTaskContext("my-id")

	GetTask(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "my-id", resp.Data.TaskID)
	assert.Equal(t, TaskStateReceived, resp.Data.State)
}

// --- SaveTaskStatus tests ---

// To verify: In SaveTaskStatus remove the nil client check and return an error; test will fail (non-nil error)
func TestSaveTaskStatus_NilRedisClient_ReturnsNil(t *testing.T) {
	err := SaveTaskStatus(nil, "task-1", TaskStatePending, nil)
	assert.NoError(t, err, "SaveTaskStatus should return nil when Redis client is nil (silent skip)")
}

// To verify: In SaveTaskStatus change taskKey prefix from "task:" to something else; test will fail (key not found)
func TestSaveTaskStatus_Success_StoresUnderCorrectKey(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "save-task-1"
	state := TaskStateSuccess
	status := true
	result := &TaskResult{Status: &status}

	err := SaveTaskStatus(client, taskID, state, result)
	require.NoError(t, err)

	key := "task:" + taskID
	got, err := mr.Get(key)
	require.NoError(t, err)
	var stored TaskStatus
	require.NoError(t, json.Unmarshal([]byte(got), &stored))
	assert.Equal(t, state, stored.State)
	require.NotNil(t, stored.Result)
	require.NotNil(t, stored.Result.Status)
	assert.True(t, *stored.Result.Status)
	require.NotNil(t, stored.Result.LastUpdate, "LastUpdate should be set when result exists")
}

// To verify: In SaveTaskStatus remove the branch that creates empty Result for non-PENDING; test will fail (nil Result or no LastUpdate)
func TestSaveTaskStatus_NilResultNonPending_CreatesEmptyResultWithLastUpdate(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "empty-result-task"
	state := TaskStateReceived

	err := SaveTaskStatus(client, taskID, state, nil)
	require.NoError(t, err)

	got, err := mr.Get("task:" + taskID)
	require.NoError(t, err)
	var stored TaskStatus
	require.NoError(t, json.Unmarshal([]byte(got), &stored))
	assert.Equal(t, state, stored.State)
	require.NotNil(t, stored.Result, "Result should be created when state is not PENDING and result is nil")
	require.NotNil(t, stored.Result.LastUpdate)
}

// To verify: In SaveTaskStatus change the PENDING+nil result handling (e.g. create Result); test will fail
func TestSaveTaskStatus_NilResultPending_StoresStateOnly(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "pending-no-result"
	state := TaskStatePending

	err := SaveTaskStatus(client, taskID, state, nil)
	require.NoError(t, err)

	got, err := mr.Get("task:" + taskID)
	require.NoError(t, err)
	var stored TaskStatus
	require.NoError(t, json.Unmarshal([]byte(got), &stored))
	assert.Equal(t, state, stored.State)
	assert.Nil(t, stored.Result, "Result should remain nil for PENDING with nil result")
}

// To verify: In SaveTaskStatus change redis Set to use a different key; test will fail
func TestSaveTaskStatus_RedisSetError_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close()

	err := SaveTaskStatus(client, "task-1", TaskStateSuccess, &TaskResult{})

	require.Error(t, err)
}

// --- UpdateTaskState tests ---

// To verify: In UpdateTaskState remove the nil client check; test will fail (panic or wrong behavior)
func TestUpdateTaskState_NilRedisClient_ReturnsNil(t *testing.T) {
	err := UpdateTaskState(nil, "task-1", TaskStateSuccess)
	assert.NoError(t, err, "UpdateTaskState should return nil when Redis client is nil")
}

// To verify: In UpdateTaskState change redis.Nil branch to not create Result or not set LastUpdate; test will fail
func TestUpdateTaskState_TaskNotFound_CreatesNewTaskWithState(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "new-task-update"
	state := TaskStateStarted

	err := UpdateTaskState(client, taskID, state)
	require.NoError(t, err)

	got, err := mr.Get("task:" + taskID)
	require.NoError(t, err)
	var stored TaskStatus
	require.NoError(t, json.Unmarshal([]byte(got), &stored))
	assert.Equal(t, state, stored.State)
	require.NotNil(t, stored.Result, "Result should be created for new task")
	require.NotNil(t, stored.Result.LastUpdate)
}

// To verify: In UpdateTaskState change the existing-task branch (e.g. do not update state); test will fail
func TestUpdateTaskState_TaskExists_UpdatesStatePreservesResult(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "existing-task"
	msg := "original message"
	orig := TaskStatus{
		State: TaskStateReceived,
		Result: &TaskResult{
			Message: &msg,
		},
	}
	data, err := json.Marshal(orig)
	require.NoError(t, err)
	mr.Set("task:"+taskID, string(data))

	newState := TaskStateSuccess
	err = UpdateTaskState(client, taskID, newState)
	require.NoError(t, err)

	got, err := mr.Get("task:" + taskID)
	require.NoError(t, err)
	var stored TaskStatus
	require.NoError(t, json.Unmarshal([]byte(got), &stored))
	assert.Equal(t, newState, stored.State)
	require.NotNil(t, stored.Result)
	require.NotNil(t, stored.Result.Message)
	assert.Equal(t, "original message", *stored.Result.Message)
	require.NotNil(t, stored.Result.LastUpdate)
}

// To verify: In UpdateTaskState change taskKey prefix; test will fail (key not found or wrong key)
func TestUpdateTaskState_UsesCorrectRedisKey(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "key-check-task"

	err := UpdateTaskState(client, taskID, TaskStateRunning)
	require.NoError(t, err)

	_, err = mr.Get("task:" + taskID)
	require.NoError(t, err)
}

// To verify: In UpdateTaskState change the Get error branch to return nil; test will fail
func TestUpdateTaskState_RedisGetError_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close()

	err := UpdateTaskState(client, "task-1", TaskStateSuccess)

	require.Error(t, err)
}

// To verify: In UpdateTaskState change unmarshal error handling to return nil; test will fail
func TestUpdateTaskState_InvalidJSONInRedis_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("task:bad-json", "not valid json")

	err := UpdateTaskState(client, "bad-json", TaskStateSuccess)

	require.Error(t, err)
}

// To verify: In UpdateTaskState change Set error handling to return nil; test will fail
func TestUpdateTaskState_RedisSetError_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "set-error-task"
	mr.Set("task:"+taskID, `{"state":"RECEIVED","result":{}}`)

	mr.Close()

	err := UpdateTaskState(client, taskID, TaskStateSuccess)

	require.Error(t, err)
}

// --- UpdateTaskResult tests ---

// To verify: In UpdateTaskResult remove the nil client check; test will fail
func TestUpdateTaskResult_NilRedisClient_ReturnsNil(t *testing.T) {
	err := UpdateTaskResult(nil, "task-1", &TaskResult{})
	assert.NoError(t, err, "UpdateTaskResult should return nil when Redis client is nil")
}

// To verify: In UpdateTaskResult change redis.Nil branch (e.g. use different state); test will fail
func TestUpdateTaskResult_TaskNotFound_CreatesNewTaskWithPendingState(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "new-result-task"
	msg := "task result message"
	result := &TaskResult{Message: &msg}

	err := UpdateTaskResult(client, taskID, result)
	require.NoError(t, err)

	got, err := mr.Get("task:" + taskID)
	require.NoError(t, err)
	var stored TaskStatus
	require.NoError(t, json.Unmarshal([]byte(got), &stored))
	assert.Equal(t, TaskStatePending, stored.State)
	require.NotNil(t, stored.Result)
	require.NotNil(t, stored.Result.Message)
	assert.Equal(t, "task result message", *stored.Result.Message)
	require.NotNil(t, stored.Result.LastUpdate)
}

// To verify: In UpdateTaskResult change the existing-task branch (e.g. overwrite state); test will fail
func TestUpdateTaskResult_TaskExists_UpdatesResultPreservesState(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "existing-result-task"
	mr.Set("task:"+taskID, `{"state":"RUNNING","result":{"message":"old"}}`)

	msg := "new result"
	result := &TaskResult{Message: &msg}
	err := UpdateTaskResult(client, taskID, result)
	require.NoError(t, err)

	got, err := mr.Get("task:" + taskID)
	require.NoError(t, err)
	var stored TaskStatus
	require.NoError(t, json.Unmarshal([]byte(got), &stored))
	assert.Equal(t, TaskStateRunning, stored.State, "State should be preserved")
	require.NotNil(t, stored.Result)
	require.NotNil(t, stored.Result.Message)
	assert.Equal(t, "new result", *stored.Result.Message)
	require.NotNil(t, stored.Result.LastUpdate)
}

// To verify: In UpdateTaskResult change taskKey prefix; test will fail
func TestUpdateTaskResult_UsesCorrectRedisKey(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "result-key-task"

	err := UpdateTaskResult(client, taskID, &TaskResult{})
	require.NoError(t, err)

	_, err = mr.Get("task:" + taskID)
	require.NoError(t, err)
}

// To verify: In UpdateTaskResult when result is nil, LastUpdate is not set; stored result is nil
func TestUpdateTaskResult_NilResult_StoresWithoutLastUpdate(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "nil-result-task"
	mr.Set("task:"+taskID, `{"state":"SUCCESS","result":{"message":"before"}}`)

	err := UpdateTaskResult(client, taskID, nil)
	require.NoError(t, err)

	got, err := mr.Get("task:" + taskID)
	require.NoError(t, err)
	var stored TaskStatus
	require.NoError(t, json.Unmarshal([]byte(got), &stored))
	assert.Equal(t, TaskStateSuccess, stored.State)
	assert.Nil(t, stored.Result, "Result should be nil when updated with nil result")
}

// To verify: In UpdateTaskResult change Get error branch to return nil; test will fail
func TestUpdateTaskResult_RedisGetError_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close()

	err := UpdateTaskResult(client, "task-1", &TaskResult{})

	require.Error(t, err)
}

// To verify: In UpdateTaskResult change unmarshal error handling to return nil; test will fail
func TestUpdateTaskResult_InvalidJSONInRedis_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("task:bad-json", "not valid json")

	err := UpdateTaskResult(client, "bad-json", &TaskResult{})

	require.Error(t, err)
}

// To verify: In UpdateTaskResult change Set error handling to return nil; test will fail
func TestUpdateTaskResult_RedisSetError_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	taskID := "result-set-error"
	mr.Set("task:"+taskID, `{"state":"RECEIVED","result":{}}`)

	mr.Close()

	err := UpdateTaskResult(client, taskID, &TaskResult{})

	require.Error(t, err)
}
