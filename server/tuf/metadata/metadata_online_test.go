package metadata

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"faynoSync/server/tuf/models"
	"faynoSync/server/tuf/signing"
	tuf_storage "faynoSync/server/tuf/storage"
	"faynoSync/server/tuf/tasks"
	tuf_utils "faynoSync/server/tuf/utils"
	"faynoSync/server/utils"
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

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// To verify: Change c.Query("appName") or c.ShouldBindJSON in PostMetadataOnline; test will fail (wrong status/body).
func makePostMetadataOnlineContext(username string, appName string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/tuf/v1/metadata/online"
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

func waitForOnlineTaskTerminalState(t *testing.T, redisClient *redis.Client, taskID string, timeout time.Duration) {
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

// To verify: In PostMetadataOnline remove the root-role check or return 200; test will fail (wrong status).
func TestPostMetadataOnline_RootRoleInPayload_ReturnsBadRequest(t *testing.T) {
	c, w := makePostMetadataOnlineContext("admin", "myapp", models.MetadataOnlinePostPayload{Roles: []string{"root"}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")

	PostMetadataOnline(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when root is in roles")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Root role cannot be updated via this endpoint", body["error"])
}

// To verify: In PostMetadataOnline remove GetUsernameFromContext check or return 200 on error; test will fail (wrong status).
func TestPostMetadataOnline_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	c, w := makePostMetadataOnlineContext("", "myapp", models.MetadataOnlinePostPayload{Roles: []string{"snapshot", "timestamp"}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostMetadataOnline(c, client)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 when username is missing from context")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
}

// To verify: In PostMetadataOnline change appName empty check to return 200 or remove it; test will fail (wrong status).
func TestPostMetadataOnline_MissingAppName_ReturnsBadRequest(t *testing.T) {
	c, w := makePostMetadataOnlineContext("admin", "", models.MetadataOnlinePostPayload{Roles: []string{"snapshot", "timestamp"}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_", "done")

	PostMetadataOnline(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when appName is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "appName query parameter is required", body["error"])
}

// To verify: In PostMetadataOnline remove nil Redis check or return 200; test will fail (wrong status or panic).
func TestPostMetadataOnline_NilRedis_ReturnsServiceUnavailable(t *testing.T) {
	c, w := makePostMetadataOnlineContext("admin", "myapp", models.MetadataOnlinePostPayload{Roles: []string{"snapshot", "timestamp"}})

	PostMetadataOnline(c, nil)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Expected 503 when Redis client is nil")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Redis client is not available", body["error"])
}

// To verify: In PostMetadataOnline ignore ShouldBindJSON error or return 200; test will fail (wrong status).
func TestPostMetadataOnline_InvalidJSON_ReturnsBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/metadata/online?appName=myapp", bytes.NewReader([]byte("not json")))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "admin")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")

	PostMetadataOnline(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when body is invalid JSON")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Invalid payload format")
}

// To verify: In PostMetadataOnline remove bootstrap-missing branch or return 200; test will fail (wrong status).
func TestPostMetadataOnline_BootstrapMissing_ReturnsNotFound(t *testing.T) {
	c, w := makePostMetadataOnlineContext("admin", "myapp", models.MetadataOnlinePostPayload{Roles: []string{"snapshot", "timestamp"}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostMetadataOnline(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap key is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Task not accepted.", body["message"])
	assert.Contains(t, body["error"], "Requires bootstrap finished")
}

// To verify: In PostMetadataOnline remove bootstrapValue == "" condition; test will fail (wrong status).
func TestPostMetadataOnline_BootstrapEmpty_ReturnsNotFound(t *testing.T) {
	c, w := makePostMetadataOnlineContext("admin", "myapp", models.MetadataOnlinePostPayload{Roles: []string{"snapshot", "timestamp"}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "")

	PostMetadataOnline(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap value is empty")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Task not accepted.", body["message"])
	assert.Contains(t, body["error"], "Requires bootstrap finished")
}

// To verify: In PostMetadataOnline remove the targets-offline check (contains(payload.Roles, "targets") && !targetsOnline); test will fail (wrong status).
func TestPostMetadataOnline_TargetsInPayloadButTargetsOffline_ReturnsNotFound(t *testing.T) {
	c, w := makePostMetadataOnlineContext("admin", "myapp", models.MetadataOnlinePostPayload{Roles: []string{"targets", "snapshot", "timestamp"}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")
	mr.Set("TARGETS_ONLINE_KEY_admin_myapp", "false")

	PostMetadataOnline(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when targets is in payload but targets is offline role")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Task not accepted.", body["message"])
	assert.Equal(t, "Targets is an offline role - use other endpoint to update", body["error"])
}

// To verify: In PostMetadataOnline change TARGETS_ONLINE_KEY check so "1" or "True" are not accepted; test will fail (wrong status).
func TestPostMetadataOnline_TargetsOnlineKeyVariants_Accepted(t *testing.T) {
	tests := []struct {
		name           string
		targetsKeyVal  string
		roles          []string
		expectAccepted bool
	}{
		{"true_lower", "true", []string{"targets", "snapshot", "timestamp"}, true},
		{"1", "1", []string{"targets", "snapshot", "timestamp"}, true},
		{"True_mixed", "True", []string{"targets", "snapshot", "timestamp"}, true},
		{"key_missing_defaults_true", "", []string{"targets", "snapshot", "timestamp"}, true},
		{"false_rejected", "false", []string{"targets", "snapshot", "timestamp"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, w := makePostMetadataOnlineContext("admin", "myapp", models.MetadataOnlinePostPayload{Roles: tt.roles})
			mr := miniredis.RunT(t)
			defer mr.Close()
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			mr.Set("BOOTSTRAP_admin_myapp", "done")
			if tt.targetsKeyVal != "" {
				mr.Set("TARGETS_ONLINE_KEY_admin_myapp", tt.targetsKeyVal)
			}

			PostMetadataOnline(c, client)

			if tt.expectAccepted {
				assert.Equal(t, http.StatusAccepted, w.Code, "Expected 202 when targets online key allows targets")
				var resp models.MetadataOnlinePostResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
				assert.NotEmpty(t, resp.Data.TaskID, "task_id should be set")
				assert.Equal(t, "Force online metadata update accepted.", resp.Message)
				waitForOnlineTaskTerminalState(t, client, resp.Data.TaskID, 5*time.Second)
			} else {
				assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when targets is offline")
			}
		})
	}
}

// To verify: In PostMetadataOnline change success response (StatusAccepted, message, or data shape); test will fail (wrong code/body).
func TestPostMetadataOnline_Success_AcceptedWithTaskID(t *testing.T) {
	c, w := makePostMetadataOnlineContext("admin", "myapp", models.MetadataOnlinePostPayload{Roles: []string{"snapshot", "timestamp"}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")

	PostMetadataOnline(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code, "Expected 202 when request is accepted")
	var resp models.MetadataOnlinePostResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Data.TaskID, "task_id should be non-empty UUID")
	assert.False(t, resp.Data.LastUpdate.IsZero(), "last_update should be set")
	assert.Equal(t, "Force online metadata update accepted.", resp.Message)
	waitForOnlineTaskTerminalState(t, client, resp.Data.TaskID, 5*time.Second)
}

// To verify: In PostMetadataOnline change default roles when payload.Roles is empty (e.g. omit "targets" when targetsOnline); test will fail (wrong behavior in goroutine; we only assert 202 here).
func TestPostMetadataOnline_EmptyRoles_DefaultsAccepted(t *testing.T) {
	c, w := makePostMetadataOnlineContext("admin", "myapp", models.MetadataOnlinePostPayload{Roles: nil})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")

	PostMetadataOnline(c, client)

	assert.Equal(t, http.StatusAccepted, w.Code, "Expected 202 when empty roles use defaults")
	var resp models.MetadataOnlinePostResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Data.TaskID)
	assert.Equal(t, "Force online metadata update accepted.", resp.Message)
	waitForOnlineTaskTerminalState(t, client, resp.Data.TaskID, 5*time.Second)
}

// --- forceOnlineMetadataUpdate tests ---

type storageMockClientForForceUpdate struct {
	body []byte
}

func (c *storageMockClientForForceUpdate) DownloadObject(ctx context.Context, bucketName, objectKey, filePath string) error {
	if c.body == nil {
		return fmt.Errorf("mock download error")
	}
	return os.WriteFile(filePath, c.body, 0644)
}

func (c *storageMockClientForForceUpdate) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	_, _ = io.Copy(io.Discard, fileReader)
	return nil
}

func (c *storageMockClientForForceUpdate) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	_, _ = io.Copy(io.Discard, fileReader)
	return "", nil
}

func (c *storageMockClientForForceUpdate) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	panic("not used")
}

func (c *storageMockClientForForceUpdate) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	panic("not used")
}

func (c *storageMockClientForForceUpdate) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	panic("not used")
}

// multiBodyDownloadMock returns different body by filename (last segment of objectKey). Used for bumpDelegatedRoles tests.
type multiBodyDownloadMock struct {
	bodies map[string][]byte
}

func (c *multiBodyDownloadMock) DownloadObject(ctx context.Context, bucketName, objectKey, filePath string) error {
	const sep = "/"
	i := strings.LastIndex(objectKey, sep)
	filename := objectKey
	if i >= 0 {
		filename = objectKey[i+len(sep):]
	}
	body, ok := c.bodies[filename]
	if !ok {
		return fmt.Errorf("mock: no body for %q", filename)
	}
	return os.WriteFile(filePath, body, 0644)
}

func (c *multiBodyDownloadMock) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	_, _ = io.Copy(io.Discard, fileReader)
	return nil
}

func (c *multiBodyDownloadMock) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	_, _ = io.Copy(io.Discard, fileReader)
	return "", nil
}

func (c *multiBodyDownloadMock) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	panic("not used")
}

func (c *multiBodyDownloadMock) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	panic("not used")
}

func (c *multiBodyDownloadMock) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	panic("not used")
}

func makeRootAndOnlineKeysForForceUpdate(t *testing.T) (rootJSON []byte, keyDir string, cleanup func()) {
	t.Helper()
	rootTmp := t.TempDir()
	keyDir = t.TempDir()

	expires := time.Now().Add(365 * 24 * time.Hour)
	roles := repository.New()
	keys := map[string]ed25519.PrivateKey{}

	roles.SetRoot(tuf_metadata.Root(expires))
	roles.SetTargets("targets", tuf_metadata.Targets(expires))
	roles.SetSnapshot(tuf_metadata.Snapshot(expires))
	roles.SetTimestamp(tuf_metadata.Timestamp(expires))

	for _, name := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, private, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		keys[name] = private
		key, err := tuf_metadata.KeyFromPublicKey(private.Public())
		require.NoError(t, err)
		err = roles.Root().Signed.AddKey(key, name)
		require.NoError(t, err)
	}

	for _, name := range []string{"root", "targets", "snapshot", "timestamp"} {
		signer, err := signature.LoadSigner(keys[name], crypto.Hash(0))
		require.NoError(t, err)
		switch name {
		case "root":
			_, err = roles.Root().Sign(signer)
		case "targets":
			_, err = roles.Targets("targets").Sign(signer)
		case "snapshot":
			_, err = roles.Snapshot().Sign(signer)
		case "timestamp":
			_, err = roles.Timestamp().Sign(signer)
		}
		require.NoError(t, err)
	}

	rootPath := filepath.Join(rootTmp, "1.root.json")
	err := roles.Root().ToFile(rootPath, true)
	require.NoError(t, err)

	rootJSON, err = os.ReadFile(rootPath)
	require.NoError(t, err)

	var rootMeta models.RootMetadata
	require.NoError(t, json.Unmarshal(rootJSON, &rootMeta))

	for _, name := range []string{"timestamp", "snapshot", "targets"} {
		role, ok := rootMeta.Signed.Roles[name]
		require.True(t, ok, "role %s in root", name)
		require.NotEmpty(t, role.KeyIDs, "key ID for %s", name)
		keyID := role.KeyIDs[0]
		seed := keys[name].Seed()
		require.NoError(t, os.WriteFile(filepath.Join(keyDir, keyID), seed, 0600))
	}

	oldDir := viper.GetViper().GetString("ONLINE_KEY_DIR")
	viper.GetViper().Set("ONLINE_KEY_DIR", keyDir)
	cleanup = func() {
		viper.GetViper().Set("ONLINE_KEY_DIR", oldDir)
	}
	return rootJSON, keyDir, cleanup
}

// To verify: In forceOnlineMetadataUpdate remove the root download error handling or return a different error; test will fail (no error or wrong message).
func TestForceOnlineMetadataUpdate_RootDownloadFails(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{err: fmt.Errorf("create client failed")}
	}
	defer func() {
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	updatedRoles, err := forceOnlineMetadataUpdate(ctx, redisClient, "admin", "app", []string{"timestamp"})

	require.Error(t, err)
	assert.Nil(t, updatedRoles)
	assert.Contains(t, err.Error(), "failed to download root metadata")
}

type forceUpdateMockFactory struct {
	client utils.StorageClient
	err    error
}

func (f *forceUpdateMockFactory) CreateStorageClient() (utils.StorageClient, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.client, nil
}

// To verify: In forceOnlineMetadataUpdate change the error message when timestamp role is missing; test will fail (wrong message).
func TestForceOnlineMetadataUpdate_TimestampRoleNotFound(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	rootNoTimestamp := models.RootMetadata{
		Signed: models.Signed{
			Type:    "root",
			Version: 1,
			Expires: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
			Keys:    map[string]models.Key{},
			Roles:   map[string]models.Role{"snapshot": {KeyIDs: []string{"sid"}, Threshold: 1}, "targets": {KeyIDs: []string{"tid"}, Threshold: 1}},
		},
	}
	rootBody, err := json.Marshal(rootNoTimestamp)
	require.NoError(t, err)

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &storageMockClientForForceUpdate{body: rootBody}}
	}
	defer func() {
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	updatedRoles, err := forceOnlineMetadataUpdate(ctx, redisClient, "admin", "app", []string{"timestamp"})

	require.Error(t, err)
	assert.Nil(t, updatedRoles)
	assert.Contains(t, err.Error(), "timestamp role not found in root metadata")
}

// To verify: In forceOnlineMetadataUpdate change the error message when snapshot role is missing; test will fail (wrong message).
func TestForceOnlineMetadataUpdate_SnapshotRoleNotFound(t *testing.T) {
	rootJSON, _, cleanup := makeRootAndOnlineKeysForForceUpdate(t)
	defer cleanup()

	// Remove snapshot from roles in root
	var rootMeta models.RootMetadata
	require.NoError(t, json.Unmarshal(rootJSON, &rootMeta))
	delete(rootMeta.Signed.Roles, "snapshot")
	rootBody, err := json.Marshal(rootMeta)
	require.NoError(t, err)

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &storageMockClientForForceUpdate{body: rootBody}}
	}
	defer func() {
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	updatedRoles, err := forceOnlineMetadataUpdate(ctx, redisClient, "admin", "app", []string{"timestamp"})

	require.Error(t, err)
	assert.Nil(t, updatedRoles)
	assert.Contains(t, err.Error(), "snapshot role not found in root metadata")
}

// To verify: In forceOnlineMetadataUpdate change the error message when targets role is missing; test will fail (wrong message).
func TestForceOnlineMetadataUpdate_TargetsRoleNotFound(t *testing.T) {
	rootJSON, _, cleanup := makeRootAndOnlineKeysForForceUpdate(t)
	defer cleanup()

	var rootMeta models.RootMetadata
	require.NoError(t, json.Unmarshal(rootJSON, &rootMeta))
	delete(rootMeta.Signed.Roles, "targets")
	rootBody, err := json.Marshal(rootMeta)
	require.NoError(t, err)

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &storageMockClientForForceUpdate{body: rootBody}}
	}
	defer func() {
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	updatedRoles, err := forceOnlineMetadataUpdate(ctx, redisClient, "admin", "app", []string{"timestamp"})

	require.Error(t, err)
	assert.Nil(t, updatedRoles)
	assert.Contains(t, err.Error(), "targets role not found in root metadata")
}

// To verify: In forceOnlineMetadataUpdate change the error message when timestamp key load fails; test will fail (wrong message).
func TestForceOnlineMetadataUpdate_TimestampKeyLoadFails(t *testing.T) {
	rootJSON, _, cleanup := makeRootAndOnlineKeysForForceUpdate(t)
	defer cleanup()

	emptyKeyDir := t.TempDir()
	viper.GetViper().Set("ONLINE_KEY_DIR", emptyKeyDir)

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &storageMockClientForForceUpdate{body: rootJSON}}
	}
	defer func() {
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	updatedRoles, err := forceOnlineMetadataUpdate(ctx, redisClient, "admin", "app", []string{"timestamp"})

	require.Error(t, err)
	assert.Nil(t, updatedRoles)
	assert.Contains(t, err.Error(), "failed to load timestamp private key")
}

// To verify: In forceOnlineMetadataUpdate change success path (e.g. return error or wrong updatedRoles); test will fail (wrong result).
func TestForceOnlineMetadataUpdate_Success_TimestampOnly(t *testing.T) {
	rootJSON, _, cleanup := makeRootAndOnlineKeysForForceUpdate(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload

	downloadClient := &storageMockClientForForceUpdate{body: rootJSON}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: downloadClient}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: downloadClient}
	}
	defer func() {
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	updatedRoles, err := forceOnlineMetadataUpdate(ctx, redisClient, "admin", "app", []string{"timestamp"})

	require.NoError(t, err)
	assert.Equal(t, []string{"timestamp"}, updatedRoles)
}

// --- bumpTargetsRole tests ---

// To verify: change root loading or key lookup; bumpTargetsRole success test will fail.
func makeRepoWithRootAndTargetsSigner(t *testing.T) (repo *repository.Type, signer signature.Signer, tmpDir string, keySuffix string, cleanup func()) {
	t.Helper()
	rootJSON, _, cleanup := makeRootAndOnlineKeysForForceUpdate(t)
	tmpDir = t.TempDir()
	rootPath := filepath.Join(tmpDir, "root.json")
	require.NoError(t, os.WriteFile(rootPath, rootJSON, 0644))

	repo = repository.New()
	expires := time.Now().Add(365 * 24 * time.Hour)
	repo.SetRoot(tuf_metadata.Root(expires))
	_, err := repo.Root().FromFile(rootPath)
	require.NoError(t, err)

	var rootMeta models.RootMetadata
	require.NoError(t, json.Unmarshal(rootJSON, &rootMeta))
	targetsRole, ok := rootMeta.Signed.Roles["targets"]
	require.True(t, ok)
	require.NotEmpty(t, targetsRole.KeyIDs)
	targetsKeyID := targetsRole.KeyIDs[0]

	priv, err := signing.LoadPrivateKeyFromFilesystem(targetsKeyID, targetsKeyID)
	require.NoError(t, err)
	signer, err = signature.LoadSigner(priv, crypto.Hash(0))
	require.NoError(t, err)

	return repo, signer, tmpDir, "admin_app", cleanup
}

// makeValidTargetsJSON produces valid signed targets metadata bytes for the given repo/signer.
func makeValidTargetsJSON(t *testing.T, repo *repository.Type, signer signature.Signer, tmpDir string) []byte {
	t.Helper()
	exp := tuf_utils.HelperExpireIn(365)
	targets := tuf_metadata.Targets(exp)
	repo.SetTargets("targets", targets)
	_, err := repo.Targets("targets").Sign(signer)
	require.NoError(t, err)
	targetsPath := filepath.Join(tmpDir, "1.targets.json")
	require.NoError(t, repo.Targets("targets").ToFile(targetsPath, true))
	data, err := os.ReadFile(targetsPath)
	require.NoError(t, err)
	return data
}

// To verify: In bumpTargetsRole remove the FindLatestMetadataVersion error handling or return a different error; test will fail (no error or wrong message).
func TestBumpTargetsRole_FindLatestFails(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("list failed")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	err := bumpTargetsRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find latest targets version")
}

// To verify: In bumpTargetsRole remove the DownloadMetadataFromS3 error handling or return a different error; test will fail (no error or wrong message).
func TestBumpTargetsRole_DownloadFails(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{err: fmt.Errorf("create client failed")}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	err := bumpTargetsRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to download targets metadata")
}

// To verify: In bumpTargetsRole remove the FromFile error handling or return a different error; test will fail (no error or wrong message).
func TestBumpTargetsRole_LoadTargetsFails(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// Invalid JSON so repo.Targets("targets").FromFile fails when parsing
	invalidTargetsBody := []byte(`not valid targets json`)
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &storageMockClientForForceUpdate{body: invalidTargetsBody}}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &storageMockClientForForceUpdate{body: invalidTargetsBody}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	err := bumpTargetsRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load targets metadata")
}

// To verify: In bumpTargetsRole remove the UploadMetadataToS3 error handling or return a different error; test will fail (no error or wrong message).
func TestBumpTargetsRole_UploadFails(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	targetsJSON := makeValidTargetsJSON(t, repo, signer, tmpDir)

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload

	downloadClient := &storageMockClientForForceUpdate{body: targetsJSON}
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: downloadClient}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{err: fmt.Errorf("upload client failed")}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	err := bumpTargetsRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to upload targets metadata to S3")
}

// To verify: In bumpTargetsRole change success path (e.g. return error or wrong version); test will fail (wrong result).
func TestBumpTargetsRole_Success(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	targetsJSON := makeValidTargetsJSON(t, repo, signer, tmpDir)

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload

	client := &storageMockClientForForceUpdate{body: targetsJSON}
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	err := bumpTargetsRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.NoError(t, err)
	// Version was 1, after bump it should be 2
	assert.Equal(t, int64(2), repo.Targets("targets").Signed.Version)
}

// --- bumpDelegatedRoles tests ---

func makeTargetsWithDelegationsButNoRoles(t *testing.T, repo *repository.Type, signer signature.Signer, tmpDir string) []byte {
	t.Helper()
	exp := tuf_utils.HelperExpireIn(365)
	targets := tuf_metadata.Targets(exp)
	targets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys:  map[string]*tuf_metadata.Key{},
		Roles: []tuf_metadata.DelegatedRole{},
	}
	repo.SetTargets("targets", targets)
	_, err := repo.Targets("targets").Sign(signer)
	require.NoError(t, err)
	targetsPath := filepath.Join(tmpDir, "1.targets.json")
	require.NoError(t, repo.Targets("targets").ToFile(targetsPath, true))
	data, err := os.ReadFile(targetsPath)
	require.NoError(t, err)
	return data
}

func makeTargetsAndDelegationForBumpDelegated(t *testing.T, delegationRoleName string) (targetsJSON, delegationJSON []byte, keyDir string, cleanup func()) {
	t.Helper()
	rootJSON, keyDir, cleanup := makeRootAndOnlineKeysForForceUpdate(t)
	tmpDir := t.TempDir()
	rootPath := filepath.Join(tmpDir, "root.json")
	require.NoError(t, os.WriteFile(rootPath, rootJSON, 0644))

	repo := repository.New()
	expires := time.Now().Add(365 * 24 * time.Hour)
	repo.SetRoot(tuf_metadata.Root(expires))
	_, err := repo.Root().FromFile(rootPath)
	require.NoError(t, err)

	var rootMeta models.RootMetadata
	require.NoError(t, json.Unmarshal(rootJSON, &rootMeta))
	targetsKeyID := rootMeta.Signed.Roles["targets"].KeyIDs[0]
	targetsPriv, err := signing.LoadPrivateKeyFromFilesystem(targetsKeyID, targetsKeyID)
	require.NoError(t, err)
	targetsSigner, err := signature.LoadSigner(targetsPriv, crypto.Hash(0))
	require.NoError(t, err)

	_, delegationPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	delegationKey, err := tuf_metadata.KeyFromPublicKey(delegationPriv.Public())
	require.NoError(t, err)
	delegationKeyID, err := delegationKey.ID()
	require.NoError(t, err)

	exp := tuf_utils.HelperExpireIn(365)
	targets := tuf_metadata.Targets(exp)
	targets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys:  map[string]*tuf_metadata.Key{delegationKeyID: delegationKey},
		Roles: []tuf_metadata.DelegatedRole{{Name: delegationRoleName, KeyIDs: []string{delegationKeyID}, Threshold: 1}},
	}
	repo.SetTargets("targets", targets)
	_, err = repo.Targets("targets").Sign(targetsSigner)
	require.NoError(t, err)
	targetsPath := filepath.Join(tmpDir, "1.targets.json")
	require.NoError(t, repo.Targets("targets").ToFile(targetsPath, true))
	targetsJSON, err = os.ReadFile(targetsPath)
	require.NoError(t, err)

	delegationSigner, err := signature.LoadSigner(delegationPriv, crypto.Hash(0))
	require.NoError(t, err)
	delegationMeta := tuf_metadata.Targets(exp)
	repo.SetTargets(delegationRoleName, delegationMeta)
	_, err = repo.Targets(delegationRoleName).Sign(delegationSigner)
	require.NoError(t, err)
	delegationPath := filepath.Join(tmpDir, "1."+delegationRoleName+".json")
	require.NoError(t, repo.Targets(delegationRoleName).ToFile(delegationPath, true))
	delegationJSON, err = os.ReadFile(delegationPath)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(keyDir, delegationKeyID), delegationPriv.Seed(), 0600))
	return targetsJSON, delegationJSON, keyDir, cleanup
}

// To verify: In bumpDelegatedRoles remove the FindLatestMetadataVersion (targets) error handling; test will fail (no error or wrong message).
func TestBumpDelegatedRoles_FindLatestTargetsFails(t *testing.T) {
	repo, _, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("list failed")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	_, err := bumpDelegatedRoles(ctx, repo, "admin", "app", redisClient, tmpDir, keySuffix, []string{"my-role"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find latest targets version")
}

// To verify: In bumpDelegatedRoles remove the Download (targets) error handling; test will fail (no error or wrong message).
func TestBumpDelegatedRoles_DownloadTargetsFails(t *testing.T) {
	repo, _, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{err: fmt.Errorf("create client failed")}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	_, err := bumpDelegatedRoles(ctx, repo, "admin", "app", redisClient, tmpDir, keySuffix, []string{"my-role"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to download targets metadata")
}

// To verify: In bumpDelegatedRoles remove the FromFile (targets) error handling; test will fail (no error or wrong message).
func TestBumpDelegatedRoles_LoadTargetsFails(t *testing.T) {
	repo, _, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	bodies := map[string][]byte{"1.targets.json": []byte("invalid")}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &multiBodyDownloadMock{bodies: bodies}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	_, err := bumpDelegatedRoles(ctx, repo, "admin", "app", redisClient, tmpDir, keySuffix, []string{"my-role"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load targets metadata")
}

// To verify: In bumpDelegatedRoles change behavior when roleNames is empty; test will fail (error or non-nil).
func TestBumpDelegatedRoles_EmptyRoleNames_Success(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	targetsJSON := makeValidTargetsJSON(t, repo, signer, tmpDir)
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	bodies := map[string][]byte{"1.targets.json": targetsJSON}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &multiBodyDownloadMock{bodies: bodies}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	updated, err := bumpDelegatedRoles(ctx, repo, "admin", "app", redisClient, tmpDir, keySuffix, nil)

	require.NoError(t, err)
	assert.Empty(t, updated)
}

// To verify: In bumpDelegatedRoles remove the Delegations nil check; test will fail (no error or wrong message).
func TestBumpDelegatedRoles_DelegationsNil_ReturnsError(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	targetsJSON := makeValidTargetsJSON(t, repo, signer, tmpDir)                      // no delegations
	_, delegationJSON, _, _ := makeTargetsAndDelegationForBumpDelegated(t, "my-role") // valid delegation so download/load succeeds, then we hit Delegations nil
	bodies := map[string][]byte{"1.targets.json": targetsJSON, "1.my-role.json": delegationJSON}
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json", "1.my-role.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &multiBodyDownloadMock{bodies: bodies}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	_, err := bumpDelegatedRoles(ctx, repo, "admin", "app", redisClient, tmpDir, keySuffix, []string{"my-role"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get delegations from targets metadata for role my-role")
}

// To verify: In bumpDelegatedRoles remove the "no key IDs" check; test will fail (no error or wrong message).
func TestBumpDelegatedRoles_NoKeyIDsForRole_ReturnsError(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTargetsSigner(t)
	defer cleanup()

	targetsJSON := makeTargetsWithDelegationsButNoRoles(t, repo, signer, tmpDir)
	_, delegationJSON, _, _ := makeTargetsAndDelegationForBumpDelegated(t, "my-role") // valid delegation so we reach "no key IDs" check
	bodies := map[string][]byte{"1.targets.json": targetsJSON, "1.my-role.json": delegationJSON}
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json", "1.my-role.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &multiBodyDownloadMock{bodies: bodies}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	_, err := bumpDelegatedRoles(ctx, repo, "admin", "app", redisClient, tmpDir, keySuffix, []string{"my-role"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no key IDs found for delegated role my-role")
}

// To verify: In bumpDelegatedRoles remove the delegation key load error handling; test will fail (no error or wrong message).
func TestBumpDelegatedRoles_LoadDelegationKeyFails(t *testing.T) {
	targetsJSON, delegationJSON, _, cleanup := makeTargetsAndDelegationForBumpDelegated(t, "my-role")
	defer cleanup()

	emptyKeyDir := t.TempDir()
	viper.GetViper().Set("ONLINE_KEY_DIR", emptyKeyDir)

	repo := repository.New()
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	tmpDir := t.TempDir()

	bodies := map[string][]byte{"1.targets.json": targetsJSON, "1.my-role.json": delegationJSON}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json", "1.my-role.json"}, nil
	}
	client := &multiBodyDownloadMock{bodies: bodies}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	_, err := bumpDelegatedRoles(ctx, repo, "admin", "app", redisClient, tmpDir, "admin_app", []string{"my-role"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load delegation private key")
}

// To verify: In bumpDelegatedRoles remove the Upload error handling; test will fail (no error or wrong message).
func TestBumpDelegatedRoles_UploadFails(t *testing.T) {
	targetsJSON, delegationJSON, _, cleanup := makeTargetsAndDelegationForBumpDelegated(t, "my-role")
	defer cleanup()

	repo := repository.New()
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	tmpDir := t.TempDir()

	bodies := map[string][]byte{"1.targets.json": targetsJSON, "1.my-role.json": delegationJSON}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json", "1.my-role.json"}, nil
	}
	client := &multiBodyDownloadMock{bodies: bodies}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{err: fmt.Errorf("upload failed")}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	_, err := bumpDelegatedRoles(ctx, repo, "admin", "app", redisClient, tmpDir, "admin_app", []string{"my-role"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to upload delegation my-role to S3")
}

// To verify: In bumpDelegatedRoles change success path; test will fail (error or wrong state).
func TestBumpDelegatedRoles_Success(t *testing.T) {
	targetsJSON, delegationJSON, _, cleanup := makeTargetsAndDelegationForBumpDelegated(t, "my-role")
	defer cleanup()

	repo := repository.New()
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	tmpDir := t.TempDir()

	bodies := map[string][]byte{"1.targets.json": targetsJSON, "1.my-role.json": delegationJSON}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json", "1.my-role.json"}, nil
	}
	client := &multiBodyDownloadMock{bodies: bodies}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	updated, err := bumpDelegatedRoles(ctx, repo, "admin", "app", redisClient, tmpDir, "admin_app", []string{"my-role"})

	require.NoError(t, err)
	assert.Equal(t, []string{"my-role"}, updated)
	assert.Equal(t, int64(2), repo.Targets("my-role").Signed.Version)
}

// --- bumpSnapshotRole tests ---

func makeRepoWithRootAndSnapshotSigner(t *testing.T) (repo *repository.Type, signer signature.Signer, tmpDir string, keySuffix string, cleanup func()) {
	t.Helper()
	rootJSON, _, cleanup := makeRootAndOnlineKeysForForceUpdate(t)
	tmpDir = t.TempDir()
	rootPath := filepath.Join(tmpDir, "root.json")
	require.NoError(t, os.WriteFile(rootPath, rootJSON, 0644))

	repo = repository.New()
	expires := time.Now().Add(365 * 24 * time.Hour)
	repo.SetRoot(tuf_metadata.Root(expires))
	_, err := repo.Root().FromFile(rootPath)
	require.NoError(t, err)

	var rootMeta models.RootMetadata
	require.NoError(t, json.Unmarshal(rootJSON, &rootMeta))
	snapshotRole, ok := rootMeta.Signed.Roles["snapshot"]
	require.True(t, ok)
	require.NotEmpty(t, snapshotRole.KeyIDs)
	snapshotKeyID := snapshotRole.KeyIDs[0]

	priv, err := signing.LoadPrivateKeyFromFilesystem(snapshotKeyID, snapshotKeyID)
	require.NoError(t, err)
	signer, err = signature.LoadSigner(priv, crypto.Hash(0))
	require.NoError(t, err)

	return repo, signer, tmpDir, "admin_app", cleanup
}

// makeValidSnapshotJSON produces valid signed snapshot metadata bytes for the given repo/signer.
func makeValidSnapshotJSON(t *testing.T, repo *repository.Type, signer signature.Signer, tmpDir string) []byte {
	t.Helper()
	exp := tuf_utils.HelperExpireIn(7)
	snap := tuf_metadata.Snapshot(exp)
	repo.SetSnapshot(snap)
	_, err := repo.Snapshot().Sign(signer)
	require.NoError(t, err)
	snapshotPath := filepath.Join(tmpDir, "1.snapshot.json")
	require.NoError(t, repo.Snapshot().ToFile(snapshotPath, true))
	data, err := os.ReadFile(snapshotPath)
	require.NoError(t, err)
	return data
}

// To verify: In bumpSnapshotRole remove the SetNX error handling or return a different error; test will fail (no error or wrong message).
func TestBumpSnapshotRole_LockAcquireFails(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndSnapshotSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close() // cause Redis operations to fail

	err := bumpSnapshotRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acquire snapshot lock")
}

// To verify: In bumpSnapshotRole remove the !acquired check or return a different error; test will fail (no error or wrong message).
func TestBumpSnapshotRole_LockNotAcquired(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndSnapshotSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("LOCK_SNAPSHOT_admin_app", "locked") // lock already held

	err := bumpSnapshotRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acquire snapshot lock")
	assert.Contains(t, err.Error(), "snapshot lock already held")
}

// To verify: In bumpSnapshotRole remove the FindLatestMetadataVersion error handling or return a different error; test will fail (no error or wrong message).
func TestBumpSnapshotRole_FindLatestFails(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndSnapshotSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("list failed")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	err := bumpSnapshotRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find latest snapshot version")
}

// To verify: In bumpSnapshotRole remove the Download error handling or return a different error; test will fail (no error or wrong message).
func TestBumpSnapshotRole_DownloadFails(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndSnapshotSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.snapshot.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{err: fmt.Errorf("create client failed")}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
	}()

	err := bumpSnapshotRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to download snapshot metadata")
}

// To verify: In bumpSnapshotRole remove the FromFile error handling or return a different error; test will fail (no error or wrong message).
func TestBumpSnapshotRole_LoadFails(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndSnapshotSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	invalidBody := []byte("invalid snapshot json")
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.snapshot.json"}, nil
	}
	client := &storageMockClientForForceUpdate{body: invalidBody}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	err := bumpSnapshotRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load snapshot metadata")
}

// To verify: In bumpSnapshotRole remove the Upload error handling or return a different error; test will fail (no error or wrong message).
func TestBumpSnapshotRole_UploadFails(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndSnapshotSigner(t)
	defer cleanup()

	snapshotJSON := makeValidSnapshotJSON(t, repo, signer, tmpDir)

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	downloadClient := &storageMockClientForForceUpdate{body: snapshotJSON}
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.snapshot.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: downloadClient}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{err: fmt.Errorf("upload failed")}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	err := bumpSnapshotRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to upload snapshot metadata to S3")
}

// To verify: In bumpSnapshotRole change success path; test will fail (error or wrong state).
func TestBumpSnapshotRole_Success(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndSnapshotSigner(t)
	defer cleanup()

	snapshotJSON := makeValidSnapshotJSON(t, repo, signer, tmpDir)

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	client := &storageMockClientForForceUpdate{body: snapshotJSON}
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.snapshot.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	err := bumpSnapshotRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.NoError(t, err)
	assert.Equal(t, int64(2), repo.Snapshot().Signed.Version)
}

// --- bumpTimestampRole tests ---

func makeRepoWithRootAndTimestampSigner(t *testing.T) (repo *repository.Type, signer signature.Signer, tmpDir string, keySuffix string, cleanup func()) {
	t.Helper()
	rootJSON, _, cleanup := makeRootAndOnlineKeysForForceUpdate(t)
	tmpDir = t.TempDir()
	rootPath := filepath.Join(tmpDir, "root.json")
	require.NoError(t, os.WriteFile(rootPath, rootJSON, 0644))

	repo = repository.New()
	expires := time.Now().Add(365 * 24 * time.Hour)
	repo.SetRoot(tuf_metadata.Root(expires))
	_, err := repo.Root().FromFile(rootPath)
	require.NoError(t, err)

	var rootMeta models.RootMetadata
	require.NoError(t, json.Unmarshal(rootJSON, &rootMeta))
	timestampRole, ok := rootMeta.Signed.Roles["timestamp"]
	require.True(t, ok)
	require.NotEmpty(t, timestampRole.KeyIDs)
	timestampKeyID := timestampRole.KeyIDs[0]

	priv, err := signing.LoadPrivateKeyFromFilesystem(timestampKeyID, timestampKeyID)
	require.NoError(t, err)
	signer, err = signature.LoadSigner(priv, crypto.Hash(0))
	require.NoError(t, err)

	return repo, signer, tmpDir, "admin_app", cleanup
}

// makeValidTimestampJSON produces valid signed timestamp metadata bytes for the given repo/signer.
func makeValidTimestampJSON(t *testing.T, repo *repository.Type, signer signature.Signer, tmpDir string) []byte {
	t.Helper()
	exp := tuf_utils.HelperExpireIn(1)
	ts := tuf_metadata.Timestamp(exp)
	repo.SetTimestamp(ts)
	_, err := repo.Timestamp().Sign(signer)
	require.NoError(t, err)
	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	require.NoError(t, repo.Timestamp().ToFile(timestampPath, true))
	data, err := os.ReadFile(timestampPath)
	require.NoError(t, err)
	return data
}

// To verify: In bumpTimestampRole remove the Upload error handling or return a different error; test will fail (no error or wrong message).
func TestBumpTimestampRole_UploadFails(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTimestampSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	tuf_storage.GetViperForUpload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{err: fmt.Errorf("upload failed")}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	err := bumpTimestampRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to upload timestamp metadata to S3")
}

// To verify: In bumpTimestampRole remove the ToFile error handling or return a different error; test will fail (no error or wrong message).
func TestBumpTimestampRole_ToFileFails(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTimestampSigner(t)
	defer cleanup()

	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	require.NoError(t, os.Mkdir(timestampPath, 0755))

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	client := &storageMockClientForForceUpdate{body: []byte(`{}`)}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	defer func() {
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	err := bumpTimestampRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save timestamp metadata")
}

// To verify: In bumpTimestampRole change success path; test will fail (error or wrong state).
func TestBumpTimestampRole_Success(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTimestampSigner(t)
	defer cleanup()

	timestampJSON := makeValidTimestampJSON(t, repo, signer, tmpDir)

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload
	client := &storageMockClientForForceUpdate{body: timestampJSON}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	defer func() {
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	err := bumpTimestampRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.NoError(t, err)
	assert.False(t, repo.Timestamp().Signed.Expires.IsZero())
	// When existing timestamp is loaded from S3, version must be incremented (was 1, becomes 2).
	assert.Equal(t, int64(2), repo.Timestamp().Signed.Version)
}

// To verify: In bumpTimestampRole when no existing timestamp is loaded, version is not incremented (stays default 1).
func TestBumpTimestampRole_NewTimestamp_VersionIsOne(t *testing.T) {
	repo, signer, tmpDir, keySuffix, cleanup := makeRepoWithRootAndTimestampSigner(t)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedDownloadViper := tuf_storage.GetViperForDownload
	savedDownloadFactory := tuf_storage.StorageFactoryForDownload
	savedUploadViper := tuf_storage.GetViperForUpload
	savedUploadFactory := tuf_storage.StorageFactoryForUpload

	client := &storageMockClientForForceUpdate{body: nil}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: client}
	}
	defer func() {
		tuf_storage.GetViperForDownload = savedDownloadViper
		tuf_storage.StorageFactoryForDownload = savedDownloadFactory
		tuf_storage.GetViperForUpload = savedUploadViper
		tuf_storage.StorageFactoryForUpload = savedUploadFactory
	}()

	err := bumpTimestampRole(ctx, repo, "admin", "app", redisClient, signer, tmpDir, keySuffix)

	require.NoError(t, err)
	assert.False(t, repo.Timestamp().Signed.Expires.IsZero())
	assert.Equal(t, int64(1), repo.Timestamp().Signed.Version)
}

// --- contains and isStandardRole tests ---

// To verify: In contains change the comparison (e.g. use !=) or return value; test will fail (wrong result).
func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected bool
	}{
		{"empty slice", []string{}, "a", false},
		{"single match", []string{"a"}, "a", true},
		{"single no match", []string{"a"}, "b", false},
		{"first of many", []string{"a", "b", "c"}, "a", true},
		{"middle of many", []string{"a", "b", "c"}, "b", true},
		{"last of many", []string{"a", "b", "c"}, "c", true},
		{"not in slice", []string{"a", "b", "c"}, "x", false},
		{"nil slice", nil, "a", false},
		{"duplicate items", []string{"a", "a", "b"}, "a", true},
		{"empty string in slice", []string{"", "b"}, "", true},
		{"empty string not in slice", []string{"a", "b"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.slice, tt.item)
			assert.Equal(t, tt.expected, got, "contains(%v, %q)", tt.slice, tt.item)
		})
	}
}

// To verify: In isStandardRole add/remove a role or change the list; test will fail (wrong result).
func TestIsStandardRole(t *testing.T) {
	tests := []struct {
		role     string
		expected bool
	}{
		{"root", true},
		{"targets", true},
		{"snapshot", true},
		{"timestamp", true},
		{"", false},
		{"root ", false},
		{" Root", false},
		{"target", false},
		{"delegated-role", false},
		{"my-role", false},
	}
	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			got := isStandardRole(tt.role)
			assert.Equal(t, tt.expected, got, "isStandardRole(%q)", tt.role)
		})
	}
}
