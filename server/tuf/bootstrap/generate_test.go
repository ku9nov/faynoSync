package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/tuf/models"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// mockAppRepoForGenerate implements only ListApps for GenerateRootKeys tests; other methods panic if called.
type mockAppRepoForGenerate struct {
	listAppsFunc func(ctx context.Context, owner string) ([]*model.App, error)
}

func (m *mockAppRepoForGenerate) ListApps(ctx context.Context, owner string) ([]*model.App, error) {
	if m.listAppsFunc != nil {
		return m.listAppsFunc(ctx, owner)
	}
	return nil, nil
}

func (m *mockAppRepoForGenerate) Get(ctx context.Context, limit int64, owner string) ([]*model.SpecificAppWithoutIDs, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) GetAppByName(appName string, ctx context.Context, page, limit int64, owner string, filters map[string]interface{}) (*model.PaginatedResponse, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) DeleteSpecificVersionOfApp(id primitive.ObjectID, owner string, ctx context.Context) ([]string, int64, string, error) {
	return nil, 0, "", nil
}
func (m *mockAppRepoForGenerate) DeleteChannel(id primitive.ObjectID, owner string, ctx context.Context) (int64, error) {
	return 0, nil
}
func (m *mockAppRepoForGenerate) Upload(ctxQuery map[string]interface{}, appLink, extension string, owner string, ctx context.Context, redisClient *redis.Client, env *viper.Viper, checkAppVisibility bool) (interface{}, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) UpdateSpecificApp(objID primitive.ObjectID, owner string, ctxQuery map[string]interface{}, appLink, extension string, ctx context.Context) (bool, error) {
	return false, nil
}
func (m *mockAppRepoForGenerate) CheckLatestVersion(appName, version, channel, platform, arch string, ctx context.Context, owner string) (mongod.CheckResult, error) {
	return mongod.CheckResult{}, nil
}
func (m *mockAppRepoForGenerate) FetchLatestVersionOfApp(appName, channel string, ctx context.Context, owner string) ([]*model.SpecificAppWithoutIDs, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) FetchAppByID(appID primitive.ObjectID, ctx context.Context) ([]*model.SpecificAppWithoutIDs, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) CreateChannel(channelName string, owner string, ctx context.Context) (interface{}, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) ListChannels(ctx context.Context, owner string) ([]*model.Channel, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) CreatePlatform(platformName string, updaters []model.Updater, owner string, ctx context.Context) (interface{}, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) ListPlatforms(ctx context.Context, owner string) ([]*model.Platform, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) DeletePlatform(id primitive.ObjectID, owner string, ctx context.Context) (int64, error) {
	return 0, nil
}
func (m *mockAppRepoForGenerate) CreateArch(archName string, owner string, ctx context.Context) (interface{}, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) ListArchs(ctx context.Context, owner string) ([]*model.Arch, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) DeleteArch(id primitive.ObjectID, owner string, ctx context.Context) (int64, error) {
	return 0, nil
}
func (m *mockAppRepoForGenerate) CreateApp(appName string, logo string, description string, private bool, tuf bool, owner string, ctx context.Context) (interface{}, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) DeleteApp(id primitive.ObjectID, owner string, ctx context.Context) (int64, error) {
	return 0, nil
}
func (m *mockAppRepoForGenerate) UpdateApp(id primitive.ObjectID, appName string, logo string, tuf bool, description string, owner string, ctx context.Context) (interface{}, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) UpdateChannel(id primitive.ObjectID, paramValue string, owner string, ctx context.Context) (interface{}, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) UpdatePlatform(id primitive.ObjectID, platformName string, updaters []model.Updater, owner string, ctx context.Context) (interface{}, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) UpdateArch(id primitive.ObjectID, paramValue string, owner string, ctx context.Context) (interface{}, error) {
	return nil, nil
}
func (m *mockAppRepoForGenerate) DeleteSpecificArtifactOfApp(id primitive.ObjectID, ctxQuery map[string]interface{}, ctx context.Context, owner string) ([]string, bool, error) {
	return nil, false, nil
}

func makeGenerateRootKeysContext(username string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var bodyReader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		bodyReader = bytes.NewReader(raw)
		c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/bootstrap/generate", bodyReader)
		c.Request.Header.Set("Content-Type", "application/json")
	} else {
		c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/bootstrap/generate", nil)
	}
	if username != "" {
		c.Set("username", username)
	}
	return c, w
}

// To verify: In GenerateRootKeys remove GetUsernameFromContext check or return 200 on error; test will fail (wrong status).
func TestGenerateRootKeys_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	c, w := makeGenerateRootKeysContext("", map[string]string{"appName": "myapp"})
	var repo mongod.AppRepository = &mockAppRepoForGenerate{}

	GenerateRootKeys(c, nil, nil, repo)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 when username is missing from context")
	var res map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.Equal(t, "Unauthorized", res["error"])
}

// To verify: In GenerateRootKeys remove ShouldBindJSON error check or return 200; test will fail (wrong status).
func TestGenerateRootKeys_InvalidJSON_ReturnsBadRequest(t *testing.T) {
	c, w := makeGenerateRootKeysContext("admin", nil)
	c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/bootstrap/generate", bytes.NewReader([]byte("not json")))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "admin")
	var repo mongod.AppRepository = &mockAppRepoForGenerate{}

	GenerateRootKeys(c, nil, nil, repo)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when body is invalid JSON")
	var res map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.Contains(t, res["error"], "appName")
}

// To verify: In GenerateRootKeys remove empty appName check or return 200; test will fail (wrong status).
func TestGenerateRootKeys_EmptyAppName_ReturnsBadRequest(t *testing.T) {
	c, w := makeGenerateRootKeysContext("admin", map[string]string{"appName": ""})
	var repo mongod.AppRepository = &mockAppRepoForGenerate{}

	GenerateRootKeys(c, nil, nil, repo)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var res map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	errMsg, _ := res["error"].(string)
	assert.Contains(t, errMsg, "appName", "error should mention appName (binding or explicit check)")
}

// To verify: In GenerateRootKeys remove nil appRepository check or return 200; test will fail (wrong status).
func TestGenerateRootKeys_NilAppRepository_ReturnsBadRequest(t *testing.T) {
	c, w := makeGenerateRootKeysContext("admin", map[string]string{"appName": "myapp"})

	GenerateRootKeys(c, nil, nil, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var res map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.Equal(t, "appName cannot be validated: AppRepository is not available", res["error"])
}

// To verify: In GenerateRootKeys change ListApps error handling to return 200; test will fail (wrong status).
func TestGenerateRootKeys_ListAppsError_ReturnsInternalServerError(t *testing.T) {
	c, w := makeGenerateRootKeysContext("admin", map[string]string{"appName": "myapp"})
	repo := &mockAppRepoForGenerate{
		listAppsFunc: func(ctx context.Context, owner string) ([]*model.App, error) {
			return nil, assert.AnError
		},
	}

	GenerateRootKeys(c, nil, nil, repo)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var res map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.Equal(t, "Failed to list apps", res["error"])
}

// To verify: In GenerateRootKeys change "app not found" branch to return 200; test will fail (wrong status).
func TestGenerateRootKeys_AppNotFound_ReturnsBadRequest(t *testing.T) {
	c, w := makeGenerateRootKeysContext("admin", map[string]string{"appName": "nonexistent"})
	repo := &mockAppRepoForGenerate{
		listAppsFunc: func(ctx context.Context, owner string) ([]*model.App, error) {
			return []*model.App{{AppName: "otherapp", Owner: "admin", Tuf: true}}, nil
		},
	}

	GenerateRootKeys(c, nil, nil, repo)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var res map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.Contains(t, res["error"], "not found")
}

// To verify: In GenerateRootKeys remove Tuf-enabled check or return 200 when Tuf is false; test will fail (wrong status).
func TestGenerateRootKeys_AppTufDisabled_ReturnsBadRequest(t *testing.T) {
	c, w := makeGenerateRootKeysContext("admin", map[string]string{"appName": "myapp"})
	repo := &mockAppRepoForGenerate{
		listAppsFunc: func(ctx context.Context, owner string) ([]*model.App, error) {
			return []*model.App{{AppName: "myapp", Owner: "admin", Tuf: false}}, nil
		},
	}

	GenerateRootKeys(c, nil, nil, repo)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var res map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.Contains(t, res["error"], "does not have Tuf enabled")
}

// To verify: In GenerateRootKeys change success response status or remove "data"/"message"; test will fail (wrong status or body).
func TestGenerateRootKeys_ValidRequest_AppWithTufEnabled_ReturnsOKWithPayload(t *testing.T) {
	c, w := makeGenerateRootKeysContext("admin", map[string]string{"appName": "myapp"})
	repo := &mockAppRepoForGenerate{
		listAppsFunc: func(ctx context.Context, owner string) ([]*model.App, error) {
			return []*model.App{{AppName: "myapp", Owner: "admin", Tuf: true}}, nil
		},
	}

	GenerateRootKeys(c, nil, nil, repo)

	assert.Equal(t, http.StatusOK, w.Code, "Expected 200 on success")
	var res map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.NotEmpty(t, res["data"], "response should include payload data")
	assert.Equal(t, "Root keys generated and payload created successfully", res["message"])
	data, ok := res["data"].(map[string]interface{})
	require.True(t, ok, "data should be an object")
	assert.Equal(t, "myapp", data["appName"])
	assert.Contains(t, data, "metadata")
	assert.Contains(t, data, "settings")
}

// To verify: In GenerateRootKeys change default roleName to something other than "default" when empty; test will fail (wrong role in payload).
func TestGenerateRootKeys_OmitsRoleName_UsesDefaultRole(t *testing.T) {
	c, w := makeGenerateRootKeysContext("admin", map[string]string{"appName": "myapp"})
	repo := &mockAppRepoForGenerate{
		listAppsFunc: func(ctx context.Context, owner string) ([]*model.App, error) {
			return []*model.App{{AppName: "myapp", Owner: "admin", Tuf: true}}, nil
		},
	}

	GenerateRootKeys(c, nil, nil, repo)

	require.Equal(t, http.StatusOK, w.Code)
	var res map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	data, ok := res["data"].(map[string]interface{})
	require.True(t, ok)
	settings, ok := data["settings"].(map[string]interface{})
	require.True(t, ok)
	roles, ok := settings["roles"].(map[string]interface{})
	require.True(t, ok)
	delegations, ok := roles["delegations"].(map[string]interface{})
	require.True(t, ok)
	rolesList, ok := delegations["roles"].([]interface{})
	require.True(t, ok)
	require.GreaterOrEqual(t, len(rolesList), 1)
	firstRole, ok := rolesList[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "default", firstRole["name"], "role name should default to 'default' when omitted")
}

// To verify: In GenerateRootKeys change custom expiration handling; test will fail (wrong expiration in payload).
func TestGenerateRootKeys_CustomExpirations_ReflectedInRequest(t *testing.T) {
	rootExp, targetsExp, snapshotExp, timestampExp := 100, 14, 14, 2
	c, w := makeGenerateRootKeysContext("admin", map[string]interface{}{
		"appName":             "myapp",
		"rootExpiration":      rootExp,
		"targetsExpiration":   targetsExp,
		"snapshotExpiration":  snapshotExp,
		"timestampExpiration": timestampExp,
	})
	repo := &mockAppRepoForGenerate{
		listAppsFunc: func(ctx context.Context, owner string) ([]*model.App, error) {
			return []*model.App{{AppName: "myapp", Owner: "admin", Tuf: true}}, nil
		},
	}

	GenerateRootKeys(c, nil, nil, repo)

	assert.Equal(t, http.StatusOK, w.Code)
	var res map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	data, ok := res["data"].(map[string]interface{})
	require.True(t, ok)
	settings, ok := data["settings"].(map[string]interface{})
	require.True(t, ok)
	roles, ok := settings["roles"].(map[string]interface{})
	require.True(t, ok)
	rootRole, ok := roles["root"].(map[string]interface{})
	require.True(t, ok)
	exp, ok := rootRole["expiration"].(float64)
	require.True(t, ok)
	assert.InDelta(t, rootExp, exp, 1, "root expiration should reflect requested value (may differ by 1 day due to rounding)")
}

// --- generatePayload tests ---

const testOnlineKeyID = "timestamp-key-123"

func validRootMetadata(expires string) models.RootMetadata {
	if expires == "" {
		expires = time.Now().AddDate(0, 0, 365).UTC().Format(time.RFC3339)
	}
	return models.RootMetadata{
		Signatures: []models.Signature{},
		Signed: models.Signed{
			Type:               "root",
			Version:            1,
			SpecVersion:        "1.0",
			Expires:            expires,
			ConsistentSnapshot: false,
			Keys: map[string]models.Key{
				testOnlineKeyID: {
					KeyType: "ed25519",
					Scheme:  "ed25519",
					KeyVal:  models.KeyVal{Public: "dGVzdC1wdWJsaWMta2V5"},
				},
			},
			Roles: map[string]models.Role{
				"timestamp": {KeyIDs: []string{testOnlineKeyID}, Threshold: 1},
			},
		},
	}
}

func writeRootToDir(t *testing.T, root models.RootMetadata) string {
	t.Helper()
	dir := t.TempDir()
	data, err := json.Marshal(root)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, "1.root.json"), data, 0644)
	require.NoError(t, err)
	return dir
}

// To verify: In generatePayload change the root file read error handling to return nil; test will fail (wrong error).
func TestGeneratePayload_MissingRootFile_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	// No 1.root.json in dir

	payload, err := generatePayload(dir, "admin", []string{"myapp"}, "default")

	require.Error(t, err)
	assert.Nil(t, payload)
	assert.Contains(t, err.Error(), "reading root metadata")
}

// To verify: In generatePayload remove JSON unmarshal error check or return nil error; test will fail (wrong error).
func TestGeneratePayload_InvalidRootJSON_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "1.root.json"), []byte("not json"), 0644)
	require.NoError(t, err)

	payload, err := generatePayload(dir, "admin", []string{"myapp"}, "default")

	require.Error(t, err)
	assert.Nil(t, payload)
	assert.Contains(t, err.Error(), "parsing root metadata")
}

// To verify: In generatePayload remove "timestamp role not found" branch or return nil error; test will fail (wrong error).
func TestGeneratePayload_RootWithoutTimestampRole_ReturnsError(t *testing.T) {
	root := validRootMetadata("")
	root.Signed.Roles = map[string]models.Role{} // no timestamp role
	dir := writeRootToDir(t, root)

	payload, err := generatePayload(dir, "admin", []string{"myapp"}, "default")

	require.Error(t, err)
	assert.Nil(t, payload)
	assert.Contains(t, err.Error(), "failed to find timestamp key in root metadata")
}

// To verify: In generatePayload remove "timestamp keyids empty" check; test will fail (wrong error or panic).
func TestGeneratePayload_RootWithEmptyTimestampKeyIDs_ReturnsError(t *testing.T) {
	root := validRootMetadata("")
	root.Signed.Roles["timestamp"] = models.Role{KeyIDs: []string{}, Threshold: 1}
	dir := writeRootToDir(t, root)

	payload, err := generatePayload(dir, "admin", []string{"myapp"}, "default")

	require.Error(t, err)
	assert.Nil(t, payload)
	assert.Contains(t, err.Error(), "failed to find timestamp key in root metadata")
}

// To verify: In generatePayload remove "online key not in Keys" check or return nil error; test will fail (wrong error).
func TestGeneratePayload_OnlineKeyNotInKeys_ReturnsError(t *testing.T) {
	root := validRootMetadata("")
	root.Signed.Roles["timestamp"] = models.Role{KeyIDs: []string{"missing-key-id"}, Threshold: 1}
	// Keys map still has testOnlineKeyID, not "missing-key-id"
	dir := writeRootToDir(t, root)

	payload, err := generatePayload(dir, "admin", []string{"myapp"}, "default")

	require.Error(t, err)
	assert.Nil(t, payload)
	assert.Contains(t, err.Error(), "online key")
	assert.Contains(t, err.Error(), "not found in root metadata")
}

// To verify: In generatePayload change success response (e.g. omit metadata or timeout); test will fail (wrong payload).
func TestGeneratePayload_ValidRoot_ReturnsPayloadWithMetadataAndDelegations(t *testing.T) {
	root := validRootMetadata("")
	dir := writeRootToDir(t, root)

	payload, err := generatePayload(dir, "admin", []string{"myapp"}, "default")

	require.NoError(t, err)
	require.NotNil(t, payload)
	assert.Equal(t, "myapp", payload.AppName)
	require.NotNil(t, payload.Metadata)
	assert.Contains(t, payload.Metadata, "root")
	assert.Equal(t, root.Signed.Expires, payload.Metadata["root"].Signed.Expires)
	require.NotNil(t, payload.Timeout)
	assert.Equal(t, 300, *payload.Timeout)
	require.NotNil(t, payload.Settings.Roles.Delegations)
	assert.Len(t, payload.Settings.Roles.Delegations.Keys, 1)
	assert.Contains(t, payload.Settings.Roles.Delegations.Keys, testOnlineKeyID)
	require.Len(t, payload.Settings.Roles.Delegations.Roles, 1)
	assert.Equal(t, "default", payload.Settings.Roles.Delegations.Roles[0].Name)
	assert.Equal(t, []string{testOnlineKeyID}, payload.Settings.Roles.Delegations.Roles[0].KeyIDs)
}

// To verify: In generatePayload change delegation path format (admin/appName, appName-admin, etc.); test will fail (wrong paths).
func TestGeneratePayload_WithTufAppNames_DelegationPathsIncludeAppPaths(t *testing.T) {
	root := validRootMetadata("")
	dir := writeRootToDir(t, root)

	payload, err := generatePayload(dir, "owner", []string{"myapp"}, "custom-role")

	require.NoError(t, err)
	require.NotNil(t, payload.Settings.Roles.Delegations)
	paths := payload.Settings.Roles.Delegations.Roles[0].Paths
	assert.Contains(t, paths, "owner/myapp/")
	assert.Contains(t, paths, "myapp-owner/")
	assert.Contains(t, paths, "electron-builder/myapp-owner/")
	assert.Contains(t, paths, "squirrel_windows/myapp-owner/")
	assert.Equal(t, "custom-role", payload.Settings.Roles.Delegations.Roles[0].Name)
}

// To verify: In generatePayload change reading of timestamp/snapshot/targets expires; test will fail (wrong expiration).
func TestGeneratePayload_OptionalMetadataFiles_ExpirationsInPayload(t *testing.T) {
	root := validRootMetadata("")
	dir := writeRootToDir(t, root)
	tsExp := time.Now().AddDate(0, 0, 2).UTC().Format(time.RFC3339)
	snapExp := time.Now().AddDate(0, 0, 14).UTC().Format(time.RFC3339)
	targExp := time.Now().AddDate(0, 0, 30).UTC().Format(time.RFC3339)
	writeMetaWithExpires(t, dir, "timestamp.json", tsExp)
	writeMetaWithExpires(t, dir, "1.snapshot.json", snapExp)
	writeMetaWithExpires(t, dir, "1.targets.json", targExp)

	payload, err := generatePayload(dir, "admin", []string{"myapp"}, "default")

	require.NoError(t, err)
	require.NotNil(t, payload)
	assert.Greater(t, payload.Settings.Roles.Timestamp.Expiration, 0, "timestamp expiration should be set from file")
	assert.Greater(t, payload.Settings.Roles.Snapshot.Expiration, 0, "snapshot expiration should be set from file")
	assert.Greater(t, payload.Settings.Roles.Targets.Expiration, 0, "targets expiration should be set from file")
}

func writeMetaWithExpires(t *testing.T, dir, filename, expires string) {
	t.Helper()
	meta := map[string]interface{}{"signed": map[string]interface{}{"expires": expires}}
	data, err := json.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, filename), data, 0644))
}
