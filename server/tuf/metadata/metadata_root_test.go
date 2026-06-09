package metadata

import (
	"context"
	"encoding/json"
	tuf_storage "faynoSync/server/tuf/storage"
	"faynoSync/server/utils"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- GetMetadataRoot handler tests ---

// To verify: Change URL builder or query parsing in metadata GET handlers; tests will fail (wrong status/body).
func makeGetMetadataContext(username string, endpoint string, appName string, extraQuery string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := endpoint
	query := ""
	if appName != "" {
		query = "appName=" + appName
	}
	if extraQuery != "" {
		if query != "" {
			query += "&"
		}
		query += extraQuery
	}
	if query != "" {
		url += "?" + query
	}
	c.Request = httptest.NewRequest(http.MethodGet, url, nil)
	if username != "" {
		c.Set("username", username)
	}
	return c, w
}

func makeGetMetadataRootContext(username string, appName string) (*gin.Context, *httptest.ResponseRecorder) {
	return makeGetMetadataContext(username, "/tuf/v1/metadata/root", appName, "")
}

func makeGetMetadataTargetsContext(username string, appName string) (*gin.Context, *httptest.ResponseRecorder) {
	return makeGetMetadataContext(username, "/tuf/v1/metadata/targets", appName, "")
}

func makeGetMetadataDelegatedContext(username string, appName string, roleName string) (*gin.Context, *httptest.ResponseRecorder) {
	extra := ""
	if roleName != "" {
		extra = "roleName=" + roleName
	}
	return makeGetMetadataContext(username, "/tuf/v1/metadata/delegated", appName, extra)
}

// To verify: In GetMetadataRoot remove GetUsernameFromContext check or return 200 on error; test will fail (wrong status).
func TestGetMetadataRoot_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	c, w := makeGetMetadataRootContext("", "myapp")
	GetMetadataRoot(c)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 when username is missing from context")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
}

// To verify: In GetMetadataRoot remove the return after appName empty check or return 200; test will fail (wrong status).
func TestGetMetadataRoot_MissingAppName_ReturnsBadRequest(t *testing.T) {
	c, w := makeGetMetadataRootContext("admin", "")
	GetMetadataRoot(c)
	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when appName is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "appName query parameter is required", body["error"])
}

// To verify: In GetMetadataRoot change success response shape (e.g. remove data.trusted_root) or return non-200; test will fail.
func TestGetMetadataRoot_Success_WithTrustedRoot(t *testing.T) {
	fixture := buildTrustedStoreFixture(t, 1, nil)
	defer fixture.install(t, nil)()

	c, w := makeGetMetadataRootContext("admin", "myapp")
	GetMetadataRoot(c)

	require.Equal(t, http.StatusOK, w.Code, "Expected 200 when trusted_root is loaded")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok, "response should have data object")
	trustedRoot, ok := data["trusted_root"].(map[string]interface{})
	require.True(t, ok, "data should have trusted_root")
	signed, ok := trustedRoot["signed"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "root", signed["_type"])
	assert.Equal(t, float64(1), signed["version"])
}

// To verify: In GetMetadataRoot return non-200 when loadTrustedRootFromS3 fails, or change response shape; test will fail.
func TestGetMetadataRoot_Success_WithoutTrustedRoot(t *testing.T) {
	savedList := tuf_storage.ListMetadataForLatest
	savedFactory := tuf_storage.StorageFactoryForDownload
	savedViper := tuf_storage.GetViperForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("list failed")
	}
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &downloadMockFactory{err: utils.ErrUnknownStorageDriver}
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.StorageFactoryForDownload = savedFactory
		tuf_storage.GetViperForDownload = savedViper
	}()

	c, w := makeGetMetadataRootContext("admin", "myapp")
	GetMetadataRoot(c)

	require.Equal(t, http.StatusOK, w.Code, "Expected 200 even when trusted_root fails to load (trusted_root is optional)")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok, "response should have data object")
	assert.Nil(t, data["trusted_root"], "trusted_root should be nil when load fails")
}

// To verify: In GetMetadataTargets change response key or status; test will fail.
func TestGetMetadataTargets_Success_WithTrustedTargets(t *testing.T) {
	fixture := buildTrustedStoreFixture(t, 2, nil)
	defer fixture.install(t, nil)()

	c, w := makeGetMetadataTargetsContext("admin", "myapp")
	GetMetadataTargets(c)

	require.Equal(t, http.StatusOK, w.Code, "Expected 200 when trusted_targets is loaded")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok, "response should have data object")
	trustedTargets, ok := data["trusted_targets"].(map[string]interface{})
	require.True(t, ok, "data should have trusted_targets")
	signed, ok := trustedTargets["signed"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "targets", signed["_type"])
	assert.Equal(t, float64(2), signed["version"])
}

// To verify: In GetMetadataDelegated remove roleName requirement; test will fail.
func TestGetMetadataDelegated_MissingRoleName_ReturnsBadRequest(t *testing.T) {
	c, w := makeGetMetadataDelegatedContext("admin", "myapp", "")
	GetMetadataDelegated(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when roleName is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "roleName query parameter is required", body["error"])
}

// To verify: In GetMetadataDelegated change response key or delegated loading behavior; test will fail.
func TestGetMetadataDelegated_Success_WithTrustedDelegated(t *testing.T) {
	fixture := buildTrustedStoreFixture(t, 1, []*fixtureDelegation{
		{role: "myrole", version: 3, buildFile: true},
	})
	defer fixture.install(t, nil)()

	c, w := makeGetMetadataDelegatedContext("admin", "myapp", "myrole")
	GetMetadataDelegated(c)

	require.Equal(t, http.StatusOK, w.Code, "Expected 200 when trusted_delegated is loaded")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok, "response should have data object")
	trustedDelegated, ok := data["trusted_delegated"].(map[string]interface{})
	require.True(t, ok, "data should have trusted_delegated")
	signed, ok := trustedDelegated["signed"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "targets", signed["_type"])
	assert.Equal(t, float64(3), signed["version"])
}
