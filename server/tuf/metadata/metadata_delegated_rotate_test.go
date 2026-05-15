package metadata

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"faynoSync/server/tuf/models"
	tuf_storage "faynoSync/server/tuf/storage"
	"faynoSync/server/utils"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

type mapDownloadMockClient struct {
	objects map[string][]byte
}

func (m *mapDownloadMockClient) DownloadObject(ctx context.Context, bucketName, objectKey, filePath string) error {
	body, ok := m.objects[objectKey]
	if !ok {
		return fmt.Errorf("object not found: %s", objectKey)
	}
	return os.WriteFile(filePath, body, 0644)
}

func (m *mapDownloadMockClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	panic("not used")
}

func (m *mapDownloadMockClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	panic("not used")
}

func (m *mapDownloadMockClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	panic("not used")
}

func (m *mapDownloadMockClient) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	panic("not used")
}

func (m *mapDownloadMockClient) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	panic("not used")
}

type mapDownloadMockFactory struct {
	client utils.StorageClient
}

func (f *mapDownloadMockFactory) CreateStorageClient() (utils.StorageClient, error) {
	return f.client, nil
}

func makePostMetadataDelegatedRotateContext(username string, appName string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/tuf/v1/metadata/delegated/rotate"
	if appName != "" {
		url += "?appName=" + appName
	}
	raw, _ := json.Marshal(body)
	c.Request = httptest.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	c.Request.Header.Set("Content-Type", "application/json")
	if username != "" {
		c.Set("username", username)
	}
	return c, w
}

func mustBuildTargetsMetadataJSON(t *testing.T, meta *tuf_metadata.Metadata[tuf_metadata.TargetsType]) []byte {
	t.Helper()
	tmpDir := t.TempDir()
	metadataPath := filepath.Join(tmpDir, "metadata.json")
	require.NoError(t, meta.ToFile(metadataPath, true))
	body, err := os.ReadFile(metadataPath)
	require.NoError(t, err)
	return body
}

func mustNewDelegationKey(t *testing.T) (string, *tuf_metadata.Key) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	key, err := tuf_metadata.KeyFromPublicKey(privateKey.Public())
	require.NoError(t, err)
	keyID, err := key.ID()
	require.NoError(t, err)
	return keyID, key
}

func TestPostMetadataDelegatedRotate_StagesTargetsAndDelegated(t *testing.T) {
	oldKeyID, oldKey := mustNewDelegationKey(t)
	newKeyID, newKey := mustNewDelegationKey(t)
	expires := time.Now().Add(24 * time.Hour)

	trustedTargets := tuf_metadata.Targets(expires)
	trustedTargets.Signed.Version = 2
	trustedTargets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys: map[string]*tuf_metadata.Key{
			oldKeyID: oldKey,
		},
		Roles: []tuf_metadata.DelegatedRole{
			{
				Name:        "delegated",
				KeyIDs:      []string{oldKeyID},
				Threshold:   1,
				Paths:       []string{"*"},
				Terminating: false,
			},
		},
	}
	trustedTargetsJSON := mustBuildTargetsMetadataJSON(t, trustedTargets)

	trustedDelegated := tuf_metadata.Targets(expires)
	trustedDelegated.Signed.Version = 1
	trustedDelegatedJSON := mustBuildTargetsMetadataJSON(t, trustedDelegated)

	rotatedTargets := tuf_metadata.Targets(expires)
	rotatedTargets.Signed.Version = 3
	rotatedTargets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys: map[string]*tuf_metadata.Key{
			newKeyID: newKey,
		},
		Roles: []tuf_metadata.DelegatedRole{
			{
				Name:        "delegated",
				KeyIDs:      []string{newKeyID},
				Threshold:   1,
				Paths:       []string{"*"},
				Terminating: false,
			},
		},
	}
	rotatedTargetsJSON := mustBuildTargetsMetadataJSON(t, rotatedTargets)

	rotatedDelegated := tuf_metadata.Targets(expires)
	rotatedDelegated.Signed.Version = 2
	rotatedDelegatedJSON := mustBuildTargetsMetadataJSON(t, rotatedDelegated)

	savedList := tuf_storage.ListMetadataForLatest
	savedViper := tuf_storage.GetViperForDownload
	savedFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"2.targets.json", "1.delegated.json"}, nil
	}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &mapDownloadMockFactory{client: &mapDownloadMockClient{
			objects: map[string][]byte{
				"tuf_metadata/admin/myapp/2.targets.json":   trustedTargetsJSON,
				"tuf_metadata/admin/myapp/1.delegated.json": trustedDelegatedJSON,
			},
		}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedViper
		tuf_storage.StorageFactoryForDownload = savedFactory
	}()

	payload := models.MetadataDelegatedRotatePayload{
		Role: "delegated",
		Metadata: map[string]json.RawMessage{
			"targets":   rotatedTargetsJSON,
			"delegated": rotatedDelegatedJSON,
		},
	}
	c, w := makePostMetadataDelegatedRotateContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")

	PostMetadataDelegatedRotate(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	targetsStaged, err := client.Get(context.Background(), "TARGETS_SIGNING_admin_myapp").Result()
	require.NoError(t, err)
	assert.NotEmpty(t, targetsStaged)
	delegatedStaged, err := client.Get(context.Background(), "DELEGATED_SIGNING_admin_myapp").Result()
	require.NoError(t, err)
	assert.NotEmpty(t, delegatedStaged)
}

func TestPostMetadataSign_DuplicateSignatureKeyIDs_ReturnsBadRequest(t *testing.T) {
	payload := models.MetadataSignPostPayload{
		Role: "delegated",
		Signature: models.Signature{
			KeyID: "dup-key",
			Sig:   "00",
		},
	}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")
	mr.Set("DELEGATED_SIGNING_admin_myapp", `{
		"signed":{"_type":"targets","version":2,"expires":"2030-01-01T00:00:00Z","targets":{}},
		"signatures":[{"keyid":"dup-key","sig":"aa"},{"keyid":"dup-key","sig":"bb"}]
	}`)

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Signature Failed", body["message"])
	assert.Contains(t, body["error"], "duplicate signature keyid")
}

func TestPostMetadataSign_ExpiredMetadata_ReturnsBadRequest(t *testing.T) {
	payload := models.MetadataSignPostPayload{
		Role: "delegated",
		Signature: models.Signature{
			KeyID: "k1",
			Sig:   "00",
		},
	}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")
	mr.Set("DELEGATED_SIGNING_admin_myapp", `{
		"signed":{"_type":"targets","version":2,"expires":"2000-01-01T00:00:00Z","targets":{}},
		"signatures":[{"keyid":"k1","sig":"aa"}]
	}`)

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Signature Failed", body["message"])
	assert.Contains(t, body["error"], "expired")
}

func TestPostMetadataSign_DelegatedVersionNotMonotonic_ReturnsBadRequest(t *testing.T) {
	keyID, key := mustNewDelegationKey(t)
	expires := time.Now().Add(24 * time.Hour)

	trustedTargets := tuf_metadata.Targets(expires)
	trustedTargets.Signed.Version = 2
	trustedTargets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys: map[string]*tuf_metadata.Key{
			keyID: key,
		},
		Roles: []tuf_metadata.DelegatedRole{
			{
				Name:        "delegated",
				KeyIDs:      []string{keyID},
				Threshold:   1,
				Paths:       []string{"*"},
				Terminating: false,
			},
		},
	}
	trustedTargetsJSON := mustBuildTargetsMetadataJSON(t, trustedTargets)

	trustedDelegated := tuf_metadata.Targets(expires)
	trustedDelegated.Signed.Version = 1
	trustedDelegatedJSON := mustBuildTargetsMetadataJSON(t, trustedDelegated)

	savedList := tuf_storage.ListMetadataForLatest
	savedViper := tuf_storage.GetViperForDownload
	savedFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"2.targets.json", "1.delegated.json"}, nil
	}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &mapDownloadMockFactory{client: &mapDownloadMockClient{
			objects: map[string][]byte{
				"tuf_metadata/admin/myapp/2.targets.json":   trustedTargetsJSON,
				"tuf_metadata/admin/myapp/1.delegated.json": trustedDelegatedJSON,
			},
		}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedViper
		tuf_storage.StorageFactoryForDownload = savedFactory
	}()

	payload := models.MetadataSignPostPayload{
		Role: "delegated",
		Signature: models.Signature{
			KeyID: "already-present",
			Sig:   "00",
		},
	}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")
	mr.Set("DELEGATED_SIGNING_admin_myapp", `{
		"signed":{"_type":"targets","version":1,"expires":"2030-01-01T00:00:00Z","targets":{}},
		"signatures":[{"keyid":"already-present","sig":"aa"}]
	}`)

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Signature Failed", body["message"])
	assert.Contains(t, body["error"], "version must be greater than trusted version")
}
