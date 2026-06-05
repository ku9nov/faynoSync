package metadata

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"faynoSync/server/tuf/models"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

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
	newKeyID, newKey := mustNewDelegationKey(t)
	expires := time.Now().Add(24 * time.Hour)

	// Trusted store: signed root + signed targets (v2) delegating "delegated",
	// plus the signed delegated role file (v1). The loaders verify these before use.
	fixture := buildTrustedStoreFixture(t, 2, []*fixtureDelegation{
		{role: "delegated", version: 1, buildFile: true},
	})

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

	defer fixture.install(t, nil)()

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
	// Trusted store: signed root + signed targets (v2) delegating "delegated", and the signed
	// delegated role file at v1. The incoming staged delegated metadata is also v1, so the
	// version check must reject it (after the trusted store verifies cleanly).
	fixture := buildTrustedStoreFixture(t, 2, []*fixtureDelegation{
		{role: "delegated", version: 1, buildFile: true},
	})
	defer fixture.install(t, nil)()

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
