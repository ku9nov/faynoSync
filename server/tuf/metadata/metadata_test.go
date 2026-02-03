package metadata

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
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

// makeValidRootAndPayload creates a valid root using go-tuf, writes the timestamp private key to keyDir,
// and returns a BootstrapPayload and cleanup function. To verify: change AddKey/FromFile so root is invalid; test fails.
func makeValidRootAndPayload(t *testing.T) (payload *models.BootstrapPayload, keyDir string, cleanup func()) {
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

	rootData, err := os.ReadFile(rootPath)
	require.NoError(t, err)
	var rootMeta models.RootMetadata
	err = json.Unmarshal(rootData, &rootMeta)
	require.NoError(t, err)

	timestampKeyID := ""
	if r, ok := rootMeta.Signed.Roles["timestamp"]; ok && len(r.KeyIDs) > 0 {
		timestampKeyID = r.KeyIDs[0]
	}
	require.NotEmpty(t, timestampKeyID, "timestamp key ID must be present in root")

	// Write timestamp private key as 32-byte raw seed so LoadPrivateKeyFromFilesystem can load it
	seed := keys["timestamp"].Seed()
	timestampKeyPath := filepath.Join(keyDir, timestampKeyID)
	require.NoError(t, os.WriteFile(timestampKeyPath, seed, 0600))

	payload = &models.BootstrapPayload{
		AppName: "testapp",
		Settings: models.Settings{
			Roles: models.RolesData{
				Root:      models.RoleExpiration{Expiration: 365},
				Timestamp: models.RoleExpiration{Expiration: 1},
				Snapshot:  models.RoleExpiration{Expiration: 7},
				Targets:   models.RoleExpiration{Expiration: 90},
			},
		},
		Metadata: map[string]models.RootMetadata{"root": rootMeta},
	}

	oldDir := viper.GetViper().GetString("ONLINE_KEY_DIR")
	viper.GetViper().Set("ONLINE_KEY_DIR", keyDir)
	cleanup = func() {
		viper.GetViper().Set("ONLINE_KEY_DIR", oldDir)
	}
	return payload, keyDir, cleanup
}

// To verify: In BootstrapOnlineRoles remove the check for payload.Metadata["root"] or return nil; test will fail (no error).
func TestBootstrapOnlineRoles_RootMetadataNotFound(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	payload := &models.BootstrapPayload{
		AppName:  "testapp",
		Settings: models.Settings{Roles: models.RolesData{}},
		Metadata: map[string]models.RootMetadata{}, // no "root" key
	}

	err := BootstrapOnlineRoles(client, "task-1", "admin", "app", payload)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "root metadata not found in payload")
}

// To verify: In BootstrapOnlineRoles skip validation of root structure; test will fail (error expected at load or timestamp).
func TestBootstrapOnlineRoles_InvalidRootStructure_NoTimestampRole(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	payload := &models.BootstrapPayload{
		AppName:  "testapp",
		Settings: models.Settings{Roles: models.RolesData{}},
		Metadata: map[string]models.RootMetadata{
			"root": {
				Signed: models.Signed{
					Type:    "root",
					Version: 1,
					Expires: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
					Roles:   map[string]models.Role{}, // no timestamp role
					Keys:    map[string]models.Key{},
				},
			},
		},
	}

	err := BootstrapOnlineRoles(client, "task-1", "admin", "app", payload)

	require.Error(t, err)
	// Root is written to file; go-tuf FromFile may fail on type/structure, or we fail on timestamp key
	assert.True(t, strings.Contains(err.Error(), "failed to load root metadata from file") ||
		strings.Contains(err.Error(), "failed to find timestamp key in root metadata"),
		"expected load or timestamp error, got: %s", err.Error())
}

// To verify: In BootstrapOnlineRoles accept root without timestamp role; test will fail (no error).
func TestBootstrapOnlineRoles_TimestampKeyMissingInRoot(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	payload := &models.BootstrapPayload{
		AppName:  "testapp",
		Settings: models.Settings{Roles: models.RolesData{Targets: models.RoleExpiration{Expiration: 90}, Snapshot: models.RoleExpiration{Expiration: 7}, Timestamp: models.RoleExpiration{Expiration: 1}}},
		Metadata: map[string]models.RootMetadata{
			"root": {
				Signed: models.Signed{
					Type:               "root",
					Version:            1,
					Expires:            time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
					ConsistentSnapshot: true,
					Roles:              map[string]models.Role{}, // no timestamp
					Keys:               map[string]models.Key{},
				},
			},
		},
	}

	err := BootstrapOnlineRoles(client, "task-1", "admin", "app", payload)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find timestamp key in root metadata")
}

// To verify: In BootstrapOnlineRoles skip the check that online key exists in Keys; test will fail (no error or wrong message).
func TestBootstrapOnlineRoles_OnlineKeyNotFoundInRoot(t *testing.T) {
	payload, _, cleanup := makeValidRootAndPayload(t)
	defer cleanup()
	// Remove the timestamp key from Keys so key lookup fails
	rootMeta := payload.Metadata["root"]
	rootMeta.Signed.Keys = map[string]models.Key{} // empty keys
	payload.Metadata["root"] = rootMeta

	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	err := BootstrapOnlineRoles(client, "task-1", "admin", "app", payload)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "online key")
	assert.Contains(t, err.Error(), "not found in root metadata")
}

// To verify: In BootstrapOnlineRoles ignore LoadPrivateKeyFromFilesystem error and proceed; test will fail (no error).
func TestBootstrapOnlineRoles_SignerCreationFails_NoKeyDir(t *testing.T) {
	payload, _, _ := makeValidRootAndPayload(t)
	// Restore viper so ONLINE_KEY_DIR is unset for this test
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", "")
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	err := BootstrapOnlineRoles(client, "task-1", "admin", "app", payload)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create signer from private key")
}

// To verify: In BootstrapOnlineRoles change repo.Root().FromFile to skip error or use wrong path; test will fail (no error or wrong behavior).
func TestBootstrapOnlineRoles_LoadRootFromFileFails_InvalidJSON(t *testing.T) {
	payload, _, cleanup := makeValidRootAndPayload(t)
	defer cleanup()
	// Corrupt root so that go-tuf FromFile fails (e.g. invalid JSON structure for TUF)
	payload.Metadata["root"] = models.RootMetadata{
		Signed: models.Signed{
			Type:    "root",
			Version: 1,
			Expires: "invalid-date",
			Roles:   payload.Metadata["root"].Signed.Roles,
			Keys:    payload.Metadata["root"].Signed.Keys,
		},
	}

	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	err := BootstrapOnlineRoles(client, "task-1", "admin", "app", payload)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load root metadata from file")
}

// To verify: In BootstrapOnlineRoles return an error when targets signing fails; change Sign to succeed; test will fail (error expected).
func TestBootstrapOnlineRoles_Success_NoDelegations(t *testing.T) {
	payload, _, cleanup := makeValidRootAndPayload(t)
	defer cleanup()
	payload.Settings.Roles.Delegations = nil

	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	err := BootstrapOnlineRoles(client, "task-1", "admin", "app", payload)

	require.NoError(t, err)
}

// To verify: In BootstrapOnlineRoles skip the check for empty KeyIDs in delegated role; test will fail (no error).
func TestBootstrapOnlineRoles_DelegationRole_NoKeyIDs(t *testing.T) {
	payload, _, cleanup := makeValidRootAndPayload(t)
	defer cleanup()
	tsKeyID := ""
	for id := range payload.Metadata["root"].Signed.Keys {
		tsKeyID = id
		break
	}
	require.NotEmpty(t, tsKeyID)
	k := payload.Metadata["root"].Signed.Keys[tsKeyID]
	payload.Settings.Roles.Delegations = &models.TUFDelegations{
		Keys: map[string]models.TUFKey{tsKeyID: {KeyType: "ed25519", Scheme: "ed25519", KeyVal: models.TUFKeyVal{Public: k.KeyVal.Public}}},
		Roles: []models.TUFDelegatedRole{
			{Name: "delegated", KeyIDs: []string{}, Threshold: 1, Paths: []string{"*"}, Terminating: false},
		},
	}

	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	err := BootstrapOnlineRoles(client, "task-1", "admin", "app", payload)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no key IDs found for delegated role")
	assert.Contains(t, err.Error(), "delegated")
}

// To verify: In BootstrapOnlineRoles skip loading delegation private key and use a dummy signer; test will fail (no error or wrong signature).
func TestBootstrapOnlineRoles_DelegationRole_PrivateKeyNotFound(t *testing.T) {
	payload, _, cleanup := makeValidRootAndPayload(t)
	defer cleanup()
	// Use a key ID that does not exist on disk (not the timestamp key we wrote)
	fakeKeyID := "nonexistent-delegation-key-id"
	pub, _, _ := ed25519.GenerateKey(nil)
	hexPub := hex.EncodeToString(pub)
	payload.Settings.Roles.Delegations = &models.TUFDelegations{
		Keys: map[string]models.TUFKey{
			fakeKeyID: {KeyType: "ed25519", Scheme: "ed25519", KeyVal: models.TUFKeyVal{Public: hexPub}},
		},
		Roles: []models.TUFDelegatedRole{
			{Name: "delegated", KeyIDs: []string{fakeKeyID}, Threshold: 1, Paths: []string{"*"}, Terminating: false},
		},
	}

	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	err := BootstrapOnlineRoles(client, "task-1", "admin", "app", payload)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load delegation private key")
}

// makeValidRolesForValidateRoot creates a fully signed repository (root, targets, snapshot, timestamp).
// To verify: change AddKey or Sign so one role is invalid; ValidateRoot test will fail.
func makeValidRolesForValidateRoot(t *testing.T) *repository.Type {
	t.Helper()
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
	return roles
}

// To verify: In ValidateRoot skip VerifyDelegate("root", ...) or return nil; test will fail (no panic).
func TestValidateRoot_Success(t *testing.T) {
	roles := makeValidRolesForValidateRoot(t)

	assert.NotPanics(t, func() { ValidateRoot(roles) })
}

// To verify: In ValidateRoot remove the root verification block; test will fail (no panic on invalid root).
func TestValidateRoot_RootVerificationFails(t *testing.T) {
	expires := time.Now().Add(365 * 24 * time.Hour)
	roles := repository.New()
	rootKey, targetsKey := make([]ed25519.PrivateKey, 1), make([]ed25519.PrivateKey, 1)
	_, rootKey[0], _ = ed25519.GenerateKey(nil)
	_, targetsKey[0], _ = ed25519.GenerateKey(nil)

	roles.SetRoot(tuf_metadata.Root(expires))
	roles.SetTargets("targets", tuf_metadata.Targets(expires))
	roles.SetSnapshot(tuf_metadata.Snapshot(expires))
	roles.SetTimestamp(tuf_metadata.Timestamp(expires))

	rootPubKey, _ := tuf_metadata.KeyFromPublicKey(rootKey[0].Public())
	require.NoError(t, roles.Root().Signed.AddKey(rootPubKey, "root"))
	for _, name := range []string{"targets", "snapshot", "timestamp"} {
		_, priv, _ := ed25519.GenerateKey(nil)
		k, _ := tuf_metadata.KeyFromPublicKey(priv.Public())
		_ = roles.Root().Signed.AddKey(k, name)
		signer, _ := signature.LoadSigner(priv, crypto.Hash(0))
		switch name {
		case "targets":
			_, _ = roles.Targets("targets").Sign(signer)
		case "snapshot":
			_, _ = roles.Snapshot().Sign(signer)
		case "timestamp":
			_, _ = roles.Timestamp().Sign(signer)
		}
	}
	wrongSigner, _ := signature.LoadSigner(targetsKey[0], crypto.Hash(0))
	_, _ = roles.Root().Sign(wrongSigner)

	var panicMsg interface{}
	func() {
		defer func() { panicMsg = recover() }()
		ValidateRoot(roles)
	}()

	require.NotNil(t, panicMsg, "ValidateRoot should panic when root verification fails")
	assert.Contains(t, fmt.Sprint(panicMsg), "verifying root metadata failed")
}

// To verify: In ValidateRoot skip VerifyDelegate("targets", ...); test will fail (no panic).
func TestValidateRoot_TargetsVerificationFails(t *testing.T) {
	roles := makeValidRolesForValidateRoot(t)
	roles.SetTargets("targets", tuf_metadata.Targets(time.Now().Add(24*time.Hour)))

	var panicMsg interface{}
	func() {
		defer func() { panicMsg = recover() }()
		ValidateRoot(roles)
	}()

	require.NotNil(t, panicMsg, "ValidateRoot should panic when targets verification fails")
	assert.Contains(t, fmt.Sprint(panicMsg), "verifying targets metadata failed")
}

// To verify: In ValidateRoot skip VerifyDelegate("snapshot", ...); test will fail (no panic).
func TestValidateRoot_SnapshotVerificationFails(t *testing.T) {
	roles := makeValidRolesForValidateRoot(t)
	roles.SetSnapshot(tuf_metadata.Snapshot(time.Now().Add(24 * time.Hour)))

	var panicMsg interface{}
	func() {
		defer func() { panicMsg = recover() }()
		ValidateRoot(roles)
	}()

	require.NotNil(t, panicMsg, "ValidateRoot should panic when snapshot verification fails")
	assert.Contains(t, fmt.Sprint(panicMsg), "verifying snapshot metadata failed")
}

// To verify: In ValidateRoot skip VerifyDelegate("timestamp", ...); test will fail (no panic).
func TestValidateRoot_TimestampVerificationFails(t *testing.T) {
	roles := makeValidRolesForValidateRoot(t)
	roles.SetTimestamp(tuf_metadata.Timestamp(time.Now().Add(1 * time.Hour)))

	var panicMsg interface{}
	func() {
		defer func() { panicMsg = recover() }()
		ValidateRoot(roles)
	}()

	require.NotNil(t, panicMsg, "ValidateRoot should panic when timestamp verification fails")
	assert.Contains(t, fmt.Sprint(panicMsg), "verifying timestamp metadata failed")
}

// makeCurrentAndNewRootForVerify returns (currentRoot v1, newRoot v2) both valid for verifyNewRootMetadata.
// To verify: change version or signing so newRoot is invalid; TestVerifyNewRootMetadata_Success will fail.
func makeCurrentAndNewRootForVerify(t *testing.T) (currentRoot, newRoot *tuf_metadata.Metadata[tuf_metadata.RootType]) {
	t.Helper()
	expires := time.Now().Add(365 * 24 * time.Hour)
	_, rootKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	currentRepo := repository.New()
	currentRepo.SetRoot(tuf_metadata.Root(expires))
	rootPubKey, err := tuf_metadata.KeyFromPublicKey(rootKey.Public())
	require.NoError(t, err)
	require.NoError(t, currentRepo.Root().Signed.AddKey(rootPubKey, "root"))
	signer, err := signature.LoadSigner(rootKey, crypto.Hash(0))
	require.NoError(t, err)
	_, err = currentRepo.Root().Sign(signer)
	require.NoError(t, err)
	currentRoot = currentRepo.Root()
	require.Equal(t, int64(1), currentRoot.Signed.Version, "current root should be version 1")

	newRepo := repository.New()
	newRepo.SetRoot(tuf_metadata.Root(expires))
	newRepo.Root().Signed.Version = 2
	require.NoError(t, newRepo.Root().Signed.AddKey(rootPubKey, "root"))
	_, err = newRepo.Root().Sign(signer)
	require.NoError(t, err)
	newRoot = newRepo.Root()

	return currentRoot, newRoot
}

// To verify: In verifyNewRootMetadata remove the Type check or return nil; test will fail (no error).
func TestVerifyNewRootMetadata_Success(t *testing.T) {
	currentRoot, newRoot := makeCurrentAndNewRootForVerify(t)

	err := verifyNewRootMetadata(currentRoot, newRoot)

	require.NoError(t, err)
}

// To verify: In verifyNewRootMetadata skip the newRoot.Signed.Type check; test will fail (no error).
func TestVerifyNewRootMetadata_TypeNotRoot(t *testing.T) {
	currentRoot, newRoot := makeCurrentAndNewRootForVerify(t)
	newRoot.Signed.Type = "other"

	err := verifyNewRootMetadata(currentRoot, newRoot)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 'root'")
	assert.Contains(t, err.Error(), "other")
}

// To verify: In verifyNewRootMetadata skip the version check or use wrong expected version; test will fail (no error).
func TestVerifyNewRootMetadata_VersionMismatch(t *testing.T) {
	currentRoot, newRoot := makeCurrentAndNewRootForVerify(t)
	newRoot.Signed.Version = 1 // should be currentRoot.Signed.Version+1 (2)

	err := verifyNewRootMetadata(currentRoot, newRoot)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected root version 2, got version 1")
}

// To verify: In verifyNewRootMetadata skip currentRoot.VerifyDelegate check; test will fail (no error).
func TestVerifyNewRootMetadata_NotSignedByCurrentRoot(t *testing.T) {
	currentRoot, newRoot := makeCurrentAndNewRootForVerify(t)
	// Build a newRoot signed by a different key (not in current root's root role)
	_, otherKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	otherPub, _ := tuf_metadata.KeyFromPublicKey(otherKey.Public())
	newRepo2 := repository.New()
	newRepo2.SetRoot(tuf_metadata.Root(time.Now().Add(365 * 24 * time.Hour)))
	newRepo2.Root().Signed.Version = 2
	require.NoError(t, newRepo2.Root().Signed.AddKey(otherPub, "root"))
	otherSigner, _ := signature.LoadSigner(otherKey, crypto.Hash(0))
	_, _ = newRepo2.Root().Sign(otherSigner)
	newRoot = newRepo2.Root()

	err = verifyNewRootMetadata(currentRoot, newRoot)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "new root not signed by trusted root")
}

// To verify: In verifyNewRootMetadata skip newRoot.VerifyDelegate("root", newRoot) check; test will fail (no error).
func TestVerifyNewRootMetadata_ThresholdNotReached(t *testing.T) {
	expires := time.Now().Add(365 * 24 * time.Hour)
	_, rootKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, secondKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	rootPub, err := tuf_metadata.KeyFromPublicKey(rootKey.Public())
	require.NoError(t, err)
	secondPub, err := tuf_metadata.KeyFromPublicKey(secondKey.Public())
	require.NoError(t, err)

	currentRepo := repository.New()
	currentRepo.SetRoot(tuf_metadata.Root(expires))
	require.NoError(t, currentRepo.Root().Signed.AddKey(rootPub, "root"))
	signer, _ := signature.LoadSigner(rootKey, crypto.Hash(0))
	_, _ = currentRepo.Root().Sign(signer)
	currentRoot := currentRepo.Root()

	// New root: two keys, threshold 2, but sign only with first key so threshold not reached
	newRepo := repository.New()
	newRepo.SetRoot(tuf_metadata.Root(expires))
	newRepo.Root().Signed.Version = 2
	require.NoError(t, newRepo.Root().Signed.AddKey(rootPub, "root"))
	require.NoError(t, newRepo.Root().Signed.AddKey(secondPub, "root"))
	if r, ok := newRepo.Root().Signed.Roles["root"]; ok {
		r.Threshold = 2
		newRepo.Root().Signed.Roles["root"] = r
	}
	_, _ = newRepo.Root().Sign(signer) // only one signature
	newRoot := newRepo.Root()

	err = verifyNewRootMetadata(currentRoot, newRoot)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "new root threshold not reached")
}

// To verify: Change c.Query("appName") or c.ShouldBindJSON in PostMetadataRotate; test will fail (wrong status/body).
func makePostMetadataRotateContext(username string, appName string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/tuf/v1/metadata"
	if appName != "" {
		url += "?appName=" + appName
	}
	var bodyReader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
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

// To verify: In PostMetadataRotate remove GetUsernameFromContext check or return 200 on error; test will fail (wrong status).
func TestPostMetadataRotate_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	c, w := makePostMetadataRotateContext("", "myapp", models.MetadataPostPayload{Metadata: map[string]models.RootMetadata{"root": {}}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostMetadataRotate(c, client)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 when username is missing from context")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
}

// To verify: In PostMetadataRotate change appName empty check to return 200 or remove it; test will fail (wrong status).
func TestPostMetadataRotate_MissingAppName_ReturnsBadRequest(t *testing.T) {
	c, w := makePostMetadataRotateContext("admin", "", models.MetadataPostPayload{Metadata: map[string]models.RootMetadata{"root": {}}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_", "done")

	PostMetadataRotate(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when appName is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "appName query parameter is required", body["error"])
}

// To verify: In PostMetadataRotate remove nil redis check or return 200; test will fail (wrong status or panic).
func TestPostMetadataRotate_NilRedis_ReturnsServiceUnavailable(t *testing.T) {
	c, w := makePostMetadataRotateContext("admin", "myapp", models.MetadataPostPayload{Metadata: map[string]models.RootMetadata{"root": {}}})

	PostMetadataRotate(c, nil)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Expected 503 when Redis client is nil")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Redis client is not available", body["error"])
}

// To verify: In PostMetadataRotate remove bootstrap-missing branch or return 200; test will fail (wrong status).
func TestPostMetadataRotate_BootstrapMissing_ReturnsNotFound(t *testing.T) {
	c, w := makePostMetadataRotateContext("admin", "myapp", models.MetadataPostPayload{Metadata: map[string]models.RootMetadata{"root": {}}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostMetadataRotate(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap key is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "Task not accepted.")
	assert.Contains(t, body["error"], "Requires bootstrap finished")
}

// To verify: In PostMetadataRotate remove bootstrapValue == "" condition; test will fail (wrong status).
func TestPostMetadataRotate_BootstrapEmpty_ReturnsNotFound(t *testing.T) {
	c, w := makePostMetadataRotateContext("admin", "myapp", models.MetadataPostPayload{Metadata: map[string]models.RootMetadata{"root": {}}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "")

	PostMetadataRotate(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap value is empty")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Requires bootstrap finished")
}

// To verify: In PostMetadataRotate remove pre- prefix check; test will fail (wrong status).
func TestPostMetadataRotate_BootstrapPrePrefix_ReturnsNotFound(t *testing.T) {
	c, w := makePostMetadataRotateContext("admin", "myapp", models.MetadataPostPayload{Metadata: map[string]models.RootMetadata{"root": {}}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "pre-signing")

	PostMetadataRotate(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap is pre-*")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Requires bootstrap finished")
}

// To verify: In PostMetadataRotate remove signing- prefix check; test will fail (wrong status).
func TestPostMetadataRotate_BootstrapSigningPrefix_ReturnsNotFound(t *testing.T) {
	c, w := makePostMetadataRotateContext("admin", "myapp", models.MetadataPostPayload{Metadata: map[string]models.RootMetadata{"root": {}}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")

	PostMetadataRotate(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap is signing-*")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Requires bootstrap finished")
}

// To verify: In PostMetadataRotate ignore ShouldBindJSON error or return 200; test will fail (wrong status).
func TestPostMetadataRotate_InvalidJSON_ReturnsBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/metadata?appName=myapp", bytes.NewReader([]byte("not json")))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "admin")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")

	PostMetadataRotate(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when body is invalid JSON")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Invalid payload format")
}

// To verify: In PostMetadataRotate remove payload.Metadata[\"root\"] check or return 200; test will fail (wrong status).
func TestPostMetadataRotate_RootMetadataMissing_ReturnsBadRequest(t *testing.T) {
	c, w := makePostMetadataRotateContext("admin", "myapp", models.MetadataPostPayload{Metadata: map[string]models.RootMetadata{}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")

	PostMetadataRotate(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when root metadata is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Root metadata is required", body["error"])
}

// To verify: In PostMetadataRotate change error response when current root load fails; test will fail (wrong status or message).
func TestPostMetadataRotate_CurrentRootNotInStorage_ReturnsNotFound(t *testing.T) {
	payload, _, cleanup := makeValidRootAndPayload(t)
	defer cleanup()

	savedList := tuf_storage.ListMetadataForLatest
	savedViper := tuf_storage.GetViperForDownload
	savedFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("list failed")
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &downloadMockFactory{err: fmt.Errorf("create client failed")}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedViper
		tuf_storage.StorageFactoryForDownload = savedFactory
	}()

	c, w := makePostMetadataRotateContext("admin", "myapp", models.MetadataPostPayload{Metadata: map[string]models.RootMetadata{"root": payload.Metadata["root"]}})
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")

	PostMetadataRotate(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when current root cannot be loaded from storage")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Failed to load current root metadata from storage")
}

// To verify: Change c.Query("appName") in GetMetadataSign; test will fail (wrong status/body).
func makeGetMetadataSignContext(username string, appName string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/tuf/v1/metadata/sign"
	if appName != "" {
		url += "?appName=" + appName
	}
	c.Request = httptest.NewRequest(http.MethodGet, url, nil)
	if username != "" {
		c.Set("username", username)
	}
	return c, w
}

// To verify: Change c.Query("appName") or c.ShouldBindJSON in PostMetadataSign; test will fail (wrong status/body).
func makePostMetadataSignContext(username string, appName string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/tuf/v1/metadata/sign"
	if appName != "" {
		url += "?appName=" + appName
	}
	var bodyReader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
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

// makeValidRootJSONForSign creates a valid root JSON (one key, threshold 1, signed) that go-tuf can load and verify.
// Returns root JSON string and the root key ID. To verify: change AddKey or Sign so root is invalid; test will fail.
func makeValidRootJSONForSign(t *testing.T) (rootJSON string, keyID string) {
	t.Helper()
	expires := time.Now().Add(365 * 24 * time.Hour)
	roles := repository.New()
	roles.SetRoot(tuf_metadata.Root(expires))
	roles.SetTargets("targets", tuf_metadata.Targets(expires))
	roles.SetSnapshot(tuf_metadata.Snapshot(expires))
	roles.SetTimestamp(tuf_metadata.Timestamp(expires))

	_, rootPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	rootKey, err := tuf_metadata.KeyFromPublicKey(rootPriv.Public())
	require.NoError(t, err)
	for _, name := range []string{"root", "targets", "snapshot", "timestamp"} {
		require.NoError(t, roles.Root().Signed.AddKey(rootKey, name))
	}
	signer, err := signature.LoadSigner(rootPriv, crypto.Hash(0))
	require.NoError(t, err)
	_, err = roles.Root().Sign(signer)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	rootPath := filepath.Join(tmpDir, "1.root.json")
	require.NoError(t, roles.Root().ToFile(rootPath, true))
	data, err := os.ReadFile(rootPath)
	require.NoError(t, err)
	keyID = roles.Root().Signatures[0].KeyID
	return string(data), keyID
}

// makeValidTargetsJSONForSign returns valid targets JSON that go-tuf can load. To verify: change targets structure; test will fail.
func makeValidTargetsJSONForSign(t *testing.T) string {
	t.Helper()
	roles := makeValidRolesForValidateRoot(t)
	tmpDir := t.TempDir()
	targetsPath := filepath.Join(tmpDir, "1.targets.json")
	require.NoError(t, roles.Targets("targets").ToFile(targetsPath, true))
	data, err := os.ReadFile(targetsPath)
	require.NoError(t, err)
	return string(data)
}

// To verify: In GetMetadataSign remove GetUsernameFromContext check or return 200 on error; test will fail (wrong status).
func TestGetMetadataSign_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	c, w := makeGetMetadataSignContext("", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	GetMetadataSign(c, client)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 when username is missing from context")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
}

// To verify: In GetMetadataSign change appName empty check to return 200 or remove it; test will fail (wrong status).
func TestGetMetadataSign_MissingAppName_ReturnsBadRequest(t *testing.T) {
	c, w := makeGetMetadataSignContext("admin", "")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_", "done")

	GetMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 when appName is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "appName query parameter is required", body["error"])
}

// To verify: In GetMetadataSign remove nil redis check or return 200; test will fail (wrong status or panic).
func TestGetMetadataSign_NilRedis_ReturnsServiceUnavailable(t *testing.T) {
	c, w := makeGetMetadataSignContext("admin", "myapp")

	GetMetadataSign(c, nil)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Expected 503 when Redis client is nil")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Redis client is not available", body["error"])
}

// To verify: In GetMetadataSign remove bootstrap-missing branch or return 200; test will fail (wrong status).
func TestGetMetadataSign_BootstrapMissing_ReturnsNotFound(t *testing.T) {
	c, w := makeGetMetadataSignContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	GetMetadataSign(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap key is missing")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "No metadata pending signing available")
	assert.Contains(t, body["error"], "Requires bootstrap started")
}

// To verify: In GetMetadataSign remove bootstrapValue == "" condition; test will fail (wrong status).
func TestGetMetadataSign_BootstrapEmpty_ReturnsNotFound(t *testing.T) {
	c, w := makeGetMetadataSignContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "")

	GetMetadataSign(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap value is empty")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Requires bootstrap started")
}

// To verify: In GetMetadataSign remove the !isSigningState && !isCompleted check; test will fail (wrong status).
func TestGetMetadataSign_BootstrapPrePrefix_ReturnsNotFound(t *testing.T) {
	c, w := makeGetMetadataSignContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "pre-signing")

	GetMetadataSign(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when bootstrap is pre-* (not signing, not completed)")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "No metadata pending signing available")
	assert.Contains(t, body["error"], "Requires bootstrap started")
}

// To verify: In GetMetadataSign change the empty metadataResponse branch to return 404; test will fail (wrong status).
func TestGetMetadataSign_BootstrapSigning_NoSigningKeys_ReturnsOKWithNilData(t *testing.T) {
	c, w := makeGetMetadataSignContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")

	GetMetadataSign(c, client)

	assert.Equal(t, http.StatusOK, w.Code, "Expected 200 when in signing state but no signing keys set")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "No metadata pending signing available", body["message"])
	assert.Nil(t, body["data"])
}

// To verify: In GetMetadataSign skip adding ROOT_SIGNING_* to metadataResponse or change message; test will fail (wrong body).
func TestGetMetadataSign_BootstrapDone_WithRootSigning_ReturnsOKWithMetadata(t *testing.T) {
	rootJSON := []byte(`{"signed":{"_type":"root","version":1,"expires":"2030-01-01T00:00:00Z"},"signatures":[]}`)
	savedList := tuf_storage.ListMetadataForLatest
	savedViper := tuf_storage.GetViperForDownload
	savedFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.root.json"}, nil
	}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &downloadMockFactory{client: &downloadMockClient{body: rootJSON}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedViper
		tuf_storage.StorageFactoryForDownload = savedFactory
	}()

	c, w := makeGetMetadataSignContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")
	rootMeta := map[string]interface{}{"signed": map[string]interface{}{"_type": "root", "version": float64(1)}}
	rootJSONRedis, _ := json.Marshal(rootMeta)
	mr.Set("ROOT_SIGNING_admin_myapp", string(rootJSONRedis))

	GetMetadataSign(c, client)

	assert.Equal(t, http.StatusOK, w.Code, "Expected 200 when root signing key has valid JSON")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Metadata role(s) pending signing", body["message"])
	require.NotNil(t, body["data"])
	data, _ := body["data"].(map[string]interface{})
	require.NotNil(t, data["metadata"])
	meta, _ := data["metadata"].(map[string]interface{})
	assert.Contains(t, meta, "root")
}

// To verify: In GetMetadataSign remove the json.Unmarshal error check (continue on parse error); test may fail (wrong body).
func TestGetMetadataSign_InvalidJSONInSigningKey_SkipsKey(t *testing.T) {
	c, w := makeGetMetadataSignContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")
	mr.Set("ROOT_SIGNING_admin_myapp", "not valid json")

	GetMetadataSign(c, client)

	assert.Equal(t, http.StatusOK, w.Code, "Expected 200 when signing key has invalid JSON (key is skipped)")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "No metadata pending signing available", body["message"])
	assert.Nil(t, body["data"])
}

// To verify: In GetMetadataSign skip the delegated-role Keys(pattern) loop or roleLower assignment; test will fail (wrong body).
func TestGetMetadataSign_DelegatedRole_ReturnsOKWithMetadata(t *testing.T) {
	c, w := makeGetMetadataSignContext("admin", "myapp")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")
	delegatedMeta := map[string]interface{}{"signed": map[string]interface{}{"_type": "targets"}}
	delegatedJSON, _ := json.Marshal(delegatedMeta)
	mr.Set("DELEGATED_SIGNING_admin_myapp", string(delegatedJSON))

	GetMetadataSign(c, client)

	assert.Equal(t, http.StatusOK, w.Code, "Expected 200 when delegated role signing key has valid JSON")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Metadata role(s) pending signing", body["message"])
	require.NotNil(t, body["data"])
	data, _ := body["data"].(map[string]interface{})
	require.NotNil(t, data["metadata"])
	meta, _ := data["metadata"].(map[string]interface{})
	assert.Contains(t, meta, "delegated")
}

// --- PostMetadataSign tests ---

// To verify: In PostMetadataSign remove GetUsernameFromContext check or return 200 on error; test will fail (wrong status).
func TestPostMetadataSign_NoUsernameInContext_ReturnsUnauthorized(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Unauthorized", body["error"])
}

// To verify: In PostMetadataSign change appName empty check to return 200 or remove it; test will fail (wrong status).
func TestPostMetadataSign_MissingAppName_ReturnsBadRequest(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("admin", "", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_", "signing-root")

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "appName query parameter is required", body["error"])
}

// To verify: In PostMetadataSign remove nil redis check or return 200; test will fail (wrong status or panic).
func TestPostMetadataSign_NilRedis_ReturnsServiceUnavailable(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)

	PostMetadataSign(c, nil)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Redis client is not available", body["error"])
}

// To verify: In PostMetadataSign remove bootstrap-missing branch or return 200; test will fail (wrong status).
func TestPostMetadataSign_BootstrapMissing_ReturnsNotFound(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "No signing pending.")
}

// To verify: In PostMetadataSign remove bootstrapValue == "" condition; test will fail (wrong status).
func TestPostMetadataSign_BootstrapEmpty_ReturnsNotFound(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "")

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Requires bootstrap in signing state")
}

// To verify: In PostMetadataSign remove the !isSigningState && !isCompleted check; test will fail (wrong status).
func TestPostMetadataSign_BootstrapPrePrefix_ReturnsNotFound(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "pre-signing")

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "No signing pending.")
}

// To verify: In PostMetadataSign ignore ShouldBindJSON error or return 200; test will fail (wrong status).
func TestPostMetadataSign_InvalidJSON_ReturnsBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/tuf/v1/metadata/sign?appName=myapp", bytes.NewReader([]byte("not json")))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("username", "admin")
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")
	mr.Set("ROOT_SIGNING_admin_myapp", `{"signed":{},"signatures":[]}`)

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Invalid payload format")
}

// To verify: In PostMetadataSign remove the check for signing key missing; test will fail (wrong status).
func TestPostMetadataSign_BootstrapSigning_NoSigningKey_ReturnsNotFound(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "No signatures pending for root")
}

// To verify: In PostMetadataSign skip json.Unmarshal error for Redis metadata; test will fail (wrong status).
func TestPostMetadataSign_InvalidJSONInRedis_ReturnsInternalServerError(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")
	mr.Set("ROOT_SIGNING_admin_myapp", "not valid json")

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Failed to parse metadata", body["error"])
}

// To verify: In PostMetadataSign remove the check for missing 'signed' field; test will fail (wrong status).
func TestPostMetadataSign_MissingSignedField_ReturnsBadRequest(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")
	mr.Set("ROOT_SIGNING_admin_myapp", `{"signatures":[]}`)

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Invalid metadata format: missing 'signed' field", body["error"])
}

// To verify: In PostMetadataSign remove the check for missing '_type' field; test will fail (wrong status).
func TestPostMetadataSign_MissingTypeField_ReturnsBadRequest(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")
	mr.Set("ROOT_SIGNING_admin_myapp", `{"signed":{"version":1},"signatures":[]}`)

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Invalid metadata format: missing '_type' field", body["error"])
}

// To verify: In PostMetadataSign remove the default case for unsupported metadata type; test will fail (wrong status).
func TestPostMetadataSign_UnsupportedMetadataType_ReturnsBadRequest(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "snapshot", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")
	mr.Set("SNAPSHOT_SIGNING_admin_myapp", `{"signed":{"_type":"snapshot","version":1},"signatures":[]}`)

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Unsupported metadata type")
}

// To verify: In PostMetadataSign change error response when root FromFile fails; test will fail (wrong status).
func TestPostMetadataSign_Root_LoadFromFileFails_ReturnsBadRequest(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: "k1", Sig: "sig"}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")
	mr.Set("ROOT_SIGNING_admin_myapp", `{"signed":{"_type":"root","version":1,"expires":"2030-01-01T00:00:00Z","keys":{},"roles":{}},"signatures":[]}`)

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Failed to load root metadata")
}

// To verify: In PostMetadataSign remove bootstrap root validation or finalize; test will fail (wrong status or message).
func TestPostMetadataSign_RootBootstrapSigning_ThresholdReached_ReturnsOK(t *testing.T) {
	rootJSON, keyID := makeValidRootJSONForSign(t)
	var rootMap map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(rootJSON), &rootMap))
	sigs := rootMap["signatures"].([]interface{})
	sigStr := sigs[0].(map[string]interface{})["sig"].(string)

	savedUpload := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedUpload
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: keyID, Sig: sigStr}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")
	mr.Set("ROOT_SIGNING_admin_myapp", rootJSON)

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Bootstrap Finished", body["message"])
	require.NotNil(t, body["data"])
}

// To verify: In PostMetadataSign change response when threshold not reached; test will fail (wrong status or message).
func TestPostMetadataSign_RootBootstrapSigning_ThresholdNotReached_ReturnsBadRequest(t *testing.T) {
	rootJSON, keyID := makeValidRootJSONForSign(t)
	var rootMap map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(rootJSON), &rootMap))
	signedPart := rootMap["signed"].(map[string]interface{})
	// Build root with same signed body but one invalid signature (valid hex format so FromFile passes, but VerifyDelegate fails)
	invalidSigHex := hex.EncodeToString(make([]byte, 32))
	rootOneBadSig := map[string]interface{}{
		"signed":     signedPart,
		"signatures": []interface{}{map[string]interface{}{"keyid": keyID, "sig": invalidSigHex}},
	}
	rootOneBadSigJSON, _ := json.Marshal(rootOneBadSig)

	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: keyID, Sig: invalidSigHex}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")
	mr.Set("ROOT_SIGNING_admin_myapp", string(rootOneBadSigJSON))

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "Signature Failed", body["message"])
	assert.Contains(t, body["error"], "threshold not reached")
}

// To verify: In PostMetadataSign change error response when finalize fails; test will fail (wrong status).
func TestPostMetadataSign_Root_FinalizeFails_ReturnsInternalServerError(t *testing.T) {
	rootJSON, keyID := makeValidRootJSONForSign(t)
	var rootMap map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(rootJSON), &rootMap))
	sigs := rootMap["signatures"].([]interface{})
	sigStr := sigs[0].(map[string]interface{})["sig"].(string)

	savedUpload := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	tuf_storage.GetViperForUpload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{err: fmt.Errorf("create client failed")}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedUpload
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	payload := models.MetadataSignPostPayload{Role: "root", Signature: models.Signature{KeyID: keyID, Sig: sigStr}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "signing-root")
	mr.Set("ROOT_SIGNING_admin_myapp", rootJSON)

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Failed to finalize")
}

// To verify: In PostMetadataSign change error response when targets FromFile fails; test will fail (wrong status).
func TestPostMetadataSign_Targets_LoadFromFileFails_ReturnsBadRequest(t *testing.T) {
	payload := models.MetadataSignPostPayload{Role: "targets", Signature: models.Signature{KeyID: "k1", Sig: hex.EncodeToString(make([]byte, 32))}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")
	// Invalid signature hex so go-tuf FromFile fails when loading targets
	mr.Set("TARGETS_SIGNING_admin_myapp", `{"signed":{"_type":"targets","version":1,"expires":"2030-01-01T00:00:00Z","targets":{}},"signatures":[{"keyid":"k1","sig":"not-valid-hex"}]}`)

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "Failed to load targets metadata")
}

// To verify: In PostMetadataSign change response when targets threshold not reached; test will fail (wrong message).
func TestPostMetadataSign_Targets_ThresholdNotReached_ReturnsOKWithPending(t *testing.T) {
	targetsJSON := makeValidTargetsJSONForSign(t)
	payload := models.MetadataSignPostPayload{Role: "targets", Signature: models.Signature{KeyID: "k1", Sig: hex.EncodeToString(make([]byte, 32))}}
	c, w := makePostMetadataSignContext("admin", "myapp", payload)
	mr := miniredis.RunT(t)
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_admin_myapp", "done")
	mr.Set("TARGETS_SIGNING_admin_myapp", targetsJSON)

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("no targets in S3")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	PostMetadataSign(c, client)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Contains(t, body["message"], "pending signatures")
}

type uploadMockClient struct{}

func (u *uploadMockClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	return "https://mock/" + bucketName + "/" + objectKey, nil
}

func (u *uploadMockClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	panic("not used")
}

func (u *uploadMockClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	panic("not used")
}

func (u *uploadMockClient) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	panic("not used")
}

func (u *uploadMockClient) DownloadObject(ctx context.Context, bucketName, objectKey, filePath string) error {
	panic("not used")
}

func (u *uploadMockClient) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	panic("not used")
}

// uploadMockFactory returns a client that succeeds on upload (for BootstrapOnlineRoles tests).
type uploadMockFactory struct {
	client utils.StorageClient
	err    error
}

func (f *uploadMockFactory) CreateStorageClient() (utils.StorageClient, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.client != nil {
		return f.client, nil
	}
	return &uploadMockClient{}, nil
}

// uploadFailingMockClient implements utils.StorageClient for tests that require UploadPublicObject to fail.
type uploadFailingMockClient struct {
	err error
}

func (u *uploadFailingMockClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	if u.err != nil {
		return "", u.err
	}
	return "", nil
}

func (u *uploadFailingMockClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	panic("not used")
}

func (u *uploadFailingMockClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	panic("not used")
}

func (u *uploadFailingMockClient) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	panic("not used")
}

func (u *uploadFailingMockClient) DownloadObject(ctx context.Context, bucketName, objectKey string, filePath string) error {
	panic("not used")
}

func (u *uploadFailingMockClient) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	panic("not used")
}

// --- finalizeRootMetadataUpdate tests ---

// To verify: In finalizeRootMetadataUpdate remove the root == nil check or return nil; test will fail (no error when root is nil).
func TestFinalizeRootMetadataUpdate_RootNil_ReturnsError(t *testing.T) {
	ctx := context.Background()

	repo := repository.New()
	tmpDir := t.TempDir()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	err := finalizeRootMetadataUpdate(ctx, repo, "admin", "app", tmpDir, false, "", redisClient)

	require.Error(t, err, "Expected error when root metadata is not loaded")
	assert.Contains(t, err.Error(), "root metadata not loaded")
}

// To verify: In finalizeRootMetadataUpdate ignore root.ToFile error or return nil; test will fail (no error when ToFile fails).
func TestFinalizeRootMetadataUpdate_ToFileFails_ReturnsError(t *testing.T) {
	ctx := context.Background()
	repo := makeValidRolesForValidateRoot(t)
	// Use a path whose parent is a file so ToFile cannot create the output file.
	tmpDir := t.TempDir()
	fileAsDir := filepath.Join(tmpDir, "notadir")
	require.NoError(t, os.WriteFile(fileAsDir, []byte{}, 0644))
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	err := finalizeRootMetadataUpdate(ctx, repo, "admin", "app", fileAsDir, false, "", redisClient)

	require.Error(t, err, "Expected error when saving root metadata fails")
	assert.Contains(t, err.Error(), "failed to save root metadata")
}

// To verify: In finalizeRootMetadataUpdate ignore UploadMetadataToS3 error or return nil; test will fail (no error when S3 upload fails).
func TestFinalizeRootMetadataUpdate_UploadToS3Fails_ReturnsError(t *testing.T) {
	ctx := context.Background()
	repo := makeValidRolesForValidateRoot(t)
	tmpDir := t.TempDir()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	uploadErr := fmt.Errorf("s3 upload failed")
	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{client: &uploadFailingMockClient{err: uploadErr}}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	err := finalizeRootMetadataUpdate(ctx, repo, "admin", "app", tmpDir, false, "", redisClient)

	require.Error(t, err, "Expected error when S3 upload fails")
	assert.Contains(t, err.Error(), "failed to upload root metadata to S3")
}

// To verify: In finalizeRootMetadataUpdate change root filename format or skip upload; test will fail (wrong file or no upload).
func TestFinalizeRootMetadataUpdate_Success_NotBootstrap(t *testing.T) {
	ctx := context.Background()
	repo := makeValidRolesForValidateRoot(t)
	tmpDir := t.TempDir()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	err := finalizeRootMetadataUpdate(ctx, repo, "admin", "app", tmpDir, false, "", redisClient)

	require.NoError(t, err)
	rootFilename := fmt.Sprintf("%d.root.json", repo.Root().Signed.Version)
	assert.FileExists(t, filepath.Join(tmpDir, rootFilename), "Root metadata file should be written to tmpDir")
}

// To verify: In finalizeRootMetadataUpdate skip Redis Set when isBootstrap and bootstrapValue has "signing-" prefix; test will fail (key not set).
func TestFinalizeRootMetadataUpdate_Success_Bootstrap_WithSigningPrefix_SetsRedis(t *testing.T) {
	ctx := context.Background()
	repo := makeValidRolesForValidateRoot(t)
	tmpDir := t.TempDir()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	err := finalizeRootMetadataUpdate(ctx, repo, "admin", "myapp", tmpDir, true, "signing-task-123", redisClient)

	require.NoError(t, err)
	val, errRedis := redisClient.Get(ctx, "BOOTSTRAP_admin_myapp").Result()
	require.NoError(t, errRedis, "Redis Get should succeed")
	assert.Equal(t, "task-123", val, "Bootstrap key should store task ID without 'signing-' prefix")
}

// To verify: In finalizeRootMetadataUpdate call Redis Set even when bootstrapValue does not have "signing-" prefix; test would set key (wrong behavior).
func TestFinalizeRootMetadataUpdate_Success_Bootstrap_WithoutSigningPrefix_DoesNotSetRedis(t *testing.T) {
	ctx := context.Background()
	repo := makeValidRolesForValidateRoot(t)
	tmpDir := t.TempDir()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	err := finalizeRootMetadataUpdate(ctx, repo, "admin", "myapp", tmpDir, true, "done", redisClient)

	require.NoError(t, err)
	_, errRedis := redisClient.Get(ctx, "BOOTSTRAP_admin_myapp").Result()
	assert.Error(t, errRedis, "Bootstrap key should not be set when bootstrapValue does not start with 'signing-'")
}

// To verify: In finalizeRootMetadataUpdate return error when Redis Set fails in bootstrap path; test expects nil (only warning is logged).
func TestFinalizeRootMetadataUpdate_Success_Bootstrap_RedisSetFails_StillReturnsNil(t *testing.T) {
	ctx := context.Background()
	repo := makeValidRolesForValidateRoot(t)
	tmpDir := t.TempDir()
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: addr})

	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	err := finalizeRootMetadataUpdate(ctx, repo, "admin", "myapp", tmpDir, true, "signing-task-456", redisClient)

	require.NoError(t, err)
}

// --- finalizeTargetsMetadataUpdate tests ---

// To verify: In finalizeTargetsMetadataUpdate remove the targets == nil check or return nil; test will fail (no error when targets not loaded).
func TestFinalizeTargetsMetadataUpdate_TargetsNil_ReturnsError(t *testing.T) {
	ctx := context.Background()
	repo := repository.New()
	tmpDir := t.TempDir()

	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	err := finalizeTargetsMetadataUpdate(ctx, repo, "targets", "admin", "app", tmpDir)

	require.Error(t, err, "Expected error when targets metadata is not loaded")
	assert.Contains(t, err.Error(), "targets metadata not loaded for role targets")
}

// To verify: In finalizeTargetsMetadataUpdate ignore targets.ToFile error or return nil; test will fail (no error when ToFile fails).
func TestFinalizeTargetsMetadataUpdate_ToFileFails_ReturnsError(t *testing.T) {
	ctx := context.Background()
	repo := makeValidRolesForValidateRoot(t)
	tmpDir := t.TempDir()
	fileAsDir := filepath.Join(tmpDir, "notadir")
	require.NoError(t, os.WriteFile(fileAsDir, []byte{}, 0644))

	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	err := finalizeTargetsMetadataUpdate(ctx, repo, "targets", "admin", "app", fileAsDir)

	require.Error(t, err, "Expected error when saving targets metadata fails")
	assert.Contains(t, err.Error(), "failed to save targets metadata")
}

// To verify: In finalizeTargetsMetadataUpdate ignore UploadMetadataToS3 error or return nil; test will fail (no error when S3 upload fails).
func TestFinalizeTargetsMetadataUpdate_UploadToS3Fails_ReturnsError(t *testing.T) {
	ctx := context.Background()
	repo := makeValidRolesForValidateRoot(t)
	tmpDir := t.TempDir()
	uploadErr := fmt.Errorf("s3 upload failed")

	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{client: &uploadFailingMockClient{err: uploadErr}}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	err := finalizeTargetsMetadataUpdate(ctx, repo, "targets", "admin", "app", tmpDir)

	require.Error(t, err, "Expected error when S3 upload fails")
	assert.Contains(t, err.Error(), "failed to upload targets metadata to S3")
}

// To verify: In finalizeTargetsMetadataUpdate change targets filename format or skip upload; test will fail (wrong file or no upload).
func TestFinalizeTargetsMetadataUpdate_Success_NoSnapshotUpdate(t *testing.T) {
	ctx := context.Background()
	repo := makeValidRolesForValidateRoot(t)
	tmpDir := t.TempDir()

	savedList := tuf_storage.ListMetadataForLatest
	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, nil // no snapshot file
	}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	}()

	err := finalizeTargetsMetadataUpdate(ctx, repo, "targets", "admin", "app", tmpDir)

	require.NoError(t, err)
	targetsFilename := fmt.Sprintf("%d.targets.json", repo.Targets("targets").Signed.Version)
	assert.FileExists(t, filepath.Join(tmpDir, targetsFilename), "Targets metadata file should be written to tmpDir")
}

// To verify: In finalizeTargetsMetadataUpdate skip snapshot load/update block (FindLatestMetadataVersion or Download); test would not exercise snapshot path.
func TestFinalizeTargetsMetadataUpdate_Success_WithSnapshotUpdate(t *testing.T) {
	ctx := context.Background()
	repo := makeValidRolesForValidateRoot(t)
	tmpDir := t.TempDir()

	snapshotTmp := t.TempDir()
	snapshotPath := filepath.Join(snapshotTmp, "1.snapshot.json")
	require.NoError(t, repo.Snapshot().ToFile(snapshotPath, true))
	snapshotBody, err := os.ReadFile(snapshotPath)
	require.NoError(t, err)

	savedList := tuf_storage.ListMetadataForLatest
	savedViperUpload := tuf_storage.GetViperForUpload
	savedFactoryUpload := tuf_storage.StorageFactoryForUpload
	savedViperDownload := tuf_storage.GetViperForDownload
	savedFactoryDownload := tuf_storage.StorageFactoryForDownload

	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.snapshot.json"}, nil
	}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{}
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &downloadMockFactory{client: &downloadMockClient{body: snapshotBody}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForUpload = savedViperUpload
		tuf_storage.StorageFactoryForUpload = savedFactoryUpload
		tuf_storage.GetViperForDownload = savedViperDownload
		tuf_storage.StorageFactoryForDownload = savedFactoryDownload
	}()

	err = finalizeTargetsMetadataUpdate(ctx, repo, "targets", "admin", "app", tmpDir)

	require.NoError(t, err)
	targetsFilename := fmt.Sprintf("%d.targets.json", repo.Targets("targets").Signed.Version)
	assert.FileExists(t, filepath.Join(tmpDir, targetsFilename), "Targets metadata file should be written to tmpDir")
	newSnapshotFilename := fmt.Sprintf("%d.snapshot.json", repo.Snapshot().Signed.Version)
	assert.FileExists(t, filepath.Join(tmpDir, newSnapshotFilename), "New snapshot metadata file should be written when snapshot path runs")
}

// --- loadTrustedRootFromS3 tests ---

// downloadMockClient implements utils.StorageClient for loadTrustedRootFromS3 tests; only DownloadObject is used.
type downloadMockClient struct {
	body []byte
}

func (d *downloadMockClient) DownloadObject(ctx context.Context, bucketName, objectKey, filePath string) error {
	if d.body == nil {
		d.body = []byte(`{"signed":{"_type":"root","version":1},"signatures":[]}`)
	}
	return os.WriteFile(filePath, d.body, 0644)
}

func (d *downloadMockClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	panic("not used")
}

func (d *downloadMockClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	panic("not used")
}

func (d *downloadMockClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	panic("not used")
}

func (d *downloadMockClient) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	panic("not used")
}

func (d *downloadMockClient) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	panic("not used")
}

// downloadMockFactory returns a fixed client (or error) for loadTrustedRootFromS3 tests.
type downloadMockFactory struct {
	client utils.StorageClient
	err    error
}

func (f *downloadMockFactory) CreateStorageClient() (utils.StorageClient, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.client, nil
}

// To verify: In loadTrustedRootFromS3 change the return error message or return nil when download fails; test will fail (no error or wrong message).
func TestLoadTrustedRootFromS3_StorageUnavailable_ReturnsError(t *testing.T) {
	ctx := context.Background()
	// Use mocks that fail so real storage is never called (no "unknown storage driver" logs).
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

	result, err := loadTrustedRootFromS3(ctx, "admin", "myapp")

	require.Error(t, err, "Expected error when S3/storage is unavailable")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to download root metadata")
}

// To verify: In loadTrustedRootFromS3 skip ReadFile or json.Unmarshal; test will fail (nil result or wrong content).
func TestLoadTrustedRootFromS3_Success_WithMockedStorage(t *testing.T) {
	ctx := context.Background()
	rootJSON := []byte(`{"signed":{"_type":"root","version":1,"expires":"2030-01-01T00:00:00Z"},"signatures":[]}`)

	savedList := tuf_storage.ListMetadataForLatest
	savedViper := tuf_storage.GetViperForDownload
	savedFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.root.json"}, nil
	}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &downloadMockFactory{client: &downloadMockClient{body: rootJSON}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedViper
		tuf_storage.StorageFactoryForDownload = savedFactory
	}()

	result, err := loadTrustedRootFromS3(ctx, "admin", "myapp")

	require.NoError(t, err, "Expected success when storage is mocked")
	require.NotNil(t, result)
	assert.Equal(t, "root", result["signed"].(map[string]interface{})["_type"])
	assert.Equal(t, float64(1), result["signed"].(map[string]interface{})["version"])
}

// To verify: In loadTrustedRootFromS3 skip os.ReadFile error or return nil; test will fail (no error).
func TestLoadTrustedRootFromS3_ReadFileFailure_ReturnsError(t *testing.T) {
	ctx := context.Background()

	savedList := tuf_storage.ListMetadataForLatest
	savedFactory := tuf_storage.StorageFactoryForDownload
	savedViper := tuf_storage.GetViperForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("list failed")
	}
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &downloadMockFactory{err: fmt.Errorf("create client failed")}
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.StorageFactoryForDownload = savedFactory
		tuf_storage.GetViperForDownload = savedViper
	}()

	result, err := loadTrustedRootFromS3(ctx, "admin", "nonexistent")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, strings.Contains(err.Error(), "failed to download root metadata") ||
		strings.Contains(err.Error(), "failed to read root metadata") ||
		strings.Contains(err.Error(), "failed to parse root metadata"),
		"expected download/read/parse error, got: %s", err.Error())
}

// --- loadTrustedTargetsFromS3 tests ---

// To verify: In loadTrustedTargetsFromS3 change the return error message or return nil when FindLatestMetadataVersion fails; test will fail (no error or wrong message).
func TestLoadTrustedTargetsFromS3_FindFails_ReturnsError(t *testing.T) {
	ctx := context.Background()
	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("list failed")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	result, err := loadTrustedTargetsFromS3(ctx, "admin", "myapp")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to find targets metadata")
}

// To verify: In loadTrustedTargetsFromS3 change the return error when download fails; test will fail (no error or wrong message).
func TestLoadTrustedTargetsFromS3_DownloadFails_ReturnsError(t *testing.T) {
	ctx := context.Background()
	savedList := tuf_storage.ListMetadataForLatest
	savedViper := tuf_storage.GetViperForDownload
	savedFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &downloadMockFactory{err: fmt.Errorf("create client failed")}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedViper
		tuf_storage.StorageFactoryForDownload = savedFactory
	}()

	result, err := loadTrustedTargetsFromS3(ctx, "admin", "myapp")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to download targets metadata")
}

// To verify: In loadTrustedTargetsFromS3 skip ReadFile or json.Unmarshal; test will fail (nil result or wrong content).
func TestLoadTrustedTargetsFromS3_Success_WithMockedStorage(t *testing.T) {
	ctx := context.Background()
	targetsJSON := []byte(`{"signed":{"_type":"targets","version":2,"expires":"2030-01-01T00:00:00Z"},"signatures":[]}`)

	savedList := tuf_storage.ListMetadataForLatest
	savedViper := tuf_storage.GetViperForDownload
	savedFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json"}, nil
	}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &downloadMockFactory{client: &downloadMockClient{body: targetsJSON}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedViper
		tuf_storage.StorageFactoryForDownload = savedFactory
	}()

	result, err := loadTrustedTargetsFromS3(ctx, "admin", "myapp")

	require.NoError(t, err, "Expected success when storage is mocked")
	require.NotNil(t, result)
	assert.Equal(t, "targets", result["signed"].(map[string]interface{})["_type"])
	assert.Equal(t, float64(2), result["signed"].(map[string]interface{})["version"])
}
