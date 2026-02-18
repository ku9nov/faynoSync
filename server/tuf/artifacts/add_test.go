package artifacts

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"testing"
	"time"

	"faynoSync/server/tuf/models"
	tuf_storage "faynoSync/server/tuf/storage"
	tuf_utils "faynoSync/server/tuf/utils"
	"faynoSync/server/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	testAdminName = "admin"
	testAppName   = "app"
	testTaskID    = "task-123"
)

type fsStorageClient struct {
	baseDir string
}

func (c *fsStorageClient) DownloadObject(ctx context.Context, bucketName, objectKey, filePath string) error {
	src := filepath.Join(c.baseDir, objectKey)
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", src, err)
	}
	return os.WriteFile(filePath, data, 0644)
}

func (c *fsStorageClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	panic("not used")
}

func (c *fsStorageClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	dst := filepath.Join(c.baseDir, objectKey)
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return "", err
	}
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = io.Copy(f, fileReader)
	return "", err
}

func (c *fsStorageClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	panic("not used")
}

func (c *fsStorageClient) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	panic("not used")
}

func (c *fsStorageClient) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	var keys []string
	if err := filepath.Walk(c.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(c.baseDir, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if prefix == "" || (len(key) >= len(prefix) && key[:len(prefix)] == prefix) {
			keys = append(keys, key)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return keys, nil
}

type fsStorageFactory struct {
	client utils.StorageClient
}

func (f *fsStorageFactory) CreateStorageClient() (utils.StorageClient, error) {
	return f.client, nil
}

func makeAddArtifactsTestEnv(t *testing.T, adminName, appName string) (storeDir, keyDir string, cleanup func()) {
	t.Helper()
	rootTmp := t.TempDir()
	keyDir = t.TempDir()
	storeDir = t.TempDir()

	expires := time.Now().Add(365 * 24 * time.Hour)
	keys := map[string]ed25519.PrivateKey{}
	roles := repository.New()

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
	require.NoError(t, roles.Root().ToFile(rootPath, true))
	rootJSON, err := os.ReadFile(rootPath)
	require.NoError(t, err)

	var rootMeta models.RootMetadata
	require.NoError(t, json.Unmarshal(rootJSON, &rootMeta))

	for _, name := range []string{"timestamp", "snapshot", "targets"} {
		role, ok := rootMeta.Signed.Roles[name]
		require.True(t, ok)
		require.NotEmpty(t, role.KeyIDs)
		keyID := role.KeyIDs[0]
		seed := keys[name].Seed()
		require.NoError(t, os.WriteFile(filepath.Join(keyDir, keyID), seed, 0600))
	}

	targetsKeyID := rootMeta.Signed.Roles["targets"].KeyIDs[0]
	targetsKey := roles.Root().Signed.Keys[targetsKeyID]
	require.NotNil(t, targetsKey)

	exp := tuf_utils.HelperExpireIn(365)
	targets := tuf_metadata.Targets(exp)
	targets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys:  map[string]*tuf_metadata.Key{targetsKeyID: targetsKey},
		Roles: []tuf_metadata.DelegatedRole{{Name: "updates", KeyIDs: []string{targetsKeyID}, Threshold: 1, Paths: []string{"updates/"}}},
	}
	roles.SetTargets("targets", targets)
	targetsSigner, err := signature.LoadSigner(keys["targets"], crypto.Hash(0))
	require.NoError(t, err)
	_, err = roles.Targets("targets").Sign(targetsSigner)
	require.NoError(t, err)
	targetsPath := filepath.Join(rootTmp, "2.targets.json")
	require.NoError(t, roles.Targets("targets").ToFile(targetsPath, true))
	targetsJSON, err := os.ReadFile(targetsPath)
	require.NoError(t, err)

	metadataPrefix := filepath.Join(storeDir, "tuf_metadata", adminName, appName)
	require.NoError(t, os.MkdirAll(metadataPrefix, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(metadataPrefix, "1.root.json"), rootJSON, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(metadataPrefix, "2.targets.json"), targetsJSON, 0644))

	savedList := tuf_storage.ListMetadataForLatest
	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
	savedGetViperU := tuf_storage.GetViperForUpload
	savedFactoryU := tuf_storage.StorageFactoryForUpload

	client := &fsStorageClient{baseDir: storeDir}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")

	tuf_storage.ListMetadataForLatest = func(ctx context.Context, a, p, prefix string) ([]string, error) {
		if a != adminName || p != appName {
			return nil, fmt.Errorf("unexpected admin/app")
		}
		return []string{"1.root.json", "2.targets.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: client}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: client}
	}

	oldKeyDir := viper.GetViper().GetString("ONLINE_KEY_DIR")
	viper.GetViper().Set("ONLINE_KEY_DIR", keyDir)

	cleanup = func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
		tuf_storage.GetViperForUpload = savedGetViperU
		tuf_storage.StorageFactoryForUpload = savedFactoryU
		viper.GetViper().Set("ONLINE_KEY_DIR", oldKeyDir)
	}
	return storeDir, keyDir, cleanup
}

// To verify: In AddArtifacts change the bootstrap key check (BOOTSTRAP_...) or the redis.Nil/empty handling; test will fail (no error or wrong message).
func TestAddArtifacts_BootstrapNotCompleted_ReturnsError(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	// Do not set BOOTSTRAP_admin_app so bootstrap is not completed

	err := AddArtifacts(ctx, redisClient, nil, testAdminName, testAppName, []Artifact{}, false, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap not completed")
	t.Logf("Inputs: admin=%q app=%q; Result: err=%v", testAdminName, testAppName, err)
}

// To verify: In AddArtifacts remove the check for bootstrapValue == ""; test with empty value may pass incorrectly.
func TestAddArtifacts_BootstrapKeyEmpty_ReturnsError(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "")

	err := AddArtifacts(ctx, redisClient, nil, testAdminName, testAppName, []Artifact{}, false, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap not completed")
}

// To verify: In AddArtifacts remove the "no valid artifacts" check after filtering invalid paths; test will fail (panic or wrong behavior).
func TestAddArtifacts_NoValidArtifacts_ReturnsError(t *testing.T) {
	storeDir, _, cleanup := makeAddArtifactsTestEnv(t, testAdminName, testAppName)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "done")

	// Path that does not match any delegation (e.g. "updates/" is the only path; use something else)
	artifacts := []Artifact{
		{Path: "other/unknown.exe", Info: ArtifactInfo{Length: 100, Hashes: map[string]string{"sha256": "abc"}}},
	}

	t.Logf("Inputs: artifacts=%v; storeDir=%s", artifacts, storeDir)
	err := AddArtifacts(ctx, redisClient, nil, testAdminName, testAppName, artifacts, false, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid artifacts to add")
}

// To verify: In AddArtifacts change getRoleForArtifactPath or delegation path matching; test will fail (error or no update).
func TestAddArtifacts_ValidArtifact_NoPublish_Success(t *testing.T) {
	_, _, cleanup := makeAddArtifactsTestEnv(t, testAdminName, testAppName)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "done")
	mr.Set("TARGETS_EXPIRATION_"+testAdminName+"_"+testAppName, "365")

	artifacts := []Artifact{
		{Path: "updates/app-1.0.0.tar", Info: ArtifactInfo{Length: 1024, Hashes: map[string]string{"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}},
	}

	err := AddArtifacts(ctx, redisClient, nil, testAdminName, testAppName, artifacts, false, testTaskID)

	require.NoError(t, err)
	// Task status should be saved
	val, err := redisClient.Get(ctx, "task:"+testTaskID).Result()
	require.NoError(t, err)
	require.NotEmpty(t, val)
	t.Logf("Inputs: artifacts=%v; Result: success, task status saved", artifacts)
}

// To verify: In AddArtifacts change error handling for FindLatestMetadataVersion (targets); test will fail (no error or wrong message).
func TestAddArtifacts_FindLatestTargetsFails_ReturnsError(t *testing.T) {
	_, _, cleanup := makeAddArtifactsTestEnv(t, testAdminName, testAppName)
	defer cleanup()

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("list failed")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "done")

	artifacts := []Artifact{
		{Path: "updates/app.tar", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}

	err := AddArtifacts(ctx, redisClient, nil, testAdminName, testAppName, artifacts, false, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find latest targets version")
}

// To verify: In AddArtifacts change error handling when DownloadMetadataFromS3 fails for root; test will fail (no error or wrong message).
func TestAddArtifacts_DownloadRootFails_ReturnsError(t *testing.T) {
	_, _, cleanup := makeAddArtifactsTestEnv(t, testAdminName, testAppName)
	defer cleanup()

	savedFactoryD := tuf_storage.StorageFactoryForDownload
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &failDownloadClient{}}
	}
	defer func() { tuf_storage.StorageFactoryForDownload = savedFactoryD }()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "done")

	err := AddArtifacts(ctx, redisClient, nil, testAdminName, testAppName, []Artifact{
		{Path: "updates/x", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}, false, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to download latest root metadata")
}

type failDownloadClient struct{}

func (c *failDownloadClient) DownloadObject(ctx context.Context, bucketName, objectKey, filePath string) error {
	return fmt.Errorf("download failed")
}
func (c *failDownloadClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	panic("not used")
}
func (c *failDownloadClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	panic("not used")
}
func (c *failDownloadClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	panic("not used")
}
func (c *failDownloadClient) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	panic("not used")
}
func (c *failDownloadClient) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	panic("not used")
}

// failUploadClient returns error on UploadPublicObject (for testing upload failure path).
type failUploadClient struct{}

func (c *failUploadClient) DownloadObject(ctx context.Context, bucketName, objectKey, filePath string) error {
	panic("not used")
}
func (c *failUploadClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	panic("not used")
}
func (c *failUploadClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	return "", fmt.Errorf("upload failed")
}
func (c *failUploadClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	panic("not used")
}
func (c *failUploadClient) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	panic("not used")
}
func (c *failUploadClient) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	panic("not used")
}

// To verify: In AddArtifacts skip loading timestamp private key error; test will fail (no error or wrong message).
func TestAddArtifacts_LoadTimestampKeyFails_ReturnsError(t *testing.T) {
	storeDir, _, cleanup := makeAddArtifactsTestEnv(t, testAdminName, testAppName)
	defer cleanup()
	_ = storeDir
	emptyKeyDir := t.TempDir()
	oldDir := viper.GetViper().GetString("ONLINE_KEY_DIR")
	viper.GetViper().Set("ONLINE_KEY_DIR", emptyKeyDir)
	defer viper.GetViper().Set("ONLINE_KEY_DIR", oldDir)

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "done")

	err := AddArtifacts(ctx, redisClient, nil, testAdminName, testAppName, []Artifact{
		{Path: "updates/x", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}, false, testTaskID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load timestamp private key")
}

// To verify: In AddArtifacts when some paths are invalid, result should still succeed and invalid_paths reported in details.
func TestAddArtifacts_MixedValidAndInvalidPaths_SuccessWithInvalidSkipped(t *testing.T) {
	_, _, cleanup := makeAddArtifactsTestEnv(t, testAdminName, testAppName)
	defer cleanup()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Set("BOOTSTRAP_"+testAdminName+"_"+testAppName, "done")
	mr.Set("TARGETS_EXPIRATION_"+testAdminName+"_"+testAppName, "365")

	artifacts := []Artifact{
		{Path: "updates/valid.tar", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
		{Path: "invalid/path.exe", Info: ArtifactInfo{Length: 2, Hashes: map[string]string{"sha256": "cd"}}},
	}

	err := AddArtifacts(ctx, redisClient, nil, testAdminName, testAppName, artifacts, false, testTaskID)

	require.NoError(t, err)
	val, err := redisClient.Get(ctx, "task:"+testTaskID).Result()
	require.NoError(t, err)
	require.NotEmpty(t, val)
	var taskData struct {
		State  string `json:"state"`
		Result *struct {
			Details map[string]interface{} `json:"details"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(val), &taskData))
	require.Equal(t, "SUCCESS", taskData.State)
	require.NotNil(t, taskData.Result)
	require.NotNil(t, taskData.Result.Details)
	invalidPaths, _ := taskData.Result.Details["invalid_paths"].([]interface{})
	require.NotEmpty(t, invalidPaths)
	assert.Contains(t, taskData.Result.Details["invalid_paths"], "invalid/path.exe")
	t.Logf("Inputs: artifacts=%v; Result: success with invalid_paths in details", artifacts)
}

// --- getRoleForArtifactPath tests ---

func repoWithNoTargetsForGetRole() *repository.Type {
	return repository.New()
}

func repoWithTargetsNoDelegationsForGetRole() *repository.Type {
	repo := repository.New()
	targets := tuf_metadata.Targets(time.Now().Add(24 * time.Hour))
	repo.SetTargets("targets", targets)
	return repo
}

func repoWithTargetsDelegationsRolesNilForGetRole() *repository.Type {
	repo := repository.New()
	targets := tuf_metadata.Targets(time.Now().Add(24 * time.Hour))
	targets.Signed.Delegations = &tuf_metadata.Delegations{Keys: map[string]*tuf_metadata.Key{}, Roles: nil}
	repo.SetTargets("targets", targets)
	return repo
}

func repoWithTargetsDelegationsRolesEmptyForGetRole() *repository.Type {
	repo := repository.New()
	targets := tuf_metadata.Targets(time.Now().Add(24 * time.Hour))
	targets.Signed.Delegations = &tuf_metadata.Delegations{Keys: map[string]*tuf_metadata.Key{}, Roles: []tuf_metadata.DelegatedRole{}}
	repo.SetTargets("targets", targets)
	return repo
}

func repoWithTargetsAndOneRoleForGetRole(roleName string, paths []string) *repository.Type {
	repo := repository.New()
	targets := tuf_metadata.Targets(time.Now().Add(24 * time.Hour))
	targets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys:  map[string]*tuf_metadata.Key{},
		Roles: []tuf_metadata.DelegatedRole{{Name: roleName, KeyIDs: []string{"k1"}, Threshold: 1, Paths: paths}},
	}
	repo.SetTargets("targets", targets)
	return repo
}

func repoWithTargetsAndRolePathHashPrefixesForGetRole(roleName string, pathHashPrefixes []string) *repository.Type {
	repo := repository.New()
	targets := tuf_metadata.Targets(time.Now().Add(24 * time.Hour))
	targets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys:  map[string]*tuf_metadata.Key{},
		Roles: []tuf_metadata.DelegatedRole{{Name: roleName, KeyIDs: []string{"k1"}, Threshold: 1, PathHashPrefixes: pathHashPrefixes}},
	}
	repo.SetTargets("targets", targets)
	return repo
}

func repoWithTargetsAndMultipleRolesForGetRole(roles []struct {
	Name  string
	Paths []string
}) *repository.Type {
	repo := repository.New()
	targets := tuf_metadata.Targets(time.Now().Add(24 * time.Hour))
	delegatedRoles := make([]tuf_metadata.DelegatedRole, 0, len(roles))
	for _, r := range roles {
		delegatedRoles = append(delegatedRoles, tuf_metadata.DelegatedRole{Name: r.Name, KeyIDs: []string{"k1"}, Threshold: 1, Paths: r.Paths})
	}
	targets.Signed.Delegations = &tuf_metadata.Delegations{Keys: map[string]*tuf_metadata.Key{}, Roles: delegatedRoles}
	repo.SetTargets("targets", targets)
	return repo
}

// To verify: In getRoleForArtifactPath change the condition so repo.Targets("targets") nil is not treated as error; test will fail (no error or wrong message).
func TestGetRoleForArtifactPath_TargetsNotLoaded_ReturnsError(t *testing.T) {
	repo := repoWithNoTargetsForGetRole()

	roleName, err := getRoleForArtifactPath(repo, "any/path")

	require.Error(t, err)
	assert.Empty(t, roleName)
	assert.Contains(t, err.Error(), "targets metadata not loaded")
}

// To verify: In getRoleForArtifactPath skip the check for delegations == nil; test will fail (panic or wrong error).
func TestGetRoleForArtifactPath_NoDelegations_ReturnsError(t *testing.T) {
	repo := repoWithTargetsNoDelegationsForGetRole()

	roleName, err := getRoleForArtifactPath(repo, "any/path")

	require.Error(t, err)
	assert.Empty(t, roleName)
	assert.Contains(t, err.Error(), "no delegations found in targets metadata")
}

// To verify: In getRoleForArtifactPath skip the check for delegations.Roles == nil; test will fail (panic or wrong error).
func TestGetRoleForArtifactPath_DelegationsRolesNil_ReturnsError(t *testing.T) {
	repo := repoWithTargetsDelegationsRolesNilForGetRole()

	roleName, err := getRoleForArtifactPath(repo, "any/path")

	require.Error(t, err)
	assert.Empty(t, roleName)
	assert.Contains(t, err.Error(), "no delegated role found for path")
}

// To verify: In getRoleForArtifactPath when Roles is empty slice, return error with path; change to return first role and test will fail.
func TestGetRoleForArtifactPath_DelegationsRolesEmpty_ReturnsError(t *testing.T) {
	repo := repoWithTargetsDelegationsRolesEmptyForGetRole()

	roleName, err := getRoleForArtifactPath(repo, "updates/app.tar")

	require.Error(t, err)
	assert.Empty(t, roleName)
	assert.Contains(t, err.Error(), "no delegated role found for path: updates/app.tar")
}

// To verify: In getRoleForArtifactPath change path matching so non-matching path is accepted; test will fail (wrong role or no error).
func TestGetRoleForArtifactPath_NoMatchingPath_ReturnsError(t *testing.T) {
	repo := repoWithTargetsAndOneRoleForGetRole("updates", []string{"updates/"})

	roleName, err := getRoleForArtifactPath(repo, "other/unknown.exe")

	require.Error(t, err)
	assert.Empty(t, roleName)
	assert.Contains(t, err.Error(), "no delegated role found for path: other/unknown.exe")
}

// To verify: In getRoleForArtifactPath change path matching (e.g. use exact match instead of prefix) or role return; test will fail (wrong role name).
func TestGetRoleForArtifactPath_PathMatchesByPrefix_ReturnsRoleName(t *testing.T) {
	repo := repoWithTargetsAndOneRoleForGetRole("updates", []string{"updates/"})

	roleName, err := getRoleForArtifactPath(repo, "updates/app-1.0.0.tar")

	require.NoError(t, err)
	assert.Equal(t, "updates", roleName)
}

// To verify: In getRoleForArtifactPath change PathHashPrefixes matching; test will fail (wrong role or no match).
// Path "a" has hex representation "61"; prefix "6" matches.
func TestGetRoleForArtifactPath_PathMatchesByPathHashPrefix_ReturnsRoleName(t *testing.T) {
	repo := repoWithTargetsAndRolePathHashPrefixesForGetRole("hashed-role", []string{"61"})

	roleName, err := getRoleForArtifactPath(repo, "a")

	require.NoError(t, err)
	assert.Equal(t, "hashed-role", roleName)
}

// To verify: In getRoleForArtifactPath change iteration order or return logic so second matching role is not returned; test will fail (wrong role).
func TestGetRoleForArtifactPath_MultipleRoles_ReturnsFirstMatchingRole(t *testing.T) {
	repo := repoWithTargetsAndMultipleRolesForGetRole([]struct {
		Name  string
		Paths []string
	}{
		{Name: "other", Paths: []string{"other/"}},
		{Name: "updates", Paths: []string{"updates/"}},
	})

	roleName, err := getRoleForArtifactPath(repo, "updates/app.tar")

	require.NoError(t, err)
	assert.Equal(t, "updates", roleName)
}

// To verify: In getRoleForArtifactPath when path matches first role, return that role name; change to return second and test will fail.
func TestGetRoleForArtifactPath_MultipleRoles_FirstRoleMatches_ReturnsFirst(t *testing.T) {
	repo := repoWithTargetsAndMultipleRolesForGetRole([]struct {
		Name  string
		Paths []string
	}{
		{Name: "updates", Paths: []string{"updates/"}},
		{Name: "releases", Paths: []string{"releases/"}},
	})

	roleName, err := getRoleForArtifactPath(repo, "updates/foo.zip")

	require.NoError(t, err)
	assert.Equal(t, "updates", roleName)
}

// --- matchesRole tests ---

// To verify: In matchesRole remove the role == nil check; test will panic when role is nil.
func TestMatchesRole_NilRole_ReturnsFalse(t *testing.T) {
	got := matchesRole("any/path", nil)
	assert.False(t, got)
}

// To verify: In matchesRole when Paths and PathHashPrefixes are empty, return false; change to true and test will fail.
func TestMatchesRole_EmptyPathsAndPathHashPrefixes_ReturnsFalse(t *testing.T) {
	role := &tuf_metadata.DelegatedRole{Name: "r", KeyIDs: []string{"k1"}, Threshold: 1}
	got := matchesRole("any/path", role)
	assert.False(t, got)
}

// To verify: In matchesRole use exact match instead of HasPrefix for Paths; test will fail (false instead of true).
func TestMatchesRole_PathPrefixMatches_ReturnsTrue(t *testing.T) {
	role := &tuf_metadata.DelegatedRole{Name: "updates", KeyIDs: []string{"k1"}, Threshold: 1, Paths: []string{"updates/"}}
	got := matchesRole("updates/app-1.0.0.tar", role)
	assert.True(t, got)
}

// To verify: In matchesRole when path does not match any Paths prefix, return false; change to true and test will fail.
func TestMatchesRole_PathPrefixNoMatch_ReturnsFalse(t *testing.T) {
	role := &tuf_metadata.DelegatedRole{Name: "updates", KeyIDs: []string{"k1"}, Threshold: 1, Paths: []string{"updates/"}}
	got := matchesRole("other/file.exe", role)
	assert.False(t, got)
}

// To verify: In matchesRole when artifactPath equals a path, HasPrefix returns true; change logic and test may fail.
func TestMatchesRole_PathEqualsRolePath_ReturnsTrue(t *testing.T) {
	role := &tuf_metadata.DelegatedRole{Name: "r", KeyIDs: []string{"k1"}, Threshold: 1, Paths: []string{"updates/"}}
	got := matchesRole("updates/", role)
	assert.True(t, got)
}

// To verify: In matchesRole iterate over all Paths; if only first path is checked, test will fail (false instead of true).
func TestMatchesRole_SecondPathMatches_ReturnsTrue(t *testing.T) {
	role := &tuf_metadata.DelegatedRole{Name: "r", KeyIDs: []string{"k1"}, Threshold: 1, Paths: []string{"a/", "b/"}}
	got := matchesRole("b/file.zip", role)
	assert.True(t, got)
}

// To verify: In matchesRole hash is fmt.Sprintf("%x", artifactPath); path "a" gives hex "61"; change hash and test will fail.
func TestMatchesRole_PathHashPrefixMatches_ReturnsTrue(t *testing.T) {
	role := &tuf_metadata.DelegatedRole{Name: "hashed", KeyIDs: []string{"k1"}, Threshold: 1, PathHashPrefixes: []string{"61"}}
	got := matchesRole("a", role)
	assert.True(t, got)
}

// To verify: In matchesRole PathHashPrefixes use prefix match on hash; prefix "6" matches hash "61" of "a".
func TestMatchesRole_PathHashPrefixPartialMatch_ReturnsTrue(t *testing.T) {
	role := &tuf_metadata.DelegatedRole{Name: "hashed", KeyIDs: []string{"k1"}, Threshold: 1, PathHashPrefixes: []string{"6"}}
	got := matchesRole("a", role)
	assert.True(t, got)
}

// To verify: In matchesRole when hash does not match any PathHashPrefixes, return false; change to true and test will fail.
func TestMatchesRole_PathHashPrefixNoMatch_ReturnsFalse(t *testing.T) {
	role := &tuf_metadata.DelegatedRole{Name: "hashed", KeyIDs: []string{"k1"}, Threshold: 1, PathHashPrefixes: []string{"ab"}}
	got := matchesRole("a", role)
	assert.False(t, got)
}

// To verify: In matchesRole Paths are checked before PathHashPrefixes; if order is reversed or only hash is used, test may fail.
func TestMatchesRole_PathsCheckedFirst_PathMatchReturnsTrue(t *testing.T) {
	role := &tuf_metadata.DelegatedRole{Name: "r", KeyIDs: []string{"k1"}, Threshold: 1, Paths: []string{"updates/"}, PathHashPrefixes: []string{"xx"}}
	got := matchesRole("updates/app.tar", role)
	assert.True(t, got)
}

// To verify: In matchesRole when Paths do not match but PathHashPrefixes match, return true; skip PathHashPrefixes branch and test will fail.
func TestMatchesRole_OnlyPathHashPrefixMatches_ReturnsTrue(t *testing.T) {
	role := &tuf_metadata.DelegatedRole{Name: "hashed", KeyIDs: []string{"k1"}, Threshold: 1, Paths: []string{"other/"}, PathHashPrefixes: []string{"61"}}
	got := matchesRole("a", role)
	assert.True(t, got)
}

// --- updateDelegatedRoleWithArtifacts tests ---

// makeRepoAndKeyForUpdateDelegatedRole creates a repo with targets and one delegated role (with real key), writes key to keyDir.
func makeRepoAndKeyForUpdateDelegatedRole(t *testing.T, roleName string) (repo *repository.Type, keyDir string, cleanup func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	key, err := tuf_metadata.KeyFromPublicKey(priv.Public())
	require.NoError(t, err)
	keyID, err := key.ID()
	require.NoError(t, err)

	keyDir = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(keyDir, keyID), priv.Seed(), 0600))

	expires := time.Now().Add(365 * 24 * time.Hour)
	repo = repository.New()
	targets := tuf_metadata.Targets(expires)
	targets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys:  map[string]*tuf_metadata.Key{keyID: key},
		Roles: []tuf_metadata.DelegatedRole{{Name: roleName, KeyIDs: []string{keyID}, Threshold: 1, Paths: []string{"updates/"}}},
	}
	repo.SetTargets("targets", targets)

	oldKeyDir := viper.GetViper().GetString("ONLINE_KEY_DIR")
	viper.GetViper().Set("ONLINE_KEY_DIR", keyDir)
	cleanup = func() { viper.GetViper().Set("ONLINE_KEY_DIR", oldKeyDir) }
	return repo, keyDir, cleanup
}

// To verify: In updateDelegatedRoleWithArtifacts skip the check for targets == nil || targets.Signed.Delegations == nil; test will fail (panic or wrong error).
func TestUpdateDelegatedRoleWithArtifacts_TargetsOrDelegationsNil_ReturnsError(t *testing.T) {
	repo := repoWithTargetsNoDelegationsForGetRole()
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	tmpDir := t.TempDir()

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("no files")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	_, err := updateDelegatedRoleWithArtifacts(ctx, repo, "updates", []Artifact{
		{Path: "updates/app.tar", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get delegations from targets metadata")
}

// To verify: In updateDelegatedRoleWithArtifacts skip "not enough distinct keys" check for threshold; test will fail (no error or wrong message).
func TestUpdateDelegatedRoleWithArtifacts_NotEnoughDistinctKeys_ReturnsError(t *testing.T) {
	repo, _, cleanup := makeRepoAndKeyForUpdateDelegatedRole(t, "updates")
	defer cleanup()

	for i := range repo.Targets("targets").Signed.Delegations.Roles {
		if repo.Targets("targets").Signed.Delegations.Roles[i].Name == "updates" {
			repo.Targets("targets").Signed.Delegations.Roles[i].Threshold = 2
			break
		}
	}

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	tmpDir := t.TempDir()

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("no files")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	_, err := updateDelegatedRoleWithArtifacts(ctx, repo, "updates", []Artifact{
		{Path: "updates/app.tar", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enough distinct keys for delegated role updates")
	assert.Contains(t, err.Error(), "need 2, got 1")
}

// To verify: In updateDelegatedRoleWithArtifacts change role lookup so wrong role name is accepted; test will fail (no error or wrong message).
func TestUpdateDelegatedRoleWithArtifacts_NoKeyIDsForRole_ReturnsError(t *testing.T) {
	repo := repoWithTargetsAndOneRoleForGetRole("other", []string{"other/"})
	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	tmpDir := t.TempDir()

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("no files")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	_, err := updateDelegatedRoleWithArtifacts(ctx, repo, "updates", []Artifact{
		{Path: "updates/app.tar", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no key IDs found for delegated role updates")
}

// To verify: In updateDelegatedRoleWithArtifacts skip LoadPrivateKeyFromFilesystem error; test will fail (no error or wrong message).
func TestUpdateDelegatedRoleWithArtifacts_LoadDelegationKeyFails_ReturnsError(t *testing.T) {
	repo, _, cleanup := makeRepoAndKeyForUpdateDelegatedRole(t, "updates")
	defer cleanup()

	emptyKeyDir := t.TempDir()
	viper.GetViper().Set("ONLINE_KEY_DIR", emptyKeyDir)
	defer func() { viper.GetViper().Set("ONLINE_KEY_DIR", "") }()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	tmpDir := t.TempDir()

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("no files")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	_, err := updateDelegatedRoleWithArtifacts(ctx, repo, "updates", []Artifact{
		{Path: "updates/app.tar", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load delegation private key")
}

// To verify: In updateDelegatedRoleWithArtifacts when !isNewDelegation, skip DownloadMetadataFromS3 error handling; test will fail (no error or wrong message).
func TestUpdateDelegatedRoleWithArtifacts_ExistingDelegation_DownloadFails_ReturnsError(t *testing.T) {
	repo, _, cleanup := makeRepoAndKeyForUpdateDelegatedRole(t, "updates")
	defer cleanup()

	savedList := tuf_storage.ListMetadataForLatest
	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.updates.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &failDownloadClient{}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
	}()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	tmpDir := t.TempDir()

	_, err := updateDelegatedRoleWithArtifacts(ctx, repo, "updates", []Artifact{
		{Path: "updates/app.tar", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to download updates metadata")
}

// To verify: In updateDelegatedRoleWithArtifacts when !isNewDelegation, skip FromFile error handling; test will fail (no error or wrong message).
func TestUpdateDelegatedRoleWithArtifacts_ExistingDelegation_LoadFails_ReturnsError(t *testing.T) {
	repo, _, cleanup := makeRepoAndKeyForUpdateDelegatedRole(t, "updates")
	defer cleanup()

	tmpDir := t.TempDir()
	badDelegationPath := filepath.Join(tmpDir, "1.updates.json")
	require.NoError(t, os.WriteFile(badDelegationPath, []byte("not valid json"), 0644))

	storeDir := t.TempDir()
	metadataPrefix := filepath.Join(storeDir, "tuf_metadata", testAdminName, testAppName)
	require.NoError(t, os.MkdirAll(metadataPrefix, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(metadataPrefix, "1.updates.json"), []byte("not valid json"), 0644))

	savedList := tuf_storage.ListMetadataForLatest
	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.updates.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper {
		v := viper.New()
		v.Set("S3_BUCKET_NAME", "test-bucket")
		return v
	}
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &fsStorageClient{baseDir: storeDir}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
	}()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	_, err := updateDelegatedRoleWithArtifacts(ctx, repo, "updates", []Artifact{
		{Path: "updates/app.tar", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "ab"}}},
	}, testAdminName, testAppName, redisClient, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load updates metadata")
}

// To verify: In updateDelegatedRoleWithArtifacts new delegation path: create delegation, sign, save, upload; change return value or skip upload and test will fail.
func TestUpdateDelegatedRoleWithArtifacts_NewDelegation_Success(t *testing.T) {
	repo, _, cleanup := makeRepoAndKeyForUpdateDelegatedRole(t, "updates")
	defer cleanup()

	storeDir := t.TempDir()
	savedGetViperU := tuf_storage.GetViperForUpload
	savedFactoryU := tuf_storage.StorageFactoryForUpload
	tuf_storage.GetViperForUpload = func() *viper.Viper {
		v := viper.New()
		v.Set("S3_BUCKET_NAME", "test-bucket")
		return v
	}
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &fsStorageClient{baseDir: storeDir}}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedGetViperU
		tuf_storage.StorageFactoryForUpload = savedFactoryU
	}()

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.root.json", "2.targets.json"}, nil
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	ctx := context.Background()
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	tmpDir := t.TempDir()

	artifacts := []Artifact{
		{Path: "updates/app-1.0.0.tar", Info: ArtifactInfo{Length: 1024, Hashes: map[string]string{"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}},
	}

	updated, err := updateDelegatedRoleWithArtifacts(ctx, repo, "updates", artifacts, testAdminName, testAppName, redisClient, tmpDir)

	require.NoError(t, err)
	assert.False(t, updated)
	delegationPath := filepath.Join(tmpDir, "2.updates.json")
	require.FileExists(t, delegationPath)
	uploadedPath := filepath.Join(storeDir, "tuf_metadata", testAdminName, testAppName, "2.updates.json")
	require.FileExists(t, uploadedPath)
}

// --- updateSnapshotAndTimestamp tests ---

// makeSnapshotAndTimestampSigners creates timestamp and snapshot signers from one ed25519 key (for tests).
func makeSnapshotAndTimestampSigners(t *testing.T) (timestampSigner, snapshotSigner signature.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	sig, err := signature.LoadSigner(priv, crypto.Hash(0))
	require.NoError(t, err)
	return sig, sig
}

// To verify: In updateSnapshotAndTimestamp when context is already cancelled, return timeout error; skip lockCtx.Done() check and test will panic or hang.
func TestUpdateSnapshotAndTimestamp_ContextCancelled_LockTimeout_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	repo := repository.New()
	tsSigner, snapSigner := makeSnapshotAndTimestampSigners(t)
	tmpDir := t.TempDir()

	err := updateSnapshotAndTimestamp(ctx, repo, nil, testAdminName, testAppName, redisClient, []signature.Signer{tsSigner}, []signature.Signer{snapSigner}, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acquire snapshot lock")
	assert.Contains(t, err.Error(), "timeout after")
}

// To verify: In updateSnapshotAndTimestamp skip SetNX error handling; test will fail (no error or wrong message).
func TestUpdateSnapshotAndTimestamp_RedisSetNXError_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close()

	ctx := context.Background()
	repo := repository.New()
	tsSigner, snapSigner := makeSnapshotAndTimestampSigners(t)
	tmpDir := t.TempDir()

	err := updateSnapshotAndTimestamp(ctx, repo, nil, testAdminName, testAppName, redisClient, []signature.Signer{tsSigner}, []signature.Signer{snapSigner}, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acquire snapshot lock")
}

// To verify: In updateSnapshotAndTimestamp when lock is held and context times out, return timeout error; change timeout message and test will fail.
func TestUpdateSnapshotAndTimestamp_LockHeld_Timeout_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	mr.Set("LOCK_SNAPSHOT_"+testAdminName, "locked")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	repo := repository.New()
	tsSigner, snapSigner := makeSnapshotAndTimestampSigners(t)
	tmpDir := t.TempDir()

	err := updateSnapshotAndTimestamp(ctx, repo, nil, testAdminName, testAppName, redisClient, []signature.Signer{tsSigner}, []signature.Signer{snapSigner}, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acquire snapshot lock")
	assert.Contains(t, err.Error(), "timeout after")
}

// To verify: In updateSnapshotAndTimestamp skip FindLatestMetadataVersion error handling; test will fail (no error or wrong message).
func TestUpdateSnapshotAndTimestamp_FindLatestSnapshotFails_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedList := tuf_storage.ListMetadataForLatest
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, fmt.Errorf("list failed")
	}
	defer func() { tuf_storage.ListMetadataForLatest = savedList }()

	ctx := context.Background()
	repo := repository.New()
	tsSigner, snapSigner := makeSnapshotAndTimestampSigners(t)
	tmpDir := t.TempDir()

	err := updateSnapshotAndTimestamp(ctx, repo, nil, testAdminName, testAppName, redisClient, []signature.Signer{tsSigner}, []signature.Signer{snapSigner}, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find latest snapshot version")
}

// To verify: In updateSnapshotAndTimestamp skip DownloadMetadataFromS3 error handling; test will fail (no error or wrong message).
func TestUpdateSnapshotAndTimestamp_DownloadSnapshotFails_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	savedList := tuf_storage.ListMetadataForLatest
	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.snapshot.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &failDownloadClient{}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
	}()

	ctx := context.Background()
	repo := repository.New()
	tsSigner, snapSigner := makeSnapshotAndTimestampSigners(t)
	tmpDir := t.TempDir()

	err := updateSnapshotAndTimestamp(ctx, repo, nil, testAdminName, testAppName, redisClient, []signature.Signer{tsSigner}, []signature.Signer{snapSigner}, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to download snapshot metadata")
}

// To verify: In updateSnapshotAndTimestamp skip FromFile error handling; test will fail (no error or wrong message).
func TestUpdateSnapshotAndTimestamp_LoadSnapshotFails_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storeDir := t.TempDir()
	metadataPrefix := filepath.Join(storeDir, "tuf_metadata", testAdminName, testAppName)
	require.NoError(t, os.MkdirAll(metadataPrefix, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(metadataPrefix, "1.snapshot.json"), []byte("not valid json"), 0644))

	savedList := tuf_storage.ListMetadataForLatest
	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.snapshot.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper {
		v := viper.New()
		v.Set("S3_BUCKET_NAME", "test-bucket")
		return v
	}
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &fsStorageClient{baseDir: storeDir}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
	}()

	ctx := context.Background()
	repo := repository.New()
	tsSigner, snapSigner := makeSnapshotAndTimestampSigners(t)
	tmpDir := t.TempDir()

	err := updateSnapshotAndTimestamp(ctx, repo, nil, testAdminName, testAppName, redisClient, []signature.Signer{tsSigner}, []signature.Signer{snapSigner}, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load snapshot metadata")
}

// To verify: In updateSnapshotAndTimestamp skip UploadMetadataToS3 error handling for snapshot; test will fail (no error or wrong message).
func TestUpdateSnapshotAndTimestamp_UploadSnapshotFails_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storeDir := t.TempDir()
	metadataPrefix := filepath.Join(storeDir, "tuf_metadata", testAdminName, testAppName)
	require.NoError(t, os.MkdirAll(metadataPrefix, 0755))

	_, snapSigner := makeSnapshotAndTimestampSigners(t)
	repo := repository.New()
	exp := tuf_utils.HelperExpireIn(7)
	snap := tuf_metadata.Snapshot(exp)
	repo.SetSnapshot(snap)
	_, err := repo.Snapshot().Sign(snapSigner)
	require.NoError(t, err)
	snapshotPath := filepath.Join(storeDir, "1.snapshot.json")
	require.NoError(t, repo.Snapshot().ToFile(snapshotPath, true))
	require.NoError(t, os.WriteFile(filepath.Join(metadataPrefix, "1.snapshot.json"), mustReadFile(t, snapshotPath), 0644))

	savedList := tuf_storage.ListMetadataForLatest
	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
	savedGetViperU := tuf_storage.GetViperForUpload
	savedFactoryU := tuf_storage.StorageFactoryForUpload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.snapshot.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper {
		v := viper.New()
		v.Set("S3_BUCKET_NAME", "test-bucket")
		return v
	}
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &fsStorageClient{baseDir: storeDir}}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &failUploadClient{}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
		tuf_storage.GetViperForUpload = savedGetViperU
		tuf_storage.StorageFactoryForUpload = savedFactoryU
	}()

	ctx := context.Background()
	tsSigner, _ := makeSnapshotAndTimestampSigners(t)
	tmpDir := t.TempDir()

	err = updateSnapshotAndTimestamp(ctx, repo, nil, testAdminName, testAppName, redisClient, []signature.Signer{tsSigner}, []signature.Signer{snapSigner}, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to upload snapshot metadata to S3")
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// --- updateTimestamp tests ---

// To verify: In updateTimestamp skip UploadMetadataToS3 error handling; test will fail (no error or wrong message).
func TestUpdateTimestamp_UploadFails_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	repo := repository.New()
	exp := tuf_utils.HelperExpireIn(7)
	snap := tuf_metadata.Snapshot(exp)
	repo.SetSnapshot(snap)
	signer, _ := makeSnapshotAndTimestampSigners(t)
	tmpDir := t.TempDir()

	savedGetViperU := tuf_storage.GetViperForUpload
	savedFactoryU := tuf_storage.StorageFactoryForUpload
	tuf_storage.GetViperForUpload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &failUploadClient{}}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedGetViperU
		tuf_storage.StorageFactoryForUpload = savedFactoryU
	}()

	ctx := context.Background()
	err := updateTimestamp(ctx, repo, testAdminName, testAppName, redisClient, []signature.Signer{signer}, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to upload timestamp metadata to S3")
}

// To verify: In updateTimestamp skip ToFile error handling; test will fail (no error or wrong message).
func TestUpdateTimestamp_ToFileFails_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	repo := repository.New()
	exp := tuf_utils.HelperExpireIn(7)
	snap := tuf_metadata.Snapshot(exp)
	repo.SetSnapshot(snap)
	signer, _ := makeSnapshotAndTimestampSigners(t)
	tmpDir := t.TempDir()
	// Make timestampPath a directory so ToFile fails when trying to write
	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	require.NoError(t, os.MkdirAll(timestampPath, 0755))

	savedGetViperU := tuf_storage.GetViperForUpload
	savedFactoryU := tuf_storage.StorageFactoryForUpload
	tuf_storage.GetViperForUpload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &failUploadClient{}}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedGetViperU
		tuf_storage.StorageFactoryForUpload = savedFactoryU
	}()

	ctx := context.Background()
	err := updateTimestamp(ctx, repo, testAdminName, testAppName, redisClient, []signature.Signer{signer}, tmpDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save timestamp metadata")
}

// To verify: In updateTimestamp when Download fails, create new timestamp; when Upload succeeds, return nil; change behavior and test will fail.
func TestUpdateTimestamp_Success_NoExistingTimestamp(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storeDir := t.TempDir()

	repo := repository.New()
	exp := tuf_utils.HelperExpireIn(7)
	snap := tuf_metadata.Snapshot(exp)
	repo.SetSnapshot(snap)
	signer, _ := makeSnapshotAndTimestampSigners(t)
	tmpDir := t.TempDir()

	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
	savedGetViperU := tuf_storage.GetViperForUpload
	savedFactoryU := tuf_storage.StorageFactoryForUpload
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &failDownloadClient{}}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper {
		v := viper.New()
		v.Set("S3_BUCKET_NAME", "test-bucket")
		return v
	}
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &fsStorageClient{baseDir: storeDir}}
	}
	defer func() {
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
		tuf_storage.GetViperForUpload = savedGetViperU
		tuf_storage.StorageFactoryForUpload = savedFactoryU
	}()

	ctx := context.Background()
	err := updateTimestamp(ctx, repo, testAdminName, testAppName, redisClient, []signature.Signer{signer}, tmpDir)

	require.NoError(t, err)
	require.FileExists(t, filepath.Join(tmpDir, "timestamp.json"))
	uploadedPath := filepath.Join(storeDir, "tuf_metadata", testAdminName, testAppName, "timestamp.json")
	require.FileExists(t, uploadedPath)

	data, err := os.ReadFile(filepath.Join(tmpDir, "timestamp.json"))
	require.NoError(t, err)
	var tsSigned struct {
		Signed struct {
			Version int `json:"version"`
		} `json:"signed"`
	}
	require.NoError(t, json.Unmarshal(data, &tsSigned))
	assert.Equal(t, 1, tsSigned.Signed.Version, "new timestamp without existing file must have version 1")
}

// To verify: In updateTimestamp when snapshot is nil, timestamp meta still updated; when snapshot set, snapshot.json in meta; change logic and test will fail.
func TestUpdateTimestamp_Success_WithSnapshotInRepo(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storeDir := t.TempDir()

	repo := repository.New()
	exp := tuf_utils.HelperExpireIn(7)
	snap := tuf_metadata.Snapshot(exp)
	snap.Signed.Version = 2
	repo.SetSnapshot(snap)
	signer, _ := makeSnapshotAndTimestampSigners(t)
	tmpDir := t.TempDir()

	savedGetViperU := tuf_storage.GetViperForUpload
	savedFactoryU := tuf_storage.StorageFactoryForUpload
	tuf_storage.GetViperForUpload = func() *viper.Viper {
		v := viper.New()
		v.Set("S3_BUCKET_NAME", "test-bucket")
		return v
	}
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &fsStorageClient{baseDir: storeDir}}
	}
	defer func() {
		tuf_storage.GetViperForUpload = savedGetViperU
		tuf_storage.StorageFactoryForUpload = savedFactoryU
	}()

	ctx := context.Background()
	err := updateTimestamp(ctx, repo, testAdminName, testAppName, redisClient, []signature.Signer{signer}, tmpDir)

	require.NoError(t, err)
	require.FileExists(t, filepath.Join(tmpDir, "timestamp.json"))
	data, err := os.ReadFile(filepath.Join(tmpDir, "timestamp.json"))
	require.NoError(t, err)
	var tsMeta struct {
		Signed struct {
			Meta map[string]struct {
				Version int `json:"version"`
			} `json:"meta"`
		} `json:"signed"`
	}
	require.NoError(t, json.Unmarshal(data, &tsMeta))
	require.Contains(t, tsMeta.Signed.Meta, "snapshot.json")
	assert.Equal(t, 2, tsMeta.Signed.Meta["snapshot.json"].Version)
}

// To verify: In updateTimestamp when an existing timestamp file is loaded, its version is incremented (bump behavior for add/delete artifacts flow).
func TestUpdateTimestamp_VersionIncremented_WhenExistingTimestampLoaded(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	storeDir := t.TempDir()
	tmpDir := t.TempDir()

	repo := repository.New()
	exp := tuf_utils.HelperExpireIn(7)
	snap := tuf_metadata.Snapshot(exp)
	snap.Signed.Version = 2
	repo.SetSnapshot(snap)

	ts := tuf_metadata.Timestamp(exp)
	ts.Signed.Version = 3
	repo.SetTimestamp(ts)
	signer, _ := makeSnapshotAndTimestampSigners(t)
	if _, err := repo.Timestamp().Sign(signer); err != nil {
		t.Fatal(err)
	}
	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	require.NoError(t, repo.Timestamp().ToFile(timestampPath, true))
	require.FileExists(t, timestampPath)

	savedGetViperD := tuf_storage.GetViperForDownload
	savedFactoryD := tuf_storage.StorageFactoryForDownload
	savedGetViperU := tuf_storage.GetViperForUpload
	savedFactoryU := tuf_storage.StorageFactoryForUpload
	tuf_storage.GetViperForDownload = func() *viper.Viper { return viper.New() }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &failDownloadClient{}}
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper {
		v := viper.New()
		v.Set("S3_BUCKET_NAME", "test-bucket")
		return v
	}
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &fsStorageFactory{client: &fsStorageClient{baseDir: storeDir}}
	}
	defer func() {
		tuf_storage.GetViperForDownload = savedGetViperD
		tuf_storage.StorageFactoryForDownload = savedFactoryD
		tuf_storage.GetViperForUpload = savedGetViperU
		tuf_storage.StorageFactoryForUpload = savedFactoryU
	}()

	ctx := context.Background()
	err := updateTimestamp(ctx, repo, testAdminName, testAppName, redisClient, []signature.Signer{signer}, tmpDir)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(tmpDir, "timestamp.json"))
	require.NoError(t, err)
	var tsSigned struct {
		Signed struct {
			Version int `json:"version"`
		} `json:"signed"`
	}
	require.NoError(t, json.Unmarshal(data, &tsSigned))
	assert.Equal(t, 4, tsSigned.Signed.Version, "when existing timestamp (version 3) is loaded, version must be incremented to 4")
}

// --- getArtifactPaths tests ---

// To verify: In getArtifactPaths change to return artifact.Path for wrong index; test will fail (wrong order or wrong path).
func TestGetArtifactPaths_EmptySlice_ReturnsEmpty(t *testing.T) {
	paths := getArtifactPaths([]Artifact{})
	assert.Empty(t, paths)
	assert.Len(t, paths, 0)
}

// To verify: In getArtifactPaths when input is nil, return empty slice; change to panic or return non-empty and test will fail.
func TestGetArtifactPaths_NilSlice_ReturnsEmpty(t *testing.T) {
	paths := getArtifactPaths(nil)
	assert.Empty(t, paths)
	assert.Len(t, paths, 0)
}

// To verify: In getArtifactPaths use wrong field or index; test will fail (wrong path).
func TestGetArtifactPaths_OneArtifact_ReturnsPath(t *testing.T) {
	artifacts := []Artifact{
		{Path: "updates/app.tar", Info: ArtifactInfo{Length: 100, Hashes: map[string]string{"sha256": "ab"}}},
	}
	paths := getArtifactPaths(artifacts)
	require.Len(t, paths, 1)
	assert.Equal(t, "updates/app.tar", paths[0])
}

// To verify: In getArtifactPaths change iteration or assignment; test will fail (wrong order or missing path).
func TestGetArtifactPaths_MultipleArtifacts_ReturnsPathsInOrder(t *testing.T) {
	artifacts := []Artifact{
		{Path: "updates/a.tar", Info: ArtifactInfo{Length: 1, Hashes: map[string]string{"sha256": "x"}}},
		{Path: "updates/b.zip", Info: ArtifactInfo{Length: 2, Hashes: map[string]string{"sha256": "y"}}},
		{Path: "releases/c.exe", Info: ArtifactInfo{Length: 3, Hashes: map[string]string{"sha256": "z"}}},
	}
	paths := getArtifactPaths(artifacts)
	require.Len(t, paths, 3)
	assert.Equal(t, "updates/a.tar", paths[0])
	assert.Equal(t, "updates/b.zip", paths[1])
	assert.Equal(t, "releases/c.exe", paths[2])
}
