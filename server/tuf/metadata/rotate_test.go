package metadata

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"faynoSync/server/tuf/models"
	tuf_storage "faynoSync/server/tuf/storage"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

func makeRotateTestKey(t *testing.T) (ed25519.PrivateKey, *tuf_metadata.Key, string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	tufKey, err := tuf_metadata.KeyFromPublicKey(privateKey.Public())
	require.NoError(t, err)
	keyID, err := tufKey.ID()
	require.NoError(t, err)
	return privateKey, tufKey, keyID
}

func signSignedSectionForTest(t *testing.T, signed interface{}, privateKey ed25519.PrivateKey) string {
	t.Helper()
	signedBytes, err := json.Marshal(signed)
	require.NoError(t, err)
	var signedMap map[string]interface{}
	require.NoError(t, json.Unmarshal(signedBytes, &signedMap))
	canonical, err := cjson.EncodeCanonical(signedMap)
	require.NoError(t, err)
	return hex.EncodeToString(ed25519.Sign(privateKey, canonical))
}

func makeRotateMetadataForTest(t *testing.T, roleName string, version int, oldPrivateKey ed25519.PrivateKey, oldKeyID string, newKeyID string, newKey *tuf_metadata.Key) []byte {
	t.Helper()
	signed := rotateSigned{
		Type:      rotateMetadataType,
		Version:   version,
		Role:      roleName,
		Keys:      map[string]*tuf_metadata.Key{newKeyID: newKey},
		Threshold: 1,
	}
	rotate := rotateMetadata{
		Signatures: modelsSignaturesForTest{{KeyID: oldKeyID, Sig: signSignedSectionForTest(t, signed, oldPrivateKey)}}.toModelSignatures(),
		Signed:     signed,
	}
	raw, err := json.Marshal(rotate)
	require.NoError(t, err)
	return raw
}

type modelsSignatureForTest struct {
	KeyID string
	Sig   string
}

type modelsSignaturesForTest []modelsSignatureForTest

func (s modelsSignaturesForTest) toModelSignatures() []models.Signature {
	result := make([]models.Signature, 0, len(s))
	for _, sig := range s {
		result = append(result, models.Signature{KeyID: sig.KeyID, Sig: sig.Sig})
	}
	return result
}

func TestVerifyRotateMetadataBytes_Success(t *testing.T) {
	oldPrivateKey, oldKey, oldKeyID := makeRotateTestKey(t)
	_, newKey, newKeyID := makeRotateTestKey(t)
	raw := makeRotateMetadataForTest(t, "targets", 1, oldPrivateKey, oldKeyID, newKeyID, newKey)

	nextTrust, rotateMeta, err := verifyRotateMetadataBytes(raw, "targets", 1, roleTrustState{
		Keys:      map[string]*tuf_metadata.Key{oldKeyID: oldKey},
		KeyIDs:    []string{oldKeyID},
		Threshold: 1,
	})

	require.NoError(t, err)
	assert.Equal(t, 1, rotateMeta.Signed.Version)
	assert.Equal(t, 1, nextTrust.Threshold)
	assert.Contains(t, nextTrust.Keys, newKeyID)
}

func TestVerifyRotateMetadataBytes_RejectsDuplicateSignatureKeyID(t *testing.T) {
	oldPrivateKey, oldKey, oldKeyID := makeRotateTestKey(t)
	_, newKey, newKeyID := makeRotateTestKey(t)
	raw := makeRotateMetadataForTest(t, "targets", 1, oldPrivateKey, oldKeyID, newKeyID, newKey)

	var rotate rotateMetadata
	require.NoError(t, json.Unmarshal(raw, &rotate))
	rotate.Signatures = append(rotate.Signatures, rotate.Signatures[0])
	raw, err := json.Marshal(rotate)
	require.NoError(t, err)

	_, _, err = verifyRotateMetadataBytes(raw, "targets", 1, roleTrustState{
		Keys:      map[string]*tuf_metadata.Key{oldKeyID: oldKey},
		KeyIDs:    []string{oldKeyID},
		Threshold: 1,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate signature keyid")
}

func TestVerifyRotateMetadataBytes_RejectsKeyIDMismatch(t *testing.T) {
	oldPrivateKey, oldKey, oldKeyID := makeRotateTestKey(t)
	_, newKey, newKeyID := makeRotateTestKey(t)
	raw := makeRotateMetadataForTest(t, "targets", 1, oldPrivateKey, oldKeyID, newKeyID+"bad", newKey)

	_, _, err := verifyRotateMetadataBytes(raw, "targets", 1, roleTrustState{
		Keys:      map[string]*tuf_metadata.Key{oldKeyID: oldKey},
		KeyIDs:    []string{oldKeyID},
		Threshold: 1,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "keyid mismatch")
}

func TestApplyExistingRotateChain_RejectsVersionGap(t *testing.T) {
	savedList := listMetadataForRotate
	listMetadataForRotate = func(context.Context, string, string, string) ([]string, error) {
		return []string{"rotate/targets.rotate.2.json"}, nil
	}
	defer func() { listMetadataForRotate = savedList }()

	_, oldKey, oldKeyID := makeRotateTestKey(t)
	_, _, err := applyExistingRotateChain(context.Background(), "admin", "app", "targets", roleTrustState{
		Keys:      map[string]*tuf_metadata.Key{oldKeyID: oldKey},
		KeyIDs:    []string{oldKeyID},
		Threshold: 1,
	}, t.TempDir())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotate version gap")
}

func TestValidateTAP8RoleName_RejectsUnsupportedRoles(t *testing.T) {
	for _, role := range []string{"root", "snapshot", "timestamp"} {
		err := validateTAP8RoleName(role)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	}
}

func TestPublishRotatedRoleMetadata_TargetsSuccess(t *testing.T) {
	ctx := context.Background()
	repo, keys, keyIDs := makeValidRolesWithKeys(t)

	newTargetsPrivateKey, newTargetsKey, newTargetsKeyID := makeRotateTestKey(t)
	newTargets := tuf_metadata.Targets(time.Now().Add(365 * 24 * time.Hour))
	newTargets.Signed.Version = repo.Targets("targets").Signed.Version + 1
	signer, err := signature.LoadED25519Signer(newTargetsPrivateKey)
	require.NoError(t, err)
	_, err = newTargets.Sign(signer)
	require.NoError(t, err)
	newTargetsRaw, err := json.Marshal(newTargets)
	require.NoError(t, err)

	rotateRaw := makeRotateMetadataForTest(t, "targets", 1, keys["targets"], keyIDs["targets"], newTargetsKeyID, newTargetsKey)

	serializeDir := t.TempDir()
	rootRaw := mustMetadataFileBytes(t, serializeDir, "1.root.json", repo.Root())
	targetsRaw := mustMetadataFileBytes(t, serializeDir, "1.targets.json", repo.Targets("targets"))
	snapshotRaw := mustMetadataFileBytes(t, serializeDir, "1.snapshot.json", repo.Snapshot())
	timestampRaw := mustMetadataFileBytes(t, serializeDir, "timestamp.json", repo.Timestamp())

	keyDir := t.TempDir()
	for _, role := range []string{"snapshot", "timestamp"} {
		require.NoError(t, os.WriteFile(filepath.Join(keyDir, keyIDs[role]), keys[role].Seed(), 0600))
	}
	oldKeyDir := viper.GetString("ONLINE_KEY_DIR")
	viper.Set("ONLINE_KEY_DIR", keyDir)
	defer viper.Set("ONLINE_KEY_DIR", oldKeyDir)

	uploaded := &uploadCaptureMockClient{objects: map[string][]byte{}}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedListLatest := tuf_storage.ListMetadataForLatest
	savedListRotate := listMetadataForRotate
	savedGetViperUpload := tuf_storage.GetViperForUpload
	savedFactoryUpload := tuf_storage.StorageFactoryForUpload
	savedGetViperDownload := tuf_storage.GetViperForDownload
	savedFactoryDownload := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.root.json", "1.targets.json", "1.snapshot.json"}, nil
	}
	listMetadataForRotate = func(context.Context, string, string, string) ([]string, error) {
		return nil, nil
	}
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{client: uploaded}
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &downloadMockFactory{client: &multiFileDownloadMockClient{
			files: map[string][]byte{
				"1.root.json":     rootRaw,
				"1.targets.json":  targetsRaw,
				"1.snapshot.json": snapshotRaw,
				"timestamp.json":  timestampRaw,
			},
		}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedListLatest
		listMetadataForRotate = savedListRotate
		tuf_storage.GetViperForUpload = savedGetViperUpload
		tuf_storage.StorageFactoryForUpload = savedFactoryUpload
		tuf_storage.GetViperForDownload = savedGetViperDownload
		tuf_storage.StorageFactoryForDownload = savedFactoryDownload
	}()

	result, err := publishRotatedRoleMetadata(ctx, nil, "admin", "app", "targets", rotateRaw, newTargetsRaw, t.TempDir())

	require.NoError(t, err)
	assert.Equal(t, "rotate/targets.rotate.1.json", result.RotateFilename)
	assert.Equal(t, "2.targets.json", result.RoleMetadataFilename)
	assert.Contains(t, uploaded.objects, "tuf_metadata/admin/app/rotate/targets.rotate.1.json")
	assert.Contains(t, uploaded.objects, "tuf_metadata/admin/app/2.targets.json")
	assert.NotEmpty(t, result.SnapshotFilename)

	var snapshotEnvelope struct {
		Signed struct {
			Meta map[string]struct {
				Version int               `json:"version"`
				Length  int               `json:"length"`
				Hashes  map[string]string `json:"hashes"`
			} `json:"meta"`
		} `json:"signed"`
	}
	snapshotObjectKey := "tuf_metadata/admin/app/" + result.SnapshotFilename
	require.NoError(t, json.Unmarshal(uploaded.objects[snapshotObjectKey], &snapshotEnvelope))
	rotateMeta := snapshotEnvelope.Signed.Meta["rotate/targets.rotate.1.json"]
	assert.Equal(t, 1, rotateMeta.Version)
	assert.Equal(t, len(rotateRaw), rotateMeta.Length)
	assert.NotEmpty(t, rotateMeta.Hashes["sha256"])
}

func mustMetadataFileBytes(t *testing.T, dir string, filename string, meta interface {
	ToFile(string, bool) error
}) []byte {
	t.Helper()
	path := filepath.Join(dir, filename)
	require.NoError(t, meta.ToFile(path, true))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func TestMetaFileForBytes_SetsLengthAndHash(t *testing.T) {
	data := []byte(`{"signed":{"_type":"rotate"}}`)
	meta := metaFileForBytes(1, data)

	assert.Equal(t, int64(1), meta.Version)
	assert.Equal(t, int64(len(data)), meta.Length)
	assert.NotEmpty(t, meta.Hashes["sha256"])
}
