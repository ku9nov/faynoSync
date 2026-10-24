package metadata

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"faynoSync/server/tuf/models"
	tuf_storage "faynoSync/server/tuf/storage"
)

func buildRootWithOnlineKeys(t *testing.T, rootKey ed25519.PrivateKey, online map[string]ed25519.PrivateKey) (*tuf_metadata.Metadata[tuf_metadata.RootType], models.RootMetadata) {
	t.Helper()
	root := tuf_metadata.Root(time.Now().Add(365 * 24 * time.Hour))
	key, err := tuf_metadata.KeyFromPublicKey(rootKey.Public())
	require.NoError(t, err)
	require.NoError(t, root.Signed.AddKey(key, "root"))
	for _, role := range []string{"targets", "snapshot", "timestamp"} {
		key, err := tuf_metadata.KeyFromPublicKey(online[role].Public())
		require.NoError(t, err)
		require.NoError(t, root.Signed.AddKey(key, role))
	}
	signer, err := signature.LoadSigner(rootKey, crypto.Hash(0))
	require.NoError(t, err)
	_, err = root.Sign(signer)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "1.root.json")
	require.NoError(t, root.ToFile(path, true))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var model models.RootMetadata
	require.NoError(t, json.Unmarshal(raw, &model))
	return root, model
}

func newEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return private
}

// Online keys of every tenant share ONLINE_KEY_DIR. Admin A bootstraps a root
// self-signed by A's own root key that lists tenant B's online public keys; the
// server must not sign A's online roles with B's private keys.
// To verify: In buildOnlineRoleSigners load any keyid present in ONLINE_KEY_DIR; test will fail (A's metadata verifies under B's root).
func TestBootstrapOnlineRoles_OtherTenantOnlineKeys_Refused(t *testing.T) {
	keyDir := t.TempDir()
	oldDir := viper.GetViper().GetString("ONLINE_KEY_DIR")
	viper.GetViper().Set("ONLINE_KEY_DIR", keyDir)
	t.Cleanup(func() { viper.GetViper().Set("ONLINE_KEY_DIR", oldDir) })

	bOnline := map[string]ed25519.PrivateKey{"targets": newEd25519(t), "snapshot": newEd25519(t), "timestamp": newEd25519(t)}
	rootB, rootBModel := buildRootWithOnlineKeys(t, newEd25519(t), bOnline)
	for _, role := range []string{"targets", "snapshot", "timestamp"} {
		keyID := rootBModel.Signed.Roles[role].KeyIDs[0]
		require.NoError(t, os.WriteFile(filepath.Join(keyDir, keyID), bOnline[role].Seed(), 0600))
	}

	// A has only its own root key; the online public keys are copied from B's public root.json.
	_, rootAModel := buildRootWithOnlineKeys(t, newEd25519(t), map[string]ed25519.PrivateKey{
		"targets": bOnline["targets"], "snapshot": bOnline["snapshot"], "timestamp": bOnline["timestamp"],
	})

	captureClient := &uploadCaptureMockClient{objects: map[string][]byte{}}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedViper := tuf_storage.GetViperForUpload
	savedFactory := tuf_storage.StorageFactoryForUpload
	tuf_storage.GetViperForUpload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForUpload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &uploadMockFactory{client: captureClient}
	}
	t.Cleanup(func() {
		tuf_storage.GetViperForUpload = savedViper
		tuf_storage.StorageFactoryForUpload = savedFactory
	})

	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	payload := &models.BootstrapPayload{
		AppName: "appA",
		Settings: models.Settings{Roles: models.RolesData{
			Root:      models.RoleExpiration{Expiration: 365},
			Timestamp: models.RoleExpiration{Expiration: 1},
			Snapshot:  models.RoleExpiration{Expiration: 7},
			Targets:   models.RoleExpiration{Expiration: 90},
		}},
		Metadata: map[string]models.RootMetadata{"root": rootAModel},
	}

	err := BootstrapOnlineRolesWithContext(context.Background(), redisClient, "task-a", "adminA", "appA", payload)
	if err != nil {
		return
	}

	verified := []string{}
	for role, key := range map[string]string{
		"targets":   "tuf_metadata/adminA/appA/1.targets.json",
		"snapshot":  "tuf_metadata/adminA/appA/1.snapshot.json",
		"timestamp": "tuf_metadata/adminA/appA/timestamp.json",
	} {
		body, ok := captureClient.objects[key]
		require.True(t, ok, "%s uploaded", key)
		var verr error
		switch role {
		case "targets":
			md := &tuf_metadata.Metadata[tuf_metadata.TargetsType]{}
			_, verr = md.FromBytes(body)
			if verr == nil {
				verr = rootB.VerifyDelegate("targets", md)
			}
		case "snapshot":
			md := &tuf_metadata.Metadata[tuf_metadata.SnapshotType]{}
			_, verr = md.FromBytes(body)
			if verr == nil {
				verr = rootB.VerifyDelegate("snapshot", md)
			}
		case "timestamp":
			md := &tuf_metadata.Metadata[tuf_metadata.TimestampType]{}
			_, verr = md.FromBytes(body)
			if verr == nil {
				verr = rootB.VerifyDelegate("timestamp", md)
			}
		}
		if verr == nil {
			verified = append(verified, role)
		}
	}
	t.Fatalf("bootstrap of adminA/appA succeeded using tenant B's online keys; A's roles verifying under B's root: %v", verified)
}
