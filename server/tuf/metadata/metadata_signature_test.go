package metadata

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	tuf_storage "faynoSync/server/tuf/storage"
	"fmt"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tuf_metadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestValidateIncomingMetadataSignature_DelegatedTargets_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	err = runDelegatedTargetsSignatureValidationTest(t, "delegated-rsa", privateKey)
	require.NoError(t, err)
}

func TestValidateIncomingMetadataSignature_DelegatedTargets_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	err = runDelegatedTargetsSignatureValidationTest(t, "delegated-ecdsa", privateKey)
	require.NoError(t, err)
}

func runDelegatedTargetsSignatureValidationTest(t *testing.T, roleName string, privateKey crypto.Signer) error {
	t.Helper()

	// Build delegated key metadata and keyid from signer public key.
	delegationKey, err := tuf_metadata.KeyFromPublicKey(privateKey.Public())
	require.NoError(t, err)
	keyID, err := delegationKey.ID()
	require.NoError(t, err)

	// Prepare trusted targets metadata that authorizes delegated role key.
	trustedTargets := tuf_metadata.Targets(time.Now().Add(24 * time.Hour))
	trustedTargets.Signed.Delegations = &tuf_metadata.Delegations{
		Keys: map[string]*tuf_metadata.Key{
			keyID: delegationKey,
		},
		Roles: []tuf_metadata.DelegatedRole{
			{
				Name:      roleName,
				KeyIDs:    []string{keyID},
				Threshold: 1,
				Paths:     []string{"*"},
			},
		},
	}
	trustedTargetsJSON, err := json.Marshal(trustedTargets)
	require.NoError(t, err)

	// Sign delegated targets metadata to produce canonical signed payload + signature.
	delegatedTargets := tuf_metadata.Targets(time.Now().Add(24 * time.Hour))
	signer, err := loadTestSigner(privateKey)
	require.NoError(t, err)
	_, err = delegatedTargets.Sign(signer)
	require.NoError(t, err)
	require.NotEmpty(t, delegatedTargets.Signatures)

	signedBytes, err := json.Marshal(delegatedTargets.Signed)
	require.NoError(t, err)
	var signedData map[string]interface{}
	require.NoError(t, json.Unmarshal(signedBytes, &signedData))
	signatureHex := hex.EncodeToString(delegatedTargets.Signatures[0].Signature)

	// Mock storage lookup used by loadTrustedTargetsFromS3.
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	savedList := tuf_storage.ListMetadataForLatest
	savedGetViperForDownload := tuf_storage.GetViperForDownload
	savedStorageFactoryForDownload := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.targets.json"}, nil
	}
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &storageMockClientForForceUpdate{body: trustedTargetsJSON}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedGetViperForDownload
		tuf_storage.StorageFactoryForDownload = savedStorageFactoryForDownload
	}()

	return validateIncomingMetadataSignature(
		context.Background(),
		"admin",
		"app",
		"targets",
		roleName,
		keyID,
		signatureHex,
		signedData,
		false,
	)
}

// To verify: In loadTrustedRootMetadataFromS3 remove the expiration check; test will fail (no error for expired root).
func TestLoadTrustedRootMetadataFromS3_ExpiredRoot_ReturnsError(t *testing.T) {
	// A root with a past expiration must be rejected even if structurally valid.
	expiredRoot := `{
		"signatures": [],
		"signed": {
			"_type": "root",
			"version": 1,
			"spec_version": "1.0.0",
			"expires": "2020-01-01T00:00:00Z",
			"consistent_snapshot": false,
			"keys": {},
			"roles": {
				"root":      {"keyids": [], "threshold": 1},
				"targets":   {"keyids": [], "threshold": 1},
				"snapshot":  {"keyids": [], "threshold": 1},
				"timestamp": {"keyids": [], "threshold": 1}
			}
		}
	}`

	savedList := tuf_storage.ListMetadataForLatest
	savedViper := tuf_storage.GetViperForDownload
	savedFactory := tuf_storage.StorageFactoryForDownload
	tuf_storage.ListMetadataForLatest = func(_ context.Context, _, _, _ string) ([]string, error) {
		return []string{"1.root.json"}, nil
	}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")
	tuf_storage.GetViperForDownload = func() *viper.Viper { return mockViper }
	tuf_storage.StorageFactoryForDownload = func(*viper.Viper) tuf_storage.StorageFactory {
		return &forceUpdateMockFactory{client: &storageMockClientForForceUpdate{body: []byte(expiredRoot)}}
	}
	defer func() {
		tuf_storage.ListMetadataForLatest = savedList
		tuf_storage.GetViperForDownload = savedViper
		tuf_storage.StorageFactoryForDownload = savedFactory
	}()

	_, err := loadTrustedRootMetadataFromS3(context.Background(), "admin", "app")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func loadTestSigner(privateKey crypto.Signer) (signature.Signer, error) {
	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		return signature.LoadED25519Signer(key)
	case *ecdsa.PrivateKey:
		return signature.LoadECDSASigner(key, crypto.SHA256)
	case *rsa.PrivateKey:
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		return signature.LoadRSAPSSSigner(key, crypto.SHA256, opts)
	default:
		return nil, fmt.Errorf("unsupported test signer type")
	}
}
