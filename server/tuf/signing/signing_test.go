package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustGenerateEd25519Seed returns a 32-byte seed for testing. Panics on error.
func mustGenerateEd25519Seed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	require.NoError(t, err)
	return seed
}

// mustMarshalPKCS8PEM returns PEM-encoded PKCS8 Ed25519 private key. Panics on error.
func mustMarshalPKCS8PEM(t *testing.T, seed []byte) []byte {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(seed)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return pem.EncodeToMemory(block)
}

// To verify: In LoadPrivateKeyFromFilesystem set keyDir to "fallback" when env is empty; test will fail (no error).
func TestLoadPrivateKeyFromFilesystem_ONLINE_KEY_DIR_Empty(t *testing.T) {
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", "")
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	key, err := LoadPrivateKeyFromFilesystem("key-id-1", "some-file")

	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "ONLINE_KEY_DIR")
}

// To verify: In LoadPrivateKeyFromFilesystem return nil, nil when file is missing; test will fail (wrong return).
func TestLoadPrivateKeyFromFilesystem_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", dir)
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	key, err := LoadPrivateKeyFromFilesystem("key-id", "nonexistent.pem")

	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "failed to read private key file")
}

// To verify: In LoadPrivateKeyFromFilesystem change condition from len(keyData)==32 to len(keyData)==64; test will fail (wrong key or error).
func TestLoadPrivateKeyFromFilesystem_Raw32Bytes(t *testing.T) {
	dir := t.TempDir()
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", dir)
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	seed := mustGenerateEd25519Seed(t)
	keyPath := filepath.Join(dir, "raw32.key")
	require.NoError(t, os.WriteFile(keyPath, seed, 0600))

	key, err := LoadPrivateKeyFromFilesystem("key-id", "raw32.key")

	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Len(t, key, ed25519.PrivateKeySize)
	assert.Equal(t, seed, key.Seed(), "Loaded key seed should match written seed")
}

// To verify: In LoadPrivateKeyFromFilesystem change hex branch to require len(keyDataStr)==32; test will fail (wrong path).
func TestLoadPrivateKeyFromFilesystem_Hex64Chars(t *testing.T) {
	dir := t.TempDir()
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", dir)
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	seed := mustGenerateEd25519Seed(t)
	hexStr := hex.EncodeToString(seed)
	keyPath := filepath.Join(dir, "hex.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(hexStr), 0600))

	key, err := LoadPrivateKeyFromFilesystem("key-id", "hex.key")

	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, seed, key.Seed(), "Loaded key seed should match hex-decoded seed")
}

// To verify: In LoadPrivateKeyFromFilesystem skip x509.ParsePKCS8PrivateKey or return before type assert; test will fail.
func TestLoadPrivateKeyFromFilesystem_PEM_PKCS8_Ed25519(t *testing.T) {
	dir := t.TempDir()
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", dir)
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	seed := mustGenerateEd25519Seed(t)
	pemBytes := mustMarshalPKCS8PEM(t, seed)
	keyPath := filepath.Join(dir, "pkcs8.pem")
	require.NoError(t, os.WriteFile(keyPath, pemBytes, 0600))

	key, err := LoadPrivateKeyFromFilesystem("key-id", "pkcs8.pem")

	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, seed, key.Seed(), "Loaded key seed should match PEM PKCS8 key")
}

// To verify: In LoadPrivateKeyFromFilesystem remove the block.Bytes length 32 branch; test will fail (fallthrough to error).
func TestLoadPrivateKeyFromFilesystem_PEM_Raw32InBlock(t *testing.T) {
	dir := t.TempDir()
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", dir)
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	seed := mustGenerateEd25519Seed(t)
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: seed}
	pemBytes := pem.EncodeToMemory(block)
	keyPath := filepath.Join(dir, "pem_raw32.pem")
	require.NoError(t, os.WriteFile(keyPath, pemBytes, 0600))

	key, err := LoadPrivateKeyFromFilesystem("key-id", "pem_raw32.pem")

	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, seed, key.Seed(), "Loaded key seed should match raw 32 bytes in PEM block")
}

// To verify: In LoadPrivateKeyFromFilesystem use keyURI as fileName when it has "fn:" prefix (do not trim); test will fail (file not found).
func TestLoadPrivateKeyFromFilesystem_KeyURI_FnPrefix(t *testing.T) {
	dir := t.TempDir()
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", dir)
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	seed := mustGenerateEd25519Seed(t)
	// File is named "targets.key", keyURI is "fn:targets.key"
	keyPath := filepath.Join(dir, "targets.key")
	require.NoError(t, os.WriteFile(keyPath, seed, 0600))

	key, err := LoadPrivateKeyFromFilesystem("some-key-id", "fn:targets.key")

	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, seed, key.Seed())
}

// To verify: In LoadPrivateKeyFromFilesystem use keyURI as fileName when keyURI is empty instead of keyID; test will fail (wrong file).
func TestLoadPrivateKeyFromFilesystem_KeyURI_Empty_UsesKeyID(t *testing.T) {
	dir := t.TempDir()
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", dir)
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	seed := mustGenerateEd25519Seed(t)
	keyPath := filepath.Join(dir, "my-key-id")
	require.NoError(t, os.WriteFile(keyPath, seed, 0600))

	key, err := LoadPrivateKeyFromFilesystem("my-key-id", "")

	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, seed, key.Seed())
}

// To verify: In LoadPrivateKeyFromFilesystem use keyID as fileName when keyURI is non-empty and not "fn:"; test will fail (file not found).
func TestLoadPrivateKeyFromFilesystem_KeyURI_NonFn_UsesKeyURI(t *testing.T) {
	dir := t.TempDir()
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", dir)
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	seed := mustGenerateEd25519Seed(t)
	keyPath := filepath.Join(dir, "custom_name.key")
	require.NoError(t, os.WriteFile(keyPath, seed, 0600))

	key, err := LoadPrivateKeyFromFilesystem("key-id-ignored", "custom_name.key")

	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, seed, key.Seed())
}

// To verify: In LoadPrivateKeyFromFilesystem return nil, nil for bad format instead of error; test will fail.
func TestLoadPrivateKeyFromFilesystem_InvalidFormat_Unrecognized(t *testing.T) {
	dir := t.TempDir()
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", dir)
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	// 30 bytes: not 32, not PEM, not 64-char hex
	badContent := make([]byte, 30)
	for i := range badContent {
		badContent[i] = byte(i)
	}
	keyPath := filepath.Join(dir, "bad.key")
	require.NoError(t, os.WriteFile(keyPath, badContent, 0600))

	key, err := LoadPrivateKeyFromFilesystem("key-id", "bad.key")

	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "could not load private key")
	assert.Contains(t, err.Error(), "expected PEM format, raw 32 bytes, or hex-encoded seed")
}

// To verify: In LoadPrivateKeyFromFilesystem accept any 64-char string as hex without decoding; test will fail (wrong behavior).
func TestLoadPrivateKeyFromFilesystem_Hex64_InvalidHex(t *testing.T) {
	dir := t.TempDir()
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", dir)
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	// 64 characters but not valid hex (contains 'z')
	invalidHex := "z000000000000000000000000000000000000000000000000000000000000000"
	keyPath := filepath.Join(dir, "badhex.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(invalidHex), 0600))

	key, err := LoadPrivateKeyFromFilesystem("key-id", "badhex.key")

	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "could not load private key")
}

// To verify: In LoadPrivateKeyFromFilesystem remove strings.TrimSpace; test will fail when file has newline.
func TestLoadPrivateKeyFromFilesystem_Hex64_WithWhitespace(t *testing.T) {
	dir := t.TempDir()
	env := viper.GetViper()
	oldDir := env.GetString("ONLINE_KEY_DIR")
	env.Set("ONLINE_KEY_DIR", dir)
	defer env.Set("ONLINE_KEY_DIR", oldDir)

	seed := mustGenerateEd25519Seed(t)
	hexStr := hex.EncodeToString(seed) + "\n"
	keyPath := filepath.Join(dir, "hex_newline.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(hexStr), 0600))

	key, err := LoadPrivateKeyFromFilesystem("key-id", "hex_newline.key")

	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, seed, key.Seed())
}
