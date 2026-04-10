package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

func LoadPrivateKeyAnyFromFilesystem(keyID string, keyURI string) (crypto.PrivateKey, error) {
	env := viper.GetViper()
	keyDir := env.GetString("ONLINE_KEY_DIR")
	if keyDir == "" {
		return nil, fmt.Errorf("ONLINE_KEY_DIR environment variable not set")
	}

	var fileName string
	if strings.HasPrefix(keyURI, "fn:") {
		fileName = strings.TrimPrefix(keyURI, "fn:")
	} else if keyURI != "" {
		fileName = keyURI
	} else {
		fileName = keyID
	}

	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		return nil, fmt.Errorf("private key filename is empty for keyID %s", keyID)
	}
	if fileName != filepath.Base(fileName) || fileName == "." || fileName == ".." {
		return nil, fmt.Errorf("invalid private key filename %q for keyID %s", fileName, keyID)
	}

	keyPath := filepath.Join(keyDir, fileName)
	absKeyDir, err := filepath.Abs(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute key directory path %s: %w", keyDir, err)
	}
	absKeyPath, err := filepath.Abs(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute key path %s: %w", keyPath, err)
	}
	relPath, err := filepath.Rel(absKeyDir, absKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to validate private key path %s: %w", keyPath, err)
	}
	if relPath == ".." || strings.HasPrefix(relPath, ".."+string(os.PathSeparator)) {
		return nil, fmt.Errorf("private key path %s escapes key directory %s", keyPath, keyDir)
	}

	logrus.Debugf("Loading private key from filesystem: %s (keyID: %s)", keyPath, keyID)

	fileInfo, err := os.Lstat(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read private key file %s: %w", keyPath, err)
		}
		return nil, fmt.Errorf("failed to stat private key file %s: %w", keyPath, err)
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to load private key from symlink path %s", keyPath)
	}
	if fileInfo.IsDir() {
		return nil, fmt.Errorf("private key path %s is a directory", keyPath)
	}

	fd, err := syscall.Open(keyPath, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("refusing to open private key file %s: symlink following is not allowed", keyPath)
		}
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read private key file %s: %w", keyPath, err)
		}
		return nil, fmt.Errorf("failed to securely open private key file %s: %w", keyPath, err)
	}

	keyFile := os.NewFile(uintptr(fd), keyPath)
	if keyFile == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("failed to create file handle for private key file %s", keyPath)
	}
	defer func() {
		_ = keyFile.Close()
	}()

	keyData, err := io.ReadAll(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", keyPath, err)
	}

	for rest := keyData; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if privateKey, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
			switch typed := privateKey.(type) {
			case ed25519.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey:
				logrus.Debugf("Successfully loaded private key from PKCS8 PEM file: %s", keyPath)
				return typed, nil
			default:
				logrus.Debugf("Parsed unsupported private key type from PKCS8 PEM file: type=%s path=%s", fmt.Sprintf("%T", typed), keyPath)
			}
		}
		if privateKey, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
			logrus.Debugf("Successfully loaded RSA private key from PKCS1 PEM file: %s", keyPath)
			return privateKey, nil
		}
		if privateKey, parseErr := x509.ParseECPrivateKey(block.Bytes); parseErr == nil {
			logrus.Debugf("Successfully loaded ECDSA private key from SEC1 PEM file: %s", keyPath)
			return privateKey, nil
		}
		if len(block.Bytes) == 32 {
			ed25519Key := ed25519.NewKeyFromSeed(block.Bytes)
			logrus.Debugf("Successfully loaded Ed25519 private key from raw seed in PEM: %s", keyPath)
			return ed25519Key, nil
		}
	}

	if len(keyData) == 32 {
		ed25519Key := ed25519.NewKeyFromSeed(keyData)
		logrus.Debugf("Successfully loaded Ed25519 private key from raw seed: %s", keyPath)
		return ed25519Key, nil
	}

	keyDataStr := strings.TrimSpace(string(keyData))
	if len(keyDataStr) == 64 {
		seedBytes, err := hex.DecodeString(keyDataStr)
		if err == nil && len(seedBytes) == 32 {
			ed25519Key := ed25519.NewKeyFromSeed(seedBytes)
			logrus.Debugf("Successfully loaded Ed25519 private key from hex-encoded seed: %s", keyPath)
			return ed25519Key, nil
		}
	}

	return nil, fmt.Errorf("could not load private key from %s: expected PEM format, raw 32 bytes, or hex-encoded seed", keyPath)
}

func BuildSignerFromPrivateKeyFile(keyID string, keyURI string) (signature.Signer, error) {
	privateKey, err := LoadPrivateKeyAnyFromFilesystem(keyID, keyURI)
	if err != nil {
		return nil, err
	}

	pubProvider, ok := privateKey.(interface {
		Public() crypto.PublicKey
	})
	if !ok {
		return nil, fmt.Errorf("private key for %s does not expose public key", keyID)
	}
	tufKey, err := tufmetadata.KeyFromPublicKey(pubProvider.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to derive TUF key from private key %s: %w", keyID, err)
	}
	computedKeyID, err := tufKey.ID()
	if err != nil {
		return nil, fmt.Errorf("failed to compute key ID for private key %s: %w", keyID, err)
	}
	if computedKeyID != keyID {
		return nil, fmt.Errorf("keyid mismatch for loaded private key: expected %s, got %s", keyID, computedKeyID)
	}

	var signer signature.Signer
	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		signer, err = signature.LoadED25519Signer(key)
	case *ecdsa.PrivateKey:
		signer, err = signature.LoadECDSASigner(key, crypto.SHA256)
	case *rsa.PrivateKey:
		pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		signer, err = signature.LoadRSAPSSSigner(key, crypto.SHA256, pssOpts)
	default:
		return nil, fmt.Errorf("unsupported private key type for key %s", keyID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create signer for key %s: %w", keyID, err)
	}

	return signer, nil
}

func BuildVerifierForPublicKey(publicKey crypto.PublicKey) (signature.Verifier, error) {
	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		return signature.LoadED25519Verifier(key)
	case *ecdsa.PublicKey:
		return signature.LoadECDSAVerifier(key, crypto.SHA256)
	case *rsa.PublicKey:
		pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		return signature.LoadRSAPSSVerifier(key, crypto.SHA256, pssOpts)
	default:
		return nil, fmt.Errorf("unsupported public key type for verifier")
	}
}

func SignatureHashForKey(key interface{}) (crypto.Hash, error) {
	switch key.(type) {
	case ed25519.PrivateKey, ed25519.PublicKey:
		return crypto.Hash(0), nil
	case *rsa.PrivateKey, *rsa.PublicKey, *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return crypto.SHA256, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %T", key)
	}
}

func LoadAndSignDelegation(
	roleName string,
	roleKeyIDs []string,
	threshold int,
	signWithSigner func(signature.Signer, string) error,
) ([]string, error) {
	if signWithSigner == nil {
		return nil, fmt.Errorf("sign callback is required for %s role", roleName)
	}
	if threshold < 1 {
		threshold = 1
	}

	seen := make(map[string]bool)
	keysToUse := make([]string, 0, threshold)
	for _, keyID := range roleKeyIDs {
		if seen[keyID] {
			continue
		}
		seen[keyID] = true
		keysToUse = append(keysToUse, keyID)
		if len(keysToUse) == threshold {
			break
		}
	}
	if len(keysToUse) < threshold {
		return nil, fmt.Errorf("not enough distinct keys for %s role: need %d, got %d", roleName, threshold, len(keysToUse))
	}

	usedKeyIDs := make([]string, 0, len(keysToUse))
	for _, keyID := range keysToUse {
		signer, err := BuildSignerFromPrivateKeyFile(keyID, keyID)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s private key %s: %w", roleName, keyID, err)
		}

		if err := signWithSigner(signer, keyID); err != nil {
			return nil, fmt.Errorf("failed to sign %s metadata with key %s: %w", roleName, keyID, err)
		}
		usedKeyIDs = append(usedKeyIDs, keyID)
	}

	return usedKeyIDs, nil
}
