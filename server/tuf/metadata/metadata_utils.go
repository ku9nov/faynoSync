package metadata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"faynoSync/server/tuf/models"
	"faynoSync/server/tuf/signing"
	tuf_storage "faynoSync/server/tuf/storage"
	tuf_utils "faynoSync/server/tuf/utils"
	"faynoSync/server/utils"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const stagedSigningDataTTL = 48 * time.Hour

type MetadataUpdateContext struct {
	Ctx            context.Context
	AdminName      string
	AppName        string
	KeySuffix      string
	BootstrapValue string
}

// validateRoot validates the root metadata
func ValidateRoot(roles *repository.Type) error {
	logrus.Debug("Performing root metadata validation")

	var err error
	err = roles.Root().VerifyDelegate("root", roles.Root())
	if err != nil {
		return fmt.Errorf("TUF: verifying root metadata failed: %w", err)
	}

	err = roles.Root().VerifyDelegate("targets", roles.Targets("targets"))
	if err != nil {
		return fmt.Errorf("TUF: verifying targets metadata failed: %w", err)
	}

	err = roles.Root().VerifyDelegate("snapshot", roles.Snapshot())
	if err != nil {
		return fmt.Errorf("TUF: verifying snapshot metadata failed: %w", err)
	}

	err = roles.Root().VerifyDelegate("timestamp", roles.Timestamp())
	if err != nil {
		return fmt.Errorf("TUF: verifying timestamp metadata failed: %w", err)
	}
	logrus.Debug("Root metadata validation completed")
	return nil
}

func validateMetadataUpdatePreconditions(c *gin.Context, redisClient *redis.Client) (*MetadataUpdateContext, bool) {
	adminName, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get admin name from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return nil, false
	}

	appName := c.Query("appName")
	if appName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "appName query parameter is required",
		})
		return nil, false
	}
	if err := tuf_utils.ValidateAppName(appName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return nil, false
	}

	if redisClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Redis client is not available",
		})
		return nil, false
	}

	ctx := context.Background()
	keySuffix := adminName + "_" + appName
	bootstrapKey := "BOOTSTRAP_" + keySuffix
	bootstrapValue, err := redisClient.Get(ctx, bootstrapKey).Result()
	if err != nil && err != redis.Nil {
		logrus.Errorf("Failed to read bootstrap state from Redis for key %s: %v", bootstrapKey, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return nil, false
	}
	if err == redis.Nil || bootstrapValue == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "Task not accepted.",
			"error":   fmt.Sprintf("Requires bootstrap finished. State: %s", bootstrapValue),
		})
		return nil, false
	}

	if strings.HasPrefix(bootstrapValue, "pre-") || strings.HasPrefix(bootstrapValue, "signing-") {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "Task not accepted.",
			"error":   fmt.Sprintf("Requires bootstrap finished. State: %s", bootstrapValue),
		})
		return nil, false
	}

	return &MetadataUpdateContext{
		Ctx:            ctx,
		AdminName:      adminName,
		AppName:        appName,
		KeySuffix:      keySuffix,
		BootstrapValue: bootstrapValue,
	}, true
}

func parseMetadataExpiration(expires string) (time.Time, error) {
	expires = strings.TrimSpace(expires)
	if expires == "" {
		return time.Time{}, fmt.Errorf("missing expires field")
	}

	parsed, err := time.Parse(time.RFC3339Nano, expires)
	if err == nil {
		return parsed.UTC(), nil
	}

	parsed, err = time.Parse(time.RFC3339, expires)
	if err == nil {
		return parsed.UTC(), nil
	}

	return time.Time{}, fmt.Errorf("invalid expires field format")
}

func ensureMetadataNotExpiredFromSigned(signedData map[string]interface{}) error {
	expiresRaw, ok := signedData["expires"].(string)
	if !ok {
		return fmt.Errorf("invalid metadata format: missing expires")
	}
	expiresAt, err := parseMetadataExpiration(expiresRaw)
	if err != nil {
		return err
	}
	if !expiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("metadata is expired")
	}
	return nil
}

func ensureUniqueSignatureKeyIDs(signatures []interface{}) error {
	seen := make(map[string]struct{}, len(signatures))
	for _, sig := range signatures {
		sigMap, ok := sig.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid signature entry")
		}
		keyID, ok := sigMap["keyid"].(string)
		if !ok || strings.TrimSpace(keyID) == "" {
			return fmt.Errorf("invalid signature keyid")
		}
		if _, exists := seen[keyID]; exists {
			return fmt.Errorf("duplicate signature keyid detected: %s", keyID)
		}
		seen[keyID] = struct{}{}
	}
	return nil
}

func ensureDelegationsKeysMatchKeyIDs(signedData map[string]interface{}) error {
	delegationsRaw, ok := signedData["delegations"]
	if !ok {
		return nil
	}
	delegationsMap, ok := delegationsRaw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid metadata format: delegations must be an object")
	}

	keysRaw, ok := delegationsMap["keys"]
	if !ok {
		return nil
	}
	keysMap, ok := keysRaw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid metadata format: delegations.keys must be an object")
	}

	for keyID, keyData := range keysMap {
		if _, err := decodeAndValidateMetadataKey(keyData, keyID); err != nil {
			return fmt.Errorf("invalid delegation key %s: %w", keyID, err)
		}
	}

	return nil
}

func loadTrustedTargetsMetadataFromS3(ctx context.Context, adminName string, appName string, roleName string) (*metadata.Metadata[metadata.TargetsType], error) {
	tmpDir, err := os.MkdirTemp("", "tmp-trusted-role-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	_, filename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to find %s metadata: %w", roleName, err)
	}

	rolePath := filepath.Join(tmpDir, filename)
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, filename, rolePath); err != nil {
		return nil, fmt.Errorf("failed to download %s metadata: %w", roleName, err)
	}

	targetsMeta := metadata.Targets(time.Now().Add(365 * 24 * time.Hour))
	if _, err := targetsMeta.FromFile(rolePath); err != nil {
		return nil, fmt.Errorf("failed to load %s metadata: %w", roleName, err)
	}

	if !targetsMeta.Signed.Expires.After(time.Now().UTC()) {
		return nil, fmt.Errorf("trusted %s metadata is expired at %s", roleName, targetsMeta.Signed.Expires.UTC().Format(time.RFC3339))
	}

	return targetsMeta, nil
}

func loadTrustedRootBytesFromS3(ctx context.Context, adminName string, appName string) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "tmp-trusted-root-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	rootPath := filepath.Join(tmpDir, "root.json")
	_, filename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "root")
	if err != nil {
		if err2 := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "root.json", rootPath); err2 != nil {
			return nil, fmt.Errorf("failed to download root metadata: %w", err2)
		}
	} else {
		if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, filename, rootPath); err != nil {
			return nil, fmt.Errorf("failed to download root metadata: %w", err)
		}
	}

	rootData, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read root metadata: %w", err)
	}

	return rootData, nil
}

func loadTrustedRootMetadataFromS3(ctx context.Context, adminName string, appName string) (*metadata.Metadata[metadata.RootType], error) {
	rootData, err := loadTrustedRootBytesFromS3(ctx, adminName, appName)
	if err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "tmp-trusted-root-meta-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	rootPath := filepath.Join(tmpDir, "root.json")
	if err := os.WriteFile(rootPath, rootData, 0600); err != nil {
		return nil, fmt.Errorf("failed to write root metadata for parsing: %w", err)
	}

	rootMeta := metadata.Root(time.Now().Add(365 * 24 * time.Hour))
	if _, err := rootMeta.FromFile(rootPath); err != nil {
		return nil, fmt.Errorf("failed to load root metadata: %w", err)
	}

	if !rootMeta.Signed.Expires.After(time.Now().UTC()) {
		return nil, fmt.Errorf("trusted root metadata is expired at %s", rootMeta.Signed.Expires.UTC().Format(time.RFC3339))
	}

	if err := rootMeta.VerifyDelegate("root", rootMeta); err != nil {
		return nil, fmt.Errorf("trusted root metadata signature verification failed: %w", err)
	}

	return rootMeta, nil
}

func stageMetadataForSigning(
	ctx context.Context,
	redisClient *redis.Client,
	keySuffix string,
	roleUpper string,
	metadataJSON []byte,
	taskID string,
) error {
	signingKey := fmt.Sprintf("%s_SIGNING_%s", roleUpper, keySuffix)
	taskKey := fmt.Sprintf("%s_SIGNING_TASK_%s", roleUpper, keySuffix)
	pipe := redisClient.TxPipeline()
	defer pipe.Close()

	metadataSetCmd := pipe.Set(ctx, signingKey, string(metadataJSON), stagedSigningDataTTL)
	taskSetCmd := pipe.Set(ctx, taskKey, taskID, stagedSigningDataTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		if metadataErr := metadataSetCmd.Err(); metadataErr != nil {
			return fmt.Errorf("failed to stage metadata for role %s: %w", roleUpper, metadataErr)
		}
		if taskErr := taskSetCmd.Err(); taskErr != nil {
			return fmt.Errorf("failed to stage task for role %s: %w", roleUpper, taskErr)
		}
		return fmt.Errorf("failed to stage metadata for role %s: %w", roleUpper, err)
	}
	return nil
}

type stagedMetadataForSigning struct {
	roleUpper    string
	metadataJSON []byte
}

func stageMetadataBatchForSigning(
	ctx context.Context,
	redisClient *redis.Client,
	keySuffix string,
	taskID string,
	staged []stagedMetadataForSigning,
) error {
	pipe := redisClient.TxPipeline()
	for _, entry := range staged {
		signingKey := fmt.Sprintf("%s_SIGNING_%s", entry.roleUpper, keySuffix)
		taskKey := fmt.Sprintf("%s_SIGNING_TASK_%s", entry.roleUpper, keySuffix)
		pipe.Set(ctx, signingKey, string(entry.metadataJSON), stagedSigningDataTTL)
		pipe.Set(ctx, taskKey, taskID, stagedSigningDataTTL)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to stage metadata batch for signing: %w", err)
	}
	return nil
}

func cleanupStagedMetadataForSigning(
	ctx context.Context,
	redisClient *redis.Client,
	keySuffix string,
	roles []string,
) error {
	if len(roles) == 0 {
		return nil
	}
	pipe := redisClient.TxPipeline()
	for _, roleUpper := range roles {
		signingKey := fmt.Sprintf("%s_SIGNING_%s", roleUpper, keySuffix)
		taskKey := fmt.Sprintf("%s_SIGNING_TASK_%s", roleUpper, keySuffix)
		pipe.Del(ctx, signingKey)
		pipe.Del(ctx, taskKey)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to cleanup staged metadata keys: %w", err)
	}
	return nil
}

func loadTargetsMetadataFromJSONBytes(metadataJSON []byte) (*metadata.Metadata[metadata.TargetsType], error) {
	targetsMeta := metadata.Targets(time.Now().Add(365 * 24 * time.Hour))
	if err := json.Unmarshal(metadataJSON, targetsMeta); err != nil {
		return nil, fmt.Errorf("failed to parse targets metadata: %w", err)
	}

	return targetsMeta, nil
}

func getTargetsSignedVersion(metadataJSON map[string]interface{}) (int64, error) {
	signedData, err := extractSignedSection(metadataJSON)
	if err != nil {
		return 0, err
	}

	versionRaw, ok := signedData["version"]
	if !ok {
		return 0, fmt.Errorf("invalid metadata format: missing version")
	}

	switch v := versionRaw.(type) {
	case float64:
		return int64(v), nil
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("invalid metadata format: version must be numeric")
	}
}

func validateTargetsMetadataForStaging(metadataJSON []byte) (map[string]interface{}, *metadata.Metadata[metadata.TargetsType], error) {
	var envelope map[string]interface{}
	if err := json.Unmarshal(metadataJSON, &envelope); err != nil {
		return nil, nil, fmt.Errorf("failed to parse metadata JSON: %w", err)
	}

	signedData, err := extractSignedSection(envelope)
	if err != nil {
		return nil, nil, err
	}

	metadataType, ok := signedData["_type"].(string)
	if !ok || metadataType != "targets" {
		return nil, nil, fmt.Errorf("expected metadata type 'targets'")
	}

	signatures, ok := envelope["signatures"].([]interface{})
	if !ok {
		signatures = []interface{}{}
	}
	if err := ensureUniqueSignatureKeyIDs(signatures); err != nil {
		return nil, nil, err
	}
	if err := ensureMetadataNotExpiredFromSigned(signedData); err != nil {
		return nil, nil, err
	}
	if err := ensureDelegationsKeysMatchKeyIDs(signedData); err != nil {
		return nil, nil, err
	}

	targetsMeta, err := loadTargetsMetadataFromJSONBytes(metadataJSON)
	if err != nil {
		return nil, nil, err
	}

	return envelope, targetsMeta, nil
}

func ensureDelegatorAuthorizesRole(
	delegatorMeta *metadata.Metadata[metadata.TargetsType],
	roleName string,
) error {
	if delegatorMeta == nil {
		return fmt.Errorf("delegator metadata is required")
	}
	if delegatorMeta.Signed.Delegations == nil {
		return fmt.Errorf("delegator metadata has no delegations")
	}

	var delegatedRole *metadata.DelegatedRole
	for i := range delegatorMeta.Signed.Delegations.Roles {
		role := &delegatorMeta.Signed.Delegations.Roles[i]
		if role.Name == roleName {
			delegatedRole = role
			break
		}
	}
	if delegatedRole == nil {
		return fmt.Errorf("delegated role %s is not defined by delegator", roleName)
	}
	if len(delegatedRole.KeyIDs) == 0 {
		return fmt.Errorf("delegated role %s has no keyids", roleName)
	}
	for _, keyID := range delegatedRole.KeyIDs {
		if _, ok := delegatorMeta.Signed.Delegations.Keys[keyID]; !ok {
			return fmt.Errorf("delegated role %s references missing delegation key %s", roleName, keyID)
		}
	}
	return nil
}

func isTopLevelRole(roleName string) bool {
	switch roleName {
	case "root", "targets", "snapshot", "timestamp":
		return true
	default:
		return false
	}
}

// errRootSignaturesMissing is returned by verifyNewRootMetadata when the
// metadata is structurally valid but lacks sufficient signatures. Callers
// use errors.Is to distinguish this from hard failures (wrong version/type).
var errRootSignaturesMissing = errors.New("root signatures missing or insufficient")

// metaFileFromPath reads path (which must already be written to disk) and
// returns a MetaFiles entry with version, length, and SHA-256 hash. The hash
// must match the bytes stored in S3 so clients can verify downloads.
func metaFileFromPath(path string, version int64) (*metadata.MetaFiles, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s for hash computation: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return &metadata.MetaFiles{
		Version: version,
		Length:  int64(len(data)),
		Hashes:  metadata.Hashes{"sha256": metadata.HexBytes(sum[:])},
	}, nil
}

func verifyNewRootMetadata(currentRoot, newRoot *metadata.Metadata[metadata.RootType]) error {
	if newRoot.Signed.Type != "root" {
		return fmt.Errorf("expected 'root', got '%s'", newRoot.Signed.Type)
	}

	if newRoot.Signed.Version != currentRoot.Signed.Version+1 {
		return fmt.Errorf("expected root version %d, got version %d", currentRoot.Signed.Version+1, newRoot.Signed.Version)
	}

	if err := currentRoot.VerifyDelegate("root", newRoot); err != nil {
		return fmt.Errorf("%w: new root not signed by trusted root: %v", errRootSignaturesMissing, err)
	}

	if err := newRoot.VerifyDelegate("root", newRoot); err != nil {
		return fmt.Errorf("%w: new root threshold not reached: %v", errRootSignaturesMissing, err)
	}

	return nil
}

func loadTrustedRootFromS3(ctx context.Context, adminName string, appName string) (map[string]interface{}, error) {
	rootData, err := loadTrustedRootBytesFromS3(ctx, adminName, appName)
	if err != nil {
		return nil, err
	}

	var rootJSON map[string]interface{}
	if err := json.Unmarshal(rootData, &rootJSON); err != nil {
		return nil, fmt.Errorf("failed to parse root metadata: %w", err)
	}

	return rootJSON, nil
}

func loadTrustedTargetsFromS3(ctx context.Context, adminName string, appName string) (map[string]interface{}, error) {
	tmpDir, err := os.MkdirTemp("", "tmp-trusted-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	targetsPath := filepath.Join(tmpDir, "targets.json")
	_, filename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "targets")
	if err != nil {
		return nil, fmt.Errorf("failed to find targets metadata: %w", err)
	}

	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, filename, targetsPath); err != nil {
		return nil, fmt.Errorf("failed to download targets metadata: %w", err)
	}

	targetsData, err := os.ReadFile(targetsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read targets metadata: %w", err)
	}

	var targetsJSON map[string]interface{}
	if err := json.Unmarshal(targetsData, &targetsJSON); err != nil {
		return nil, fmt.Errorf("failed to parse targets metadata: %w", err)
	}

	return targetsJSON, nil
}

func loadTrustedDelegatedFromS3(ctx context.Context, adminName string, appName string, roleName string) (map[string]interface{}, error) {
	tmpDir, err := os.MkdirTemp("", "tmp-trusted-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	rolePath := filepath.Join(tmpDir, roleName+".json")
	_, filename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to find %s metadata: %w", roleName, err)
	}

	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, filename, rolePath); err != nil {
		return nil, fmt.Errorf("failed to download %s metadata: %w", roleName, err)
	}

	roleData, err := os.ReadFile(rolePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s metadata: %w", roleName, err)
	}

	var roleJSON map[string]interface{}
	if err := json.Unmarshal(roleData, &roleJSON); err != nil {
		return nil, fmt.Errorf("failed to parse %s metadata: %w", roleName, err)
	}

	return roleJSON, nil
}

func extractSignedSection(metadataJSON map[string]interface{}) (map[string]interface{}, error) {
	signedData, ok := metadataJSON["signed"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: missing 'signed' field")
	}
	return signedData, nil
}

func decodeAndValidateMetadataKey(keyData interface{}, expectedKeyID string) (*metadata.Key, error) {
	keyBytes, err := json.Marshal(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to encode key %s: %w", expectedKeyID, err)
	}
	var key metadata.Key
	if err := json.Unmarshal(keyBytes, &key); err != nil {
		return nil, fmt.Errorf("failed to decode key %s: %w", expectedKeyID, err)
	}

	computedKeyID, err := key.ID()
	if err != nil {
		return nil, fmt.Errorf("failed to compute key ID for %s: %w", expectedKeyID, err)
	}
	if computedKeyID != expectedKeyID {
		return nil, fmt.Errorf("keyid mismatch: provided %s, computed %s", expectedKeyID, computedKeyID)
	}

	return &key, nil
}

func getRootRoleKeysFromSigned(signedData map[string]interface{}, roleName string) (map[string]*metadata.Key, error) {
	rolesMap, ok := signedData["roles"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: missing 'roles' field")
	}
	roleData, ok := rolesMap[roleName].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("role %s not found in metadata", roleName)
	}
	keyIDsRaw, ok := roleData["keyids"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: role %s missing keyids", roleName)
	}
	keysMap, ok := signedData["keys"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: missing 'keys' field")
	}

	result := make(map[string]*metadata.Key, len(keyIDsRaw))
	for _, raw := range keyIDsRaw {
		keyID, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid keyid entry in role %s", roleName)
		}
		keyData, exists := keysMap[keyID]
		if !exists {
			return nil, fmt.Errorf("key %s referenced by role %s not found", keyID, roleName)
		}
		key, err := decodeAndValidateMetadataKey(keyData, keyID)
		if err != nil {
			return nil, err
		}
		result[keyID] = key
	}

	return result, nil
}

func getDelegatedRoleKeysFromTrustedTargets(trustedTargets map[string]interface{}, roleName string) (map[string]*metadata.Key, error) {
	signedData, err := extractSignedSection(trustedTargets)
	if err != nil {
		return nil, err
	}
	delegationsMap, ok := signedData["delegations"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid trusted targets metadata: missing delegations")
	}
	delegatedRolesRaw, ok := delegationsMap["roles"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid trusted targets metadata: missing delegated roles")
	}
	delegatedKeysRaw, ok := delegationsMap["keys"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid trusted targets metadata: missing delegated keys")
	}

	var delegatedRole map[string]interface{}
	for _, rawRole := range delegatedRolesRaw {
		roleMap, ok := rawRole.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := roleMap["name"].(string)
		if name == roleName {
			delegatedRole = roleMap
			break
		}
	}
	if delegatedRole == nil {
		return nil, fmt.Errorf("delegated role %s not found in trusted targets metadata", roleName)
	}

	keyIDsRaw, ok := delegatedRole["keyids"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid delegated role %s: missing keyids", roleName)
	}

	result := make(map[string]*metadata.Key, len(keyIDsRaw))
	for _, raw := range keyIDsRaw {
		keyID, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid delegated keyid for role %s", roleName)
		}
		keyData, exists := delegatedKeysRaw[keyID]
		if !exists {
			return nil, fmt.Errorf("delegated key %s for role %s not found", keyID, roleName)
		}
		key, err := decodeAndValidateMetadataKey(keyData, keyID)
		if err != nil {
			return nil, err
		}
		result[keyID] = key
	}

	return result, nil
}

func verifySignatureOverSignedPayload(signedData map[string]interface{}, key *metadata.Key, signatureHex string) error {
	canonicalSigned, err := cjson.EncodeCanonical(signedData)
	if err != nil {
		return fmt.Errorf("failed to canonicalize signed payload: %w", err)
	}

	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	publicKey, err := key.ToPublicKey()
	if err != nil {
		return fmt.Errorf("failed to parse public key for verification: %w", err)
	}
	verifier, err := signing.BuildVerifierForPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to initialize verifier: %w", err)
	}

	if err := verifier.VerifySignature(bytes.NewReader(signatureBytes), bytes.NewReader(canonicalSigned)); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func validateIncomingMetadataSignature(
	ctx context.Context,
	adminName string,
	appName string,
	metadataType string,
	roleName string,
	keyID string,
	signatureHex string,
	signedData map[string]interface{},
	isSigningState bool,
) error {
	var allowedKeys map[string]*metadata.Key
	var err error

	switch metadataType {
	case "root":
		allowedKeys, err = getRootRoleKeysFromSigned(signedData, "root")
		if err != nil {
			return err
		}
		if !isSigningState {
			trustedRoot, trustedErr := loadTrustedRootFromS3(ctx, adminName, appName)
			if trustedErr != nil {
				return fmt.Errorf("trusted root is required for signature authorization: %w", trustedErr)
			}
			trustedRootSigned, signedErr := extractSignedSection(trustedRoot)
			if signedErr != nil {
				return fmt.Errorf("invalid trusted root metadata: %w", signedErr)
			}
			oldRootKeys, keyErr := getRootRoleKeysFromSigned(trustedRootSigned, "root")
			if keyErr != nil {
				return fmt.Errorf("failed to read trusted root keys: %w", keyErr)
			}
			for oldKeyID, oldKey := range oldRootKeys {
				if _, exists := allowedKeys[oldKeyID]; !exists {
					allowedKeys[oldKeyID] = oldKey
				}
			}
		}
	case "targets":
		if roleName == "targets" {
			trustedRoot, trustedErr := loadTrustedRootFromS3(ctx, adminName, appName)
			if trustedErr != nil {
				return fmt.Errorf("trusted root is required for signature authorization: %w", trustedErr)
			}
			trustedRootSigned, signedErr := extractSignedSection(trustedRoot)
			if signedErr != nil {
				return fmt.Errorf("invalid trusted root metadata: %w", signedErr)
			}
			allowedKeys, err = getRootRoleKeysFromSigned(trustedRootSigned, "targets")
			if err != nil {
				return fmt.Errorf("failed to read trusted root targets keys: %w", err)
			}
		} else {
			trustedTargets, trustedErr := loadTrustedTargetsFromS3(ctx, adminName, appName)
			if trustedErr != nil {
				return fmt.Errorf("trusted targets metadata is required for delegated signature authorization: %w", trustedErr)
			}
			allowedKeys, err = getDelegatedRoleKeysFromTrustedTargets(trustedTargets, roleName)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("signature validation not supported for metadata type %q", metadataType)
	}

	key, ok := allowedKeys[keyID]
	if !ok {
		return fmt.Errorf("keyid %s is not authorized for role %s", keyID, roleName)
	}

	if err := verifySignatureOverSignedPayload(signedData, key, signatureHex); err != nil {
		return err
	}

	return nil
}

func finalizeRootMetadataUpdate(
	ctx context.Context,
	repo *repository.Type,
	adminName string,
	appName string,
	tmpDir string,
	isBootstrap bool,
	bootstrapValue string,
	redisClient *redis.Client,
) error {
	root := repo.Root()
	if root == nil {
		return fmt.Errorf("root metadata not loaded")
	}

	rootFilename := fmt.Sprintf("%d.root.json", root.Signed.Version)
	rootPath := filepath.Join(tmpDir, rootFilename)
	if err := root.ToFile(rootPath, true); err != nil {
		return fmt.Errorf("failed to save root metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, rootFilename, rootPath); err != nil {
		return fmt.Errorf("failed to upload root metadata to S3: %w", err)
	}

	if isBootstrap {
		bootstrapKey := "BOOTSTRAP_" + adminName + "_" + appName
		if strings.HasPrefix(bootstrapValue, "signing-") {
			taskID := strings.TrimPrefix(bootstrapValue, "signing-")
			if err := redisClient.Set(ctx, bootstrapKey, taskID, 0).Err(); err != nil {
				logrus.Warnf("Failed to update bootstrap state: %v", err)
			}
		}
	}

	logrus.Infof("Successfully finalized root metadata update: %s", rootFilename)
	return nil
}

func finalizeTargetsMetadataUpdate(
	ctx context.Context,
	repo *repository.Type,
	roleName string,
	adminName string,
	appName string,
	tmpDir string,
	redisClient *redis.Client,
) error {
	logrus.Debugf("Finalizing targets metadata update for role %s", roleName)
	targets := repo.Targets(roleName)
	if targets == nil {
		return fmt.Errorf("targets metadata not loaded for role %s", roleName)
	}
	if !targets.Signed.Expires.After(time.Now().UTC()) {
		return fmt.Errorf("targets metadata for role %s is expired", roleName)
	}

	targetsFilename := fmt.Sprintf("%d.%s.json", targets.Signed.Version, roleName)
	targetsPath := filepath.Join(tmpDir, targetsFilename)
	if err := targets.ToFile(targetsPath, true); err != nil {
		return fmt.Errorf("failed to save targets metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, targetsFilename, targetsPath); err != nil {
		return fmt.Errorf("failed to upload targets metadata to S3: %w", err)
	}

	// Load root metadata to obtain snapshot and timestamp key IDs for re-signing.
	rootPath := filepath.Join(tmpDir, "finalize_root.json")
	_, rootFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "root")
	if err != nil {
		return fmt.Errorf("failed to find root metadata version: %w", err)
	}
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, rootFilename, rootPath); err != nil {
		return fmt.Errorf("failed to download root metadata: %w", err)
	}

	rootData, err := os.ReadFile(rootPath)
	if err != nil {
		return fmt.Errorf("failed to read root metadata: %w", err)
	}

	var rootMetadata models.RootMetadata
	if err := json.Unmarshal(rootData, &rootMetadata); err != nil {
		return fmt.Errorf("failed to parse root metadata: %w", err)
	}

	// Build snapshot signers from root-declared keys.
	snapshotRole, ok := rootMetadata.Signed.Roles["snapshot"]
	if !ok || len(snapshotRole.KeyIDs) == 0 {
		return fmt.Errorf("snapshot role not found in root metadata")
	}
	snapshotSigners, err := buildOnlineRoleSigners(snapshotRole.KeyIDs, snapshotRole.Threshold, "snapshot")
	if err != nil {
		return fmt.Errorf("failed to build snapshot signers: %w", err)
	}

	// Build timestamp signers from root-declared keys.
	timestampRole, ok := rootMetadata.Signed.Roles["timestamp"]
	if !ok || len(timestampRole.KeyIDs) == 0 {
		return fmt.Errorf("timestamp role not found in root metadata")
	}
	timestampSigners, err := buildOnlineRoleSigners(timestampRole.KeyIDs, timestampRole.Threshold, "timestamp")
	if err != nil {
		return fmt.Errorf("failed to build timestamp signers: %w", err)
	}

	keySuffix := adminName + "_" + appName

	// --- Update and re-sign snapshot ---
	_, snapshotFilename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, "snapshot")
	if err != nil {
		return fmt.Errorf("failed to find latest snapshot version: %w", err)
	}

	snapshotPath := filepath.Join(tmpDir, snapshotFilename)
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, snapshotFilename, snapshotPath); err != nil {
		return fmt.Errorf("failed to download snapshot metadata: %w", err)
	}

	snapshotExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "SNAPSHOT_EXPIRATION_"+keySuffix, 7)
	snapshot := metadata.Snapshot(tuf_utils.HelperExpireIn(snapshotExpiration))
	repo.SetSnapshot(snapshot)
	if _, err := repo.Snapshot().FromFile(snapshotPath); err != nil {
		return fmt.Errorf("failed to load snapshot metadata: %w", err)
	}

	targetsMF, err := metaFileFromPath(targetsPath, int64(targets.Signed.Version))
	if err != nil {
		return fmt.Errorf("failed to compute hash for %s: %w", roleName, err)
	}
	repo.Snapshot().Signed.Meta[fmt.Sprintf("%s.json", roleName)] = targetsMF
	repo.Snapshot().Signed.Version++
	repo.Snapshot().Signed.Expires = tuf_utils.HelperExpireIn(snapshotExpiration)
	repo.Snapshot().ClearSignatures()

	for i, s := range snapshotSigners {
		if _, err := repo.Snapshot().Sign(s); err != nil {
			return fmt.Errorf("failed to sign snapshot metadata with key %d: %w", i+1, err)
		}
	}

	newSnapshotFilename := fmt.Sprintf("%d.snapshot.json", repo.Snapshot().Signed.Version)
	newSnapshotPath := filepath.Join(tmpDir, newSnapshotFilename)
	if err := repo.Snapshot().ToFile(newSnapshotPath, true); err != nil {
		return fmt.Errorf("failed to save snapshot metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, newSnapshotFilename, newSnapshotPath); err != nil {
		return fmt.Errorf("failed to upload snapshot metadata to S3: %w", err)
	}

	logrus.Infof("Successfully updated and signed snapshot to version %d", repo.Snapshot().Signed.Version)

	// --- Update and re-sign timestamp to reference new snapshot ---
	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "timestamp.json", timestampPath); err != nil {
		logrus.Debugf("Timestamp metadata not found in storage, will create new: %v", err)
	}

	timestampExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TIMESTAMP_EXPIRATION_"+keySuffix, 1)
	timestamp := metadata.Timestamp(tuf_utils.HelperExpireIn(timestampExpiration))
	repo.SetTimestamp(timestamp)
	loadedTimestamp := false
	if _, statErr := os.Stat(timestampPath); statErr == nil {
		if _, loadErr := repo.Timestamp().FromFile(timestampPath); loadErr != nil {
			logrus.Warnf("Failed to load timestamp metadata: %v, creating new one", loadErr)
		} else {
			loadedTimestamp = true
		}
	}

	timestampMeta := repo.Timestamp().Signed.Meta
	if timestampMeta == nil {
		timestampMeta = make(map[string]*metadata.MetaFiles)
		repo.Timestamp().Signed.Meta = timestampMeta
	}
	snapshotMF, err := metaFileFromPath(newSnapshotPath, int64(repo.Snapshot().Signed.Version))
	if err != nil {
		return fmt.Errorf("failed to compute snapshot hash for timestamp: %w", err)
	}
	timestampMeta["snapshot.json"] = snapshotMF

	if loadedTimestamp {
		repo.Timestamp().Signed.Version++
	}
	repo.Timestamp().Signed.Expires = tuf_utils.HelperExpireIn(timestampExpiration)
	repo.Timestamp().ClearSignatures()

	for i, s := range timestampSigners {
		if _, err := repo.Timestamp().Sign(s); err != nil {
			return fmt.Errorf("failed to sign timestamp metadata with key %d: %w", i+1, err)
		}
	}

	timestampOutPath := filepath.Join(tmpDir, "timestamp.json")
	if err := repo.Timestamp().ToFile(timestampOutPath, true); err != nil {
		return fmt.Errorf("failed to save timestamp metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, "timestamp.json", timestampOutPath); err != nil {
		return fmt.Errorf("failed to upload timestamp metadata to S3: %w", err)
	}

	logrus.Debugf("Successfully updated and signed timestamp referencing snapshot version %d", repo.Snapshot().Signed.Version)

	logrus.Infof("Successfully finalized targets metadata update: %s", targetsFilename)
	return nil
}
