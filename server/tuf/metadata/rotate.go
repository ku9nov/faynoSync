package metadata

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"faynoSync/server/tuf/models"
	tuf_storage "faynoSync/server/tuf/storage"
	"faynoSync/server/tuf/tasks"
	tuf_utils "faynoSync/server/tuf/utils"
	"faynoSync/server/utils"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	gotufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

const rotateMetadataType = "rotate"

var listMetadataForRotate = tuf_storage.ListMetadataFromS3

type rotateMetadata struct {
	Signatures []models.Signature `json:"signatures"`
	Signed     rotateSigned       `json:"signed"`
}

type rotateSigned struct {
	Type      string                        `json:"_type"`
	Version   int                           `json:"version"`
	Role      string                        `json:"role"`
	Keys      map[string]*gotufmetadata.Key `json:"keys"`
	Threshold int                           `json:"threshold"`
}

type roleTrustState struct {
	Keys      map[string]*gotufmetadata.Key
	KeyIDs    []string
	Threshold int
}

type verifiedRoleState struct {
	Root               *gotufmetadata.Metadata[gotufmetadata.RootType]
	Targets            *gotufmetadata.Metadata[gotufmetadata.TargetsType]
	CurrentRole        *gotufmetadata.Metadata[gotufmetadata.TargetsType]
	CurrentTrust       roleTrustState
	LastRotateVersion  int
	CurrentRoleVersion int64
}

func PostMetadataRotateKeys(c *gin.Context, redisClient *redis.Client) {
	adminName, err := utils.GetUsernameFromContext(c)
	if err != nil {
		logrus.Errorf("Failed to get admin name from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	appName := c.Query("appName")
	if appName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "appName query parameter is required"})
		return
	}
	if redisClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Redis client is not available"})
		return
	}

	var payload models.MetadataRotateKeysPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid payload format: %v", err)})
		return
	}

	ctx := context.Background()
	keySuffix := adminName + "_" + appName
	bootstrapValue, err := redisClient.Get(ctx, "BOOTSTRAP_"+keySuffix).Result()
	if err == redis.Nil || bootstrapValue == "" || strings.HasPrefix(bootstrapValue, "pre-") || strings.HasPrefix(bootstrapValue, "signing-") {
		c.JSON(http.StatusNotFound, gin.H{
			"message": "Task not accepted.",
			"error":   fmt.Sprintf("Requires bootstrap finished. State: %s", bootstrapValue),
		})
		return
	}
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Storage temporarily unavailable"})
		return
	}

	taskName := tasks.TaskNameRotateKeys
	roleName := strings.TrimSpace(payload.Role)
	tmpDir, err := os.MkdirTemp("", "tuf-rotate-*")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temporary directory"})
		return
	}
	defer os.RemoveAll(tmpDir)

	if len(payload.Metadata) == 0 {
		signingTaskID, err := startRotateMetadataSigning(ctx, redisClient, adminName, appName, roleName, payload.Rotate, tmpDir)
		if err != nil {
			if signingTaskID == "" {
				signingTaskID = uuid.New().String()
			}
			saveRotateTaskFailure(redisClient, signingTaskID, taskName, err)
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Rotate metadata signing failed",
				"error":   err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, models.MetadataPostResponse{
			Data: models.MetadataPostData{
				TaskID:     signingTaskID,
				LastUpdate: time.Now(),
			},
			Message: "Rotate metadata is pending signatures",
		})
		return
	}

	taskID := uuid.New().String()
	_ = tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateRunning, &tasks.TaskResult{Task: &taskName})

	result, err := publishRotatedRoleMetadata(ctx, redisClient, adminName, appName, roleName, payload.Rotate, payload.Metadata, tmpDir)
	if err != nil {
		saveRotateTaskFailure(redisClient, taskID, taskName, err)
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Role key rotation failed",
			"error":   err.Error(),
		})
		return
	}

	success := true
	message := "Role key rotation completed successfully"
	_ = tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateSuccess, &tasks.TaskResult{
		Task:    &taskName,
		Status:  &success,
		Message: &message,
		Details: map[string]interface{}{
			"role":              roleName,
			"rotate_file":       result.RotateFilename,
			"metadata_file":     result.RoleMetadataFilename,
			"snapshot_file":     result.SnapshotFilename,
			"timestamp_updated": true,
		},
	})

	c.JSON(http.StatusOK, models.MetadataPostResponse{
		Data: models.MetadataPostData{
			TaskID:     taskID,
			LastUpdate: time.Now(),
		},
		Message: "Role key rotation processed",
	})
}

func startRotateMetadataSigning(
	ctx context.Context,
	redisClient *redis.Client,
	adminName string,
	appName string,
	roleName string,
	rotateRaw json.RawMessage,
	tmpDir string,
) (string, error) {
	if err := validateTAP8RoleName(roleName); err != nil {
		return "", err
	}
	state, err := loadVerifiedRoleState(ctx, adminName, appName, roleName, tmpDir)
	if err != nil {
		return "", err
	}
	if _, err := validateRotateMetadataShape(rotateRaw, roleName, state.LastRotateVersion+1); err != nil {
		return "", err
	}

	taskID := uuid.New().String()
	keySuffix := adminName + "_" + appName
	signingRole := rotateSigningRoleName(roleName)
	signingKey := fmt.Sprintf("%s_SIGNING_%s", strings.ToUpper(signingRole), keySuffix)
	taskKey := fmt.Sprintf("%s_SIGNING_TASK_%s", strings.ToUpper(signingRole), keySuffix)
	if err := redisClient.Set(ctx, signingKey, string(rotateRaw), 0).Err(); err != nil {
		return taskID, fmt.Errorf("failed to save rotate metadata for signing: %w", err)
	}
	if err := redisClient.Set(ctx, taskKey, taskID, 0).Err(); err != nil {
		return taskID, fmt.Errorf("failed to save rotate signing task: %w", err)
	}
	taskName := tasks.TaskNameRotateKeys
	pendingMessage := fmt.Sprintf("Rotate metadata for %s is pending signatures", roleName)
	if err := tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStatePending, &tasks.TaskResult{
		Task:    &taskName,
		Message: &pendingMessage,
	}); err != nil {
		return taskID, fmt.Errorf("failed to save rotate signing task status: %w", err)
	}
	return taskID, nil
}

func saveRotateTaskFailure(redisClient *redis.Client, taskID string, taskName tasks.TaskName, err error) {
	status := false
	errMsg := err.Error()
	_ = tasks.SaveTaskStatus(redisClient, taskID, tasks.TaskStateFailure, &tasks.TaskResult{
		Task:   &taskName,
		Status: &status,
		Error:  &errMsg,
	})
}

type rotatePublishResult struct {
	RotateFilename       string
	RoleMetadataFilename string
	SnapshotFilename     string
}

func publishRotatedRoleMetadata(
	ctx context.Context,
	redisClient *redis.Client,
	adminName string,
	appName string,
	roleName string,
	rotateRaw json.RawMessage,
	roleMetadataRaw json.RawMessage,
	tmpDir string,
) (rotatePublishResult, error) {
	if err := validateTAP8RoleName(roleName); err != nil {
		return rotatePublishResult{}, err
	}
	if len(rotateRaw) == 0 {
		return rotatePublishResult{}, fmt.Errorf("rotate metadata is required")
	}
	if len(roleMetadataRaw) == 0 {
		return rotatePublishResult{}, fmt.Errorf("role metadata is required")
	}

	state, err := loadVerifiedRoleState(ctx, adminName, appName, roleName, tmpDir)
	if err != nil {
		return rotatePublishResult{}, err
	}
	logrus.Debugf(
		"Loaded TAP 8 trust state: admin=%s app=%s role=%s current_role_version=%d last_rotate_version=%d threshold=%d keyids=%v",
		adminName,
		appName,
		roleName,
		state.CurrentRoleVersion,
		state.LastRotateVersion,
		state.CurrentTrust.Threshold,
		state.CurrentTrust.KeyIDs,
	)

	expectedRotateVersion := state.LastRotateVersion + 1
	logrus.Debugf(
		"Verifying TAP 8 rotate metadata: admin=%s app=%s role=%s expected_rotate_version=%d",
		adminName,
		appName,
		roleName,
		expectedRotateVersion,
	)
	postRotationTrust, rotateMeta, err := verifyRotateMetadataBytes(rotateRaw, roleName, expectedRotateVersion, state.CurrentTrust)
	if err != nil {
		return rotatePublishResult{}, err
	}
	logrus.Debugf(
		"TAP 8 rotate metadata verified: admin=%s app=%s role=%s rotate_version=%d new_threshold=%d new_keyids=%v",
		adminName,
		appName,
		roleName,
		rotateMeta.Signed.Version,
		postRotationTrust.Threshold,
		postRotationTrust.KeyIDs,
	)

	roleMeta, err := parseTargetsMetadataBytes(roleMetadataRaw, filepath.Join(tmpDir, "rotated-role.json"))
	if err != nil {
		return rotatePublishResult{}, err
	}
	logrus.Debugf(
		"Loaded rotated role metadata: admin=%s app=%s role=%s metadata_version=%d expires=%s signatures=%d",
		adminName,
		appName,
		roleName,
		roleMeta.Signed.Version,
		roleMeta.Signed.Expires.UTC().Format(time.RFC3339),
		len(roleMeta.Signatures),
	)
	if roleMeta.Signed.Expires.IsZero() || !roleMeta.Signed.Expires.After(time.Now().UTC()) {
		return rotatePublishResult{}, fmt.Errorf("%s metadata is expired at %s", roleName, roleMeta.Signed.Expires.UTC().Format(time.RFC3339))
	}
	if roleMeta.Signed.Version != state.CurrentRoleVersion+1 {
		return rotatePublishResult{}, fmt.Errorf("expected %s metadata version %d, got %d", roleName, state.CurrentRoleVersion+1, roleMeta.Signed.Version)
	}
	logrus.Debugf(
		"Verifying rotated role metadata signatures: admin=%s app=%s role=%s metadata_version=%d expected_threshold=%d expected_keyids=%v",
		adminName,
		appName,
		roleName,
		roleMeta.Signed.Version,
		postRotationTrust.Threshold,
		postRotationTrust.KeyIDs,
	)
	if err := verifyRoleMetadataWithTrust(roleMetadataRaw, roleName, postRotationTrust); err != nil {
		return rotatePublishResult{}, fmt.Errorf("rotated %s metadata verification failed: %w", roleName, err)
	}
	logrus.Debugf(
		"Rotated role metadata verified: admin=%s app=%s role=%s metadata_version=%d",
		adminName,
		appName,
		roleName,
		roleMeta.Signed.Version,
	)

	rotateFilename := rotateFilename(roleName, rotateMeta.Signed.Version)
	rotatePath := filepath.Join(tmpDir, filepath.Base(rotateFilename))
	if err := os.WriteFile(rotatePath, rotateRaw, 0644); err != nil {
		return rotatePublishResult{}, fmt.Errorf("failed to write rotate metadata: %w", err)
	}

	roleFilename := targetsRoleFilename(roleName, roleMeta.Signed.Version)
	rolePath := filepath.Join(tmpDir, roleFilename)
	if err := os.WriteFile(rolePath, roleMetadataRaw, 0644); err != nil {
		return rotatePublishResult{}, fmt.Errorf("failed to write rotated role metadata: %w", err)
	}

	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, rotateFilename, rotatePath); err != nil {
		return rotatePublishResult{}, fmt.Errorf("failed to upload rotate metadata: %w", err)
	}
	logrus.Debugf("Uploaded TAP 8 rotate metadata: admin=%s app=%s role=%s filename=%s", adminName, appName, roleName, rotateFilename)
	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, roleFilename, rolePath); err != nil {
		return rotatePublishResult{}, fmt.Errorf("failed to upload rotated role metadata: %w", err)
	}
	logrus.Debugf("Uploaded rotated role metadata: admin=%s app=%s role=%s filename=%s", adminName, appName, roleName, roleFilename)

	snapshotFilename, err := updateSnapshotAndTimestampForRotation(ctx, redisClient, adminName, appName, roleName, roleMeta, rotateFilename, rotateRaw, tmpDir)
	if err != nil {
		return rotatePublishResult{}, err
	}

	return rotatePublishResult{
		RotateFilename:       rotateFilename,
		RoleMetadataFilename: roleFilename,
		SnapshotFilename:     snapshotFilename,
	}, nil
}

func validateTAP8RoleName(roleName string) error {
	if roleName == "" {
		return fmt.Errorf("role is required")
	}
	switch roleName {
	case "root", "snapshot", "timestamp":
		return fmt.Errorf("TAP 8 rotation is not supported for %s role", roleName)
	}
	if strings.Contains(roleName, "/") || strings.Contains(roleName, "\\") || roleName == "." || roleName == ".." {
		return fmt.Errorf("invalid role name %q", roleName)
	}
	return nil
}

func loadVerifiedRoleState(ctx context.Context, adminName, appName, roleName, tmpDir string) (verifiedRoleState, error) {
	now := time.Now().UTC()
	repo := repository.New()

	rootPath, err := downloadLatestMetadataToPath(ctx, adminName, appName, "root", tmpDir)
	if err != nil {
		return verifiedRoleState{}, err
	}
	root := gotufmetadata.Root(now.Add(365 * 24 * time.Hour))
	repo.SetRoot(root)
	if _, err := repo.Root().FromFile(rootPath); err != nil {
		return verifiedRoleState{}, fmt.Errorf("failed to load root metadata: %w", err)
	}
	if err := repo.Root().VerifyDelegate("root", repo.Root()); err != nil {
		return verifiedRoleState{}, fmt.Errorf("failed to verify root metadata: %w", err)
	}
	if !repo.Root().Signed.Expires.After(now) {
		return verifiedRoleState{}, fmt.Errorf("root metadata is expired at %s", repo.Root().Signed.Expires.UTC().Format(time.RFC3339))
	}

	targetsPath, err := downloadLatestMetadataToPath(ctx, adminName, appName, "targets", tmpDir)
	if err != nil {
		return verifiedRoleState{}, err
	}
	targets := gotufmetadata.Targets(now.Add(365 * 24 * time.Hour))
	repo.SetTargets("targets", targets)
	if _, err := repo.Targets("targets").FromFile(targetsPath); err != nil {
		return verifiedRoleState{}, fmt.Errorf("failed to load targets metadata: %w", err)
	}

	targetsTrust, err := roleTrustFromRoot(repo.Root(), "targets")
	if err != nil {
		return verifiedRoleState{}, err
	}
	targetsTrust, targetsLastRotateVersion, err := applyExistingRotateChain(ctx, adminName, appName, "targets", targetsTrust, tmpDir)
	if err != nil {
		return verifiedRoleState{}, err
	}
	targetsRaw, err := os.ReadFile(targetsPath)
	if err != nil {
		return verifiedRoleState{}, fmt.Errorf("failed to read targets metadata: %w", err)
	}
	if err := verifyRoleMetadataWithTrust(targetsRaw, "targets", targetsTrust); err != nil {
		return verifiedRoleState{}, fmt.Errorf("failed to verify targets metadata: %w", err)
	}
	if !repo.Targets("targets").Signed.Expires.After(now) {
		return verifiedRoleState{}, fmt.Errorf("targets metadata is expired at %s", repo.Targets("targets").Signed.Expires.UTC().Format(time.RFC3339))
	}

	if roleName == "targets" {
		return verifiedRoleState{
			Root:               repo.Root(),
			Targets:            repo.Targets("targets"),
			CurrentRole:        repo.Targets("targets"),
			CurrentTrust:       targetsTrust,
			LastRotateVersion:  targetsLastRotateVersion,
			CurrentRoleVersion: repo.Targets("targets").Signed.Version,
		}, nil
	}

	delegatedTrust, err := roleTrustFromTargets(repo.Targets("targets"), roleName)
	if err != nil {
		return verifiedRoleState{}, err
	}
	delegatedTrust, delegatedLastRotateVersion, err := applyExistingRotateChain(ctx, adminName, appName, roleName, delegatedTrust, tmpDir)
	if err != nil {
		return verifiedRoleState{}, err
	}

	delegatedPath, err := downloadLatestMetadataToPath(ctx, adminName, appName, roleName, tmpDir)
	if err != nil {
		return verifiedRoleState{}, err
	}
	delegated := gotufmetadata.Targets(now.Add(365 * 24 * time.Hour))
	repo.SetTargets(roleName, delegated)
	if _, err := repo.Targets(roleName).FromFile(delegatedPath); err != nil {
		return verifiedRoleState{}, fmt.Errorf("failed to load %s metadata: %w", roleName, err)
	}
	delegatedRaw, err := os.ReadFile(delegatedPath)
	if err != nil {
		return verifiedRoleState{}, fmt.Errorf("failed to read %s metadata: %w", roleName, err)
	}
	if err := verifyRoleMetadataWithTrust(delegatedRaw, roleName, delegatedTrust); err != nil {
		return verifiedRoleState{}, fmt.Errorf("failed to verify %s metadata: %w", roleName, err)
	}
	if !repo.Targets(roleName).Signed.Expires.After(now) {
		return verifiedRoleState{}, fmt.Errorf("%s metadata is expired at %s", roleName, repo.Targets(roleName).Signed.Expires.UTC().Format(time.RFC3339))
	}

	return verifiedRoleState{
		Root:               repo.Root(),
		Targets:            repo.Targets("targets"),
		CurrentRole:        repo.Targets(roleName),
		CurrentTrust:       delegatedTrust,
		LastRotateVersion:  delegatedLastRotateVersion,
		CurrentRoleVersion: repo.Targets(roleName).Signed.Version,
	}, nil
}

func downloadLatestMetadataToPath(ctx context.Context, adminName, appName, roleName, tmpDir string) (string, error) {
	_, filename, err := tuf_storage.FindLatestMetadataVersion(ctx, adminName, appName, roleName)
	if err != nil {
		return "", fmt.Errorf("failed to find latest %s metadata version: %w", roleName, err)
	}
	path := filepath.Join(tmpDir, strings.ReplaceAll(filename, "/", "_"))
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, filename, path); err != nil {
		return "", fmt.Errorf("failed to download %s metadata: %w", roleName, err)
	}
	return path, nil
}

func roleTrustFromRoot(root *gotufmetadata.Metadata[gotufmetadata.RootType], roleName string) (roleTrustState, error) {
	role, ok := root.Signed.Roles[roleName]
	if !ok {
		return roleTrustState{}, fmt.Errorf("role %s not found in root metadata", roleName)
	}
	return buildRoleTrust(roleName, root.Signed.Keys, role.KeyIDs, role.Threshold)
}

func roleTrustFromTargets(targets *gotufmetadata.Metadata[gotufmetadata.TargetsType], roleName string) (roleTrustState, error) {
	if targets.Signed.Delegations == nil {
		return roleTrustState{}, fmt.Errorf("targets metadata has no delegations")
	}
	for _, role := range targets.Signed.Delegations.Roles {
		if role.Name == roleName {
			return buildRoleTrust(roleName, targets.Signed.Delegations.Keys, role.KeyIDs, role.Threshold)
		}
	}
	return roleTrustState{}, fmt.Errorf("delegated role %s not found in targets metadata", roleName)
}

func buildRoleTrust(roleName string, keys map[string]*gotufmetadata.Key, keyIDs []string, threshold int) (roleTrustState, error) {
	if threshold < 1 {
		return roleTrustState{}, fmt.Errorf("invalid threshold %d for role %s", threshold, roleName)
	}
	if len(keyIDs) < threshold {
		return roleTrustState{}, fmt.Errorf("not enough keyids for role %s: need %d, got %d", roleName, threshold, len(keyIDs))
	}
	seen := make(map[string]bool, len(keyIDs))
	trustedKeys := make(map[string]*gotufmetadata.Key, len(keyIDs))
	for _, keyID := range keyIDs {
		if seen[keyID] {
			return roleTrustState{}, fmt.Errorf("duplicate keyid %s in role %s", keyID, roleName)
		}
		seen[keyID] = true
		key, ok := keys[keyID]
		if !ok {
			return roleTrustState{}, fmt.Errorf("key %s referenced by role %s not found", keyID, roleName)
		}
		computedKeyID, err := key.ID()
		if err != nil {
			return roleTrustState{}, fmt.Errorf("failed to compute keyid for role %s key %s: %w", roleName, keyID, err)
		}
		if computedKeyID != keyID {
			return roleTrustState{}, fmt.Errorf("keyid mismatch for role %s: provided %s, computed %s", roleName, keyID, computedKeyID)
		}
		trustedKeys[keyID] = key
	}
	return roleTrustState{Keys: trustedKeys, KeyIDs: append([]string(nil), keyIDs...), Threshold: threshold}, nil
}

func applyExistingRotateChain(
	ctx context.Context,
	adminName string,
	appName string,
	roleName string,
	initialTrust roleTrustState,
	tmpDir string,
) (roleTrustState, int, error) {
	rotateFiles, err := listRotateFiles(ctx, adminName, appName, roleName)
	if err != nil {
		return roleTrustState{}, 0, err
	}
	trust := initialTrust
	lastVersion := 0
	for _, file := range rotateFiles {
		expectedVersion := lastVersion + 1
		if file.Version != expectedVersion {
			return roleTrustState{}, 0, fmt.Errorf("rotate version gap for %s: expected %d, got %d", roleName, expectedVersion, file.Version)
		}
		path := filepath.Join(tmpDir, strings.ReplaceAll(file.Filename, "/", "_"))
		if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, file.Filename, path); err != nil {
			return roleTrustState{}, 0, fmt.Errorf("failed to download rotate metadata %s: %w", file.Filename, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return roleTrustState{}, 0, fmt.Errorf("failed to read rotate metadata %s: %w", file.Filename, err)
		}
		nextTrust, _, err := verifyRotateMetadataBytes(raw, roleName, expectedVersion, trust)
		if err != nil {
			return roleTrustState{}, 0, fmt.Errorf("failed to verify rotate metadata %s: %w", file.Filename, err)
		}
		trust = nextTrust
		lastVersion = file.Version
	}
	return trust, lastVersion, nil
}

type rotateFileRef struct {
	Filename string
	Version  int
}

func listRotateFiles(ctx context.Context, adminName, appName, roleName string) ([]rotateFileRef, error) {
	prefix := fmt.Sprintf("rotate/%s.rotate.", roleName)
	filenames, err := listMetadataForRotate(ctx, adminName, appName, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list rotate metadata for %s: %w", roleName, err)
	}
	refs := make([]rotateFileRef, 0, len(filenames))
	for _, filename := range filenames {
		if !strings.HasPrefix(filename, prefix) || !strings.HasSuffix(filename, ".json") {
			continue
		}
		versionPart := strings.TrimSuffix(strings.TrimPrefix(filename, prefix), ".json")
		version, err := strconv.Atoi(versionPart)
		if err != nil {
			return nil, fmt.Errorf("invalid rotate metadata filename %s", filename)
		}
		refs = append(refs, rotateFileRef{Filename: filename, Version: version})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Version < refs[j].Version })
	return refs, nil
}

func verifyRotateMetadataBytes(raw []byte, roleName string, expectedVersion int, currentTrust roleTrustState) (roleTrustState, rotateMetadata, error) {
	rotate, err := validateRotateMetadataShape(raw, roleName, expectedVersion)
	if err != nil {
		return roleTrustState{}, rotateMetadata{}, err
	}
	signedData, err := extractSignedSectionFromBytes(raw)
	if err != nil {
		return roleTrustState{}, rotateMetadata{}, err
	}
	if err := verifyThresholdSignatures(signedData, rotate.Signatures, currentTrust, roleName+" rotate"); err != nil {
		return roleTrustState{}, rotateMetadata{}, err
	}

	nextTrust := roleTrustState{Keys: rotate.Signed.Keys, KeyIDs: sortedKeyIDs(rotate.Signed.Keys), Threshold: rotate.Signed.Threshold}
	return nextTrust, rotate, nil
}

func validateRotateMetadataShape(raw []byte, roleName string, expectedVersion int) (rotateMetadata, error) {
	var rotate rotateMetadata
	if err := json.Unmarshal(raw, &rotate); err != nil {
		return rotateMetadata{}, fmt.Errorf("failed to parse rotate metadata: %w", err)
	}
	if rotate.Signed.Type != rotateMetadataType {
		return rotateMetadata{}, fmt.Errorf("expected rotate metadata type, got %q", rotate.Signed.Type)
	}
	if rotate.Signed.Role != roleName {
		return rotateMetadata{}, fmt.Errorf("rotate metadata role mismatch: expected %s, got %s", roleName, rotate.Signed.Role)
	}
	if rotate.Signed.Version != expectedVersion {
		return rotateMetadata{}, fmt.Errorf("expected rotate version %d, got %d", expectedVersion, rotate.Signed.Version)
	}
	if rotate.Signed.Threshold < 1 {
		return rotateMetadata{}, fmt.Errorf("rotate threshold must be at least 1")
	}
	if len(rotate.Signed.Keys) < rotate.Signed.Threshold {
		return rotateMetadata{}, fmt.Errorf("not enough rotate keys for threshold: need %d, got %d", rotate.Signed.Threshold, len(rotate.Signed.Keys))
	}
	keyIDs := make([]string, 0, len(rotate.Signed.Keys))
	for keyID, key := range rotate.Signed.Keys {
		computedKeyID, err := key.ID()
		if err != nil {
			return rotateMetadata{}, fmt.Errorf("failed to compute rotate keyid %s: %w", keyID, err)
		}
		if computedKeyID != keyID {
			return rotateMetadata{}, fmt.Errorf("keyid mismatch in rotate metadata: provided %s, computed %s", keyID, computedKeyID)
		}
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	return rotate, nil
}

func sortedKeyIDs(keys map[string]*gotufmetadata.Key) []string {
	keyIDs := make([]string, 0, len(keys))
	for keyID := range keys {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	return keyIDs
}

func verifyRoleMetadataWithTrust(raw []byte, roleName string, trust roleTrustState) error {
	signedData, err := extractSignedSectionFromBytes(raw)
	if err != nil {
		return err
	}
	metadataType, _ := signedData["_type"].(string)
	if metadataType != "targets" {
		return fmt.Errorf("expected targets metadata for role %s, got %q", roleName, metadataType)
	}
	signatures, err := extractSignaturesFromBytes(raw)
	if err != nil {
		return err
	}
	return verifyThresholdSignatures(signedData, signatures, trust, roleName)
}

func verifyThresholdSignatures(signedData map[string]interface{}, signatures []models.Signature, trust roleTrustState, roleName string) error {
	if trust.Threshold < 1 {
		return fmt.Errorf("invalid threshold %d for %s", trust.Threshold, roleName)
	}
	logrus.Debugf(
		"Starting threshold signature verification: role=%s threshold=%d trusted_keyids=%v signatures=%d signed_version=%v signed_type=%v",
		roleName,
		trust.Threshold,
		trust.KeyIDs,
		len(signatures),
		signedData["version"],
		signedData["_type"],
	)
	seenSignatureKeyIDs := make(map[string]bool, len(signatures))
	verified := make(map[string]bool, trust.Threshold)
	for _, sig := range signatures {
		if sig.KeyID == "" {
			return fmt.Errorf("signature with empty keyid for %s", roleName)
		}
		logrus.Debugf("Verifying signature keyid for role=%s keyid=%s", roleName, sig.KeyID)
		if seenSignatureKeyIDs[sig.KeyID] {
			return fmt.Errorf("duplicate signature keyid %s for %s", sig.KeyID, roleName)
		}
		seenSignatureKeyIDs[sig.KeyID] = true

		key, ok := trust.Keys[sig.KeyID]
		if !ok {
			return fmt.Errorf("signature keyid %s is not authorized for %s", sig.KeyID, roleName)
		}
		if err := verifySignatureOverSignedPayload(signedData, key, sig.Sig); err != nil {
			logrus.Debugf(
				"Signature verification failed: role=%s keyid=%s signed_type=%v signed_version=%v err=%v",
				roleName,
				sig.KeyID,
				signedData["_type"],
				signedData["version"],
				err,
			)
			return fmt.Errorf("invalid signature for %s with key %s: %w", roleName, sig.KeyID, err)
		}
		verified[sig.KeyID] = true
		logrus.Debugf("Signature verified: role=%s keyid=%s verified_count=%d threshold=%d", roleName, sig.KeyID, len(verified), trust.Threshold)
	}
	if len(verified) < trust.Threshold {
		return fmt.Errorf("threshold not reached for %s: got %d, want %d", roleName, len(verified), trust.Threshold)
	}
	logrus.Debugf("Threshold signature verification succeeded: role=%s verified=%d threshold=%d", roleName, len(verified), trust.Threshold)
	return nil
}

func extractSignedSectionFromBytes(raw []byte) (map[string]interface{}, error) {
	var metadataJSON map[string]interface{}
	if err := json.Unmarshal(raw, &metadataJSON); err != nil {
		return nil, fmt.Errorf("failed to parse metadata JSON: %w", err)
	}
	return extractSignedSection(metadataJSON)
}

func extractSignaturesFromBytes(raw []byte) ([]models.Signature, error) {
	var envelope struct {
		Signatures []models.Signature `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse metadata signatures: %w", err)
	}
	return envelope.Signatures, nil
}

func parseTargetsMetadataBytes(raw []byte, path string) (*gotufmetadata.Metadata[gotufmetadata.TargetsType], error) {
	if err := os.WriteFile(path, raw, 0644); err != nil {
		return nil, fmt.Errorf("failed to write targets metadata: %w", err)
	}
	targets := gotufmetadata.Targets(time.Now().Add(365 * 24 * time.Hour))
	if _, err := targets.FromFile(path); err != nil {
		return nil, fmt.Errorf("failed to load targets metadata: %w", err)
	}
	return targets, nil
}

func updateSnapshotAndTimestampForRotation(
	ctx context.Context,
	redisClient *redis.Client,
	adminName string,
	appName string,
	roleName string,
	roleMeta *gotufmetadata.Metadata[gotufmetadata.TargetsType],
	rotateFilename string,
	rotateRaw []byte,
	tmpDir string,
) (string, error) {
	keySuffix := adminName + "_" + appName

	rootPath, err := downloadLatestMetadataToPath(ctx, adminName, appName, "root", tmpDir)
	if err != nil {
		return "", err
	}
	var rootMetadata models.RootMetadata
	rootData, err := os.ReadFile(rootPath)
	if err != nil {
		return "", fmt.Errorf("failed to read root metadata: %w", err)
	}
	if err := json.Unmarshal(rootData, &rootMetadata); err != nil {
		return "", fmt.Errorf("failed to parse root metadata: %w", err)
	}

	snapshotRole, ok := rootMetadata.Signed.Roles["snapshot"]
	if !ok || len(snapshotRole.KeyIDs) == 0 {
		return "", fmt.Errorf("snapshot role not found in root metadata")
	}
	snapshotSigners, err := buildOnlineRoleSigners(snapshotRole.KeyIDs, snapshotRole.Threshold, "snapshot")
	if err != nil {
		return "", fmt.Errorf("failed to build snapshot signers: %w", err)
	}
	timestampRole, ok := rootMetadata.Signed.Roles["timestamp"]
	if !ok || len(timestampRole.KeyIDs) == 0 {
		return "", fmt.Errorf("timestamp role not found in root metadata")
	}
	timestampSigners, err := buildOnlineRoleSigners(timestampRole.KeyIDs, timestampRole.Threshold, "timestamp")
	if err != nil {
		return "", fmt.Errorf("failed to build timestamp signers: %w", err)
	}

	snapshotPath, err := downloadLatestMetadataToPath(ctx, adminName, appName, "snapshot", tmpDir)
	if err != nil {
		return "", err
	}
	snapshotExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "SNAPSHOT_EXPIRATION_"+keySuffix, 7)
	snapshot := gotufmetadata.Snapshot(tuf_utils.HelperExpireIn(snapshotExpiration))
	if _, err := snapshot.FromFile(snapshotPath); err != nil {
		return "", fmt.Errorf("failed to load snapshot metadata: %w", err)
	}
	if !snapshot.Signed.Expires.After(time.Now().UTC()) {
		return "", fmt.Errorf("snapshot metadata is expired at %s", snapshot.Signed.Expires.UTC().Format(time.RFC3339))
	}
	if snapshot.Signed.Meta == nil {
		snapshot.Signed.Meta = make(map[string]*gotufmetadata.MetaFiles)
	}
	snapshot.Signed.Meta[fmt.Sprintf("%s.json", roleName)] = gotufmetadata.MetaFile(roleMeta.Signed.Version)
	snapshot.Signed.Meta[rotateFilename] = metaFileForBytes(int64(extractRotateVersionFromFilename(rotateFilename)), rotateRaw)
	snapshot.Signed.Version++
	snapshot.Signed.Expires = tuf_utils.HelperExpireIn(snapshotExpiration)
	snapshot.ClearSignatures()
	for i, signer := range snapshotSigners {
		if _, err := snapshot.Sign(signer); err != nil {
			return "", fmt.Errorf("failed to sign snapshot metadata with key %d: %w", i+1, err)
		}
	}
	newSnapshotFilename := fmt.Sprintf("%d.snapshot.json", snapshot.Signed.Version)
	newSnapshotPath := filepath.Join(tmpDir, newSnapshotFilename)
	if err := snapshot.ToFile(newSnapshotPath, true); err != nil {
		return "", fmt.Errorf("failed to save snapshot metadata: %w", err)
	}
	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, newSnapshotFilename, newSnapshotPath); err != nil {
		return "", fmt.Errorf("failed to upload snapshot metadata: %w", err)
	}

	timestampPath := filepath.Join(tmpDir, "timestamp.json")
	loadedTimestamp := false
	if err := tuf_storage.DownloadMetadataFromS3(ctx, adminName, appName, "timestamp.json", timestampPath); err == nil {
		loadedTimestamp = true
	}
	timestampExpiration := tuf_utils.GetExpirationFromRedis(redisClient, ctx, "TIMESTAMP_EXPIRATION_"+keySuffix, 1)
	timestamp := gotufmetadata.Timestamp(tuf_utils.HelperExpireIn(timestampExpiration))
	if loadedTimestamp {
		if _, err := timestamp.FromFile(timestampPath); err != nil {
			return "", fmt.Errorf("failed to load timestamp metadata: %w", err)
		}
		if !timestamp.Signed.Expires.After(time.Now().UTC()) {
			return "", fmt.Errorf("timestamp metadata is expired at %s", timestamp.Signed.Expires.UTC().Format(time.RFC3339))
		}
	}
	if timestamp.Signed.Meta == nil {
		timestamp.Signed.Meta = make(map[string]*gotufmetadata.MetaFiles)
	}
	timestamp.Signed.Meta["snapshot.json"] = gotufmetadata.MetaFile(snapshot.Signed.Version)
	if loadedTimestamp {
		timestamp.Signed.Version++
	}
	timestamp.Signed.Expires = tuf_utils.HelperExpireIn(timestampExpiration)
	timestamp.ClearSignatures()
	for i, signer := range timestampSigners {
		if _, err := timestamp.Sign(signer); err != nil {
			return "", fmt.Errorf("failed to sign timestamp metadata with key %d: %w", i+1, err)
		}
	}
	if err := timestamp.ToFile(timestampPath, true); err != nil {
		return "", fmt.Errorf("failed to save timestamp metadata: %w", err)
	}
	if err := tuf_storage.UploadMetadataToS3(ctx, adminName, appName, "timestamp.json", timestampPath); err != nil {
		return "", fmt.Errorf("failed to upload timestamp metadata: %w", err)
	}

	return newSnapshotFilename, nil
}

func metaFileForBytes(version int64, data []byte) *gotufmetadata.MetaFiles {
	hash := sha256.Sum256(data)
	meta := gotufmetadata.MetaFile(version)
	meta.Length = int64(len(data))
	meta.Hashes = gotufmetadata.Hashes{"sha256": hash[:]}
	return meta
}

func extractRotateVersionFromFilename(filename string) int {
	name := strings.TrimSuffix(filepath.Base(filename), ".json")
	idx := strings.LastIndex(name, ".")
	if idx == -1 {
		return 1
	}
	version, err := strconv.Atoi(name[idx+1:])
	if err != nil {
		return 1
	}
	return version
}

func rotateFilename(roleName string, version int) string {
	return fmt.Sprintf("rotate/%s.rotate.%d.json", roleName, version)
}

func targetsRoleFilename(roleName string, version int64) string {
	return fmt.Sprintf("%d.%s.json", version, roleName)
}

func rotateSigningRoleName(roleName string) string {
	return "rotate_" + roleName
}

func roleNameFromRotateSigningRole(roleName string) (string, bool) {
	return strings.CutPrefix(roleName, "rotate_")
}
