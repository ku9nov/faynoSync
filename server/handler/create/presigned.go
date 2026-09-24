package create

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"faynoSync/server/utils/storage"
	"faynoSync/server/utils/updaters"
	"faynoSync/server/utils/updaters/sparkle"
	"faynoSync/server/utils/updaters/velopack"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	pendingUploadsCollection = "pending_uploads"
	defaultPresignedPutTTL   = 30 * time.Minute
	// The SigV4 limit for S3-compatible storage, applied to every driver so the setting means the same everywhere.
	maxPresignedPutTTL = 7 * 24 * time.Hour
	// The pending record outlives the PUT URLs so a transfer that started just before they expire can still complete.
	pendingUploadGrace    = 90 * time.Minute
	maxPresignedFileSize  = 5 << 30
	maxInlineFeedFileSize = 10 << 20

	pendingStatePending    = "pending"
	pendingStateCompleting = "completing"
)

type presignedFileManifest struct {
	Name   string `json:"name"`
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
	Length int64  `json:"length"`
}

type pendingFile struct {
	Name         string `bson:"name"`
	PendingKey   string `bson:"pending_key"`
	Key          string `bson:"key"`
	Extension    string `bson:"extension"`
	ContentType  string `bson:"content_type"`
	DownloadLink string `bson:"download_link"`
	// Inline files were received and hashed by faynoSync at init; the rest were PUT by the client.
	Inline bool              `bson:"is_inline"`
	MD5    string            `bson:"md5,omitempty"`
	Hashes map[string]string `bson:"hashes"`
	Length int64             `bson:"length"`
}

// pendingUpload holds everything complete needs, so complete takes no parameters from
// the client besides the upload id.
type pendingUpload struct {
	ID           string        `bson:"_id"`
	Username     string        `bson:"username"`
	Owner        string        `bson:"owner"`
	AppName      string        `bson:"app_name"`
	Data         string        `bson:"data"`
	Intermediate string        `bson:"intermediate,omitempty"`
	Private      bool          `bson:"private"`
	Bucket       string        `bson:"bucket"`
	Public       bool          `bson:"public"`
	Files        []pendingFile `bson:"files"`
	State        string        `bson:"state"`
	CreatedAt    time.Time     `bson:"created_at"`
	ExpiresAt    time.Time     `bson:"expires_at"`
}

type presignedFileResponse struct {
	Name    string            `json:"name"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

var newPresignedStorage = func(env *viper.Viper) (utils.StorageClient, storage.PresignedUploader, error) {
	client, err := utils.NewStorageFactory(env).CreateStorageClient()
	if err != nil {
		return nil, nil, err
	}
	uploader, ok := client.(storage.PresignedUploader)
	if !ok {
		return nil, nil, errPresignedUnsupported
	}
	return client, uploader, nil
}

var errPresignedUnsupported = errors.New("presigned uploads are not supported by the configured storage driver")

func presignedStorage(c *gin.Context, env *viper.Viper) (utils.StorageClient, storage.PresignedUploader, bool) {
	client, uploader, err := newPresignedStorage(env)
	if errors.Is(err, errPresignedUnsupported) {
		c.JSON(http.StatusNotImplemented, gin.H{"error": err.Error()})
		return nil, nil, false
	}
	if err != nil {
		logrus.Errorf("failed to create storage client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create storage client"})
		return nil, nil, false
	}
	return client, uploader, true
}

func isLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// parsePresignedManifest validates the files the client will PUT. Only md5 is required:
// storage binds the bytes to it. sha256/sha512 are only syntax-checked and are needed
// solely by TUF, which verifies them against the stored bytes before signing; without
// them the artifact cannot be signed. A missing length is taken from storage at complete.
func parsePresignedManifest(raw string) ([]presignedFileManifest, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("files manifest is required")
	}
	var manifest []presignedFileManifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		return nil, errors.New("invalid files manifest")
	}
	if len(manifest) == 0 {
		return nil, errors.New("files manifest is empty")
	}

	seen := make(map[string]struct{}, len(manifest))
	for i := range manifest {
		file := &manifest[i]
		if file.Name == "" || file.Name != path.Base(file.Name) || strings.ContainsAny(file.Name, `\`) || file.Name == "." || file.Name == ".." {
			return nil, fmt.Errorf("invalid file name %q", file.Name)
		}
		if _, dup := seen[file.Name]; dup {
			return nil, fmt.Errorf("duplicate file name %q", file.Name)
		}
		seen[file.Name] = struct{}{}

		file.MD5 = strings.ToLower(file.MD5)
		file.SHA256 = strings.ToLower(file.SHA256)
		file.SHA512 = strings.ToLower(file.SHA512)
		if !isLowerHex(file.MD5, 32) {
			return nil, fmt.Errorf("file %q: md5 must be a hex digest", file.Name)
		}
		if file.SHA256 != "" && !isLowerHex(file.SHA256, 64) {
			return nil, fmt.Errorf("file %q: sha256 must be a hex digest", file.Name)
		}
		if file.SHA512 != "" && !isLowerHex(file.SHA512, 128) {
			return nil, fmt.Errorf("file %q: sha512 must be a hex digest", file.Name)
		}
		if file.Length < 0 || file.Length > maxPresignedFileSize {
			return nil, fmt.Errorf("file %q: length must be between 0 (not declared) and %d bytes", file.Name, int64(maxPresignedFileSize))
		}
	}
	return manifest, nil
}

func declaredHashes(file presignedFileManifest) map[string]string {
	hashes := map[string]string{}
	if file.SHA256 != "" {
		hashes["sha256"] = file.SHA256
	}
	if file.SHA512 != "" {
		hashes["sha512"] = file.SHA512
	}
	return hashes
}

func newUploadID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

const artifactExistsMessage = "app with this name, version, platform, architecture and extension already exists"

// findArtifactConflict mirrors the checks repository.Upload applies to an existing
// version (immutable channel, duplicate artifact), so a conflict is reported before the
// client transfers anything. It returns the conflict message, or "" when there is none.
func findArtifactConflict(ctx context.Context, database *mongo.Database, owner string, params map[string]interface{}, extensions []string) (string, error) {
	metaCollection := database.Collection("apps_meta")
	var appMeta, platformMeta, archMeta, channelMeta struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	lookups := []struct {
		filter bson.D
		target *struct {
			ID primitive.ObjectID `bson:"_id"`
		}
	}{
		{bson.D{{Key: "app_name", Value: params["app_name"]}, {Key: "owner", Value: owner}}, &appMeta},
		{bson.D{{Key: "platform_name", Value: params["platform"]}, {Key: "owner", Value: owner}}, &platformMeta},
		{bson.D{{Key: "arch_id", Value: params["arch"]}, {Key: "owner", Value: owner}}, &archMeta},
	}
	if channel, _ := params["channel"].(string); channel != "" {
		lookups = append(lookups, struct {
			filter bson.D
			target *struct {
				ID primitive.ObjectID `bson:"_id"`
			}
		}{bson.D{{Key: "channel_name", Value: channel}, {Key: "owner", Value: owner}}, &channelMeta})
	}
	for _, lookup := range lookups {
		if err := metaCollection.FindOne(ctx, lookup.filter).Decode(lookup.target); err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				return "", nil
			}
			return "", err
		}
	}

	var existing model.SpecificApp
	err := database.Collection("apps").FindOne(ctx, bson.D{
		{Key: "app_id", Value: appMeta.ID},
		{Key: "version", Value: params["version"]},
		{Key: "owner", Value: owner},
	}).Decode(&existing)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	if channelMeta.ID != existing.ChannelID {
		return db.ErrVersionChannelMismatch.Error(), nil
	}

	for _, extension := range extensions {
		if db.IsDuplicateCheckIgnored(extension) {
			continue
		}
		for _, artifact := range existing.Artifacts {
			if artifact.Package == extension && artifact.Platform == platformMeta.ID && artifact.Arch == archMeta.ID {
				return artifactExistsMessage, nil
			}
		}
	}
	return "", nil
}

// InitPresignedUpload validates an upload up front and returns presigned PUT URLs into a
// staging prefix. Feed files are small and their content is needed for validation, so
// they are sent inline and stored by faynoSync itself.
func presignedPutTTL(env *viper.Viper) time.Duration {
	rawTTL := strings.TrimSpace(env.GetString("PRESIGNED_UPLOAD_URL_TTL"))
	if rawTTL == "" {
		return defaultPresignedPutTTL
	}

	ttl, err := time.ParseDuration(rawTTL)
	if err != nil || ttl <= 0 || ttl > maxPresignedPutTTL {
		logrus.Warnf("Invalid PRESIGNED_UPLOAD_URL_TTL value %q (must be a duration up to %s), falling back to %s", rawTTL, maxPresignedPutTTL, defaultPresignedPutTTL)
		return defaultPresignedPutTTL
	}

	return ttl
}

func InitPresignedUpload(c *gin.Context, database *mongo.Database) {
	env := viper.GetViper()
	putTTL := presignedPutTTL(env)
	storageClient, uploader, ok := presignedStorage(c, env)
	if !ok {
		return
	}

	uploadRequest, ok := ResolveUploadRequest(c, database)
	if !ok {
		return
	}
	owner, appName, ctxQueryMap := uploadRequest.Owner, uploadRequest.AppName, uploadRequest.Params
	username, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	manifest, err := parsePresignedManifest(c.PostForm("files"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var inlineFiles []*multipart.FileHeader
	if form, err := c.MultipartForm(); err == nil {
		inlineFiles = form.File["file"]
	} else if !errors.Is(err, http.ErrNotMultipart) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid multipart form"})
		return
	}

	updaterType, _ := ctxQueryMap["updater"].(string)
	fileNames := FileNames(inlineFiles)
	for _, file := range inlineFiles {
		if !updaters.IsFeedFile(file.Filename, updaterType) {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("file %q: only updater feed files are sent inline, list it in the files manifest", file.Filename)})
			return
		}
		if file.Size > maxInlineFeedFileSize {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("feed file %q is larger than %d bytes", file.Filename, maxInlineFeedFileSize)})
			return
		}
	}
	for _, file := range manifest {
		if updaters.IsFeedFile(file.Name, updaterType) {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("feed file %q must be sent inline, not presigned", file.Name)})
			return
		}
		fileNames = append(fileNames, file.Name)
	}

	if err := ValidateUpdaterUpload(ctxQueryMap, updaterType, fileNames, inlineFiles); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	checkAppVisibility, ok := ResolveAppVisibility(c, database, appName, owner, ctxQueryMap)
	if !ok {
		return
	}

	uploadID, err := newUploadID()
	if err != nil {
		logrus.Errorf("failed to generate upload id: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start upload"})
		return
	}

	placements := make([]utils.ObjectPlacement, 0, len(fileNames))
	keys := make(map[string]string, len(fileNames))
	extensions := make(map[string]string, len(fileNames))
	for _, name := range fileNames {
		placement := utils.BuildObjectPlacement(ctxQueryMap, owner, name, env, checkAppVisibility)
		if other, dup := keys[placement.Key]; dup {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("files %q and %q would be stored under the same key", other, name)})
			return
		}
		keys[placement.Key] = name
		if !db.IsDuplicateCheckIgnored(placement.Extension) {
			if other, dup := extensions[placement.Extension]; dup {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("files %q and %q have the same extension", other, name)})
				return
			}
			extensions[placement.Extension] = name
		}
		placements = append(placements, placement)
	}

	extensionList := make([]string, 0, len(placements))
	for _, placement := range placements {
		extensionList = append(extensionList, placement.Extension)
	}
	conflict, err := findArtifactConflict(c.Request.Context(), database, owner, ctxQueryMap, extensionList)
	if err != nil {
		logrus.Errorf("failed to check artifact conflicts: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check existing artifacts"})
		return
	}
	if conflict != "" {
		c.JSON(http.StatusConflict, gin.H{"error": conflict})
		return
	}

	bucket := placements[0].Bucket
	pending := pendingUpload{
		ID:           uploadID,
		Username:     username,
		Owner:        owner,
		AppName:      appName,
		Data:         c.PostForm("data"),
		Intermediate: c.PostForm("intermediate"),
		Private:      checkAppVisibility,
		Bucket:       bucket,
		Public:       placements[0].Public,
		State:        pendingStatePending,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(putTTL + pendingUploadGrace),
	}

	for i, file := range inlineFiles {
		placement := placements[i]
		pendingKey := fmt.Sprintf("pending/%s/%d", uploadID, i)
		hashes, length, err := utils.CalculateFileHashes(file)
		if err != nil {
			logrus.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to calculate file hashes"})
			return
		}
		reader, err := file.Open()
		if err != nil {
			logrus.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open file for reading"})
			return
		}
		err = storageClient.UploadObject(c.Request.Context(), bucket, pendingKey, reader, placement.ContentType)
		reader.Close()
		if err != nil {
			logrus.Errorf("failed to stage feed file %s: %v", file.Filename, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file to storage"})
			return
		}
		pending.Files = append(pending.Files, pendingFile{
			Name:         file.Filename,
			PendingKey:   pendingKey,
			Key:          placement.Key,
			Extension:    placement.Extension,
			ContentType:  placement.ContentType,
			DownloadLink: placement.DownloadLink,
			Inline:       true,
			Hashes:       hashes,
			Length:       length,
		})
	}

	response := make([]presignedFileResponse, 0, len(manifest))
	for i, file := range manifest {
		index := len(inlineFiles) + i
		placement := placements[index]
		pendingKey := fmt.Sprintf("pending/%s/%d", uploadID, index)
		contentMD5, _ := hex.DecodeString(file.MD5)
		signed, err := uploader.PresignPutObject(c.Request.Context(), bucket, pendingKey, contentMD5, file.Length, placement.ContentType, putTTL)
		if err != nil {
			logrus.Errorf("failed to presign upload for %s: %v", file.Name, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to presign upload"})
			return
		}

		headers := make(map[string]string, len(signed.Headers))
		for name := range signed.Headers {
			headers[name] = signed.Headers.Get(name)
		}
		response = append(response, presignedFileResponse{Name: file.Name, Method: http.MethodPut, URL: signed.URL, Headers: headers})
		pending.Files = append(pending.Files, pendingFile{
			Name:         file.Name,
			PendingKey:   pendingKey,
			Key:          placement.Key,
			Extension:    placement.Extension,
			ContentType:  placement.ContentType,
			DownloadLink: placement.DownloadLink,
			MD5:          file.MD5,
			Hashes:       declaredHashes(file),
			Length:       file.Length,
		})
	}

	if _, err := database.Collection(pendingUploadsCollection).InsertOne(c.Request.Context(), pending); err != nil {
		logrus.Errorf("failed to store pending upload: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start upload"})
		return
	}

	logrus.Debugf("Presigned upload %s started: owner=%s app=%s files=%d", uploadID, owner, appName, len(pending.Files))
	c.JSON(http.StatusOK, gin.H{
		"upload_id":  uploadID,
		"expires_at": time.Now().Add(putTTL),
		"files":      response,
	})
}

type completePresignedPayload struct {
	UploadID string `json:"upload_id" binding:"required"`
}

// verifyPresignedFile confirms from storage that the client uploaded exactly the bytes it
// declared at init and returns the stored size. Only size and MD5 are available on every
// provider; sha256/sha512 are verified against the stored bytes by TUF publish before
// they are signed.
func verifyPresignedFile(ctx context.Context, uploader storage.PresignedUploader, bucket string, file pendingFile) (int64, error) {
	stat, err := uploader.StatObject(ctx, bucket, file.PendingKey)
	if errors.Is(err, storage.ErrObjectNotFound) {
		return 0, errors.New("not uploaded")
	}
	if err != nil {
		return 0, err
	}
	if file.Length > 0 && stat.Size != file.Length {
		return 0, fmt.Errorf("stored %d bytes, declared %d", stat.Size, file.Length)
	}
	if stat.MD5 == "" {
		return 0, errors.New("storage returned no MD5 for the object")
	}
	if stat.MD5 != file.MD5 {
		return 0, errors.New("stored bytes do not match the declared MD5")
	}
	return stat.Size, nil
}

func readInlineFeed(ctx context.Context, uploader storage.PresignedUploader, bucket, key string) ([]byte, error) {
	body, err := uploader.OpenObject(ctx, bucket, key)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(io.LimitReader(body, maxInlineFeedFileSize))
}

func ingestInlineFeeds(ctx context.Context, uploader storage.PresignedUploader, pending pendingUpload, ctxQueryMap map[string]interface{}, updaterType string) error {
	for _, file := range pending.Files {
		if !file.Inline {
			continue
		}
		switch {
		case updaterType == velopack.UpdaterType && isVelopackFeedName(file.Name):
			content, err := readInlineFeed(ctx, uploader, pending.Bucket, file.PendingKey)
			if err != nil {
				return err
			}
			meta, err := velopack.ParseFeed(content)
			if err != nil {
				return err
			}
			ctxQueryMap["velopack_meta"] = meta
		case updaterType == sparkle.UpdaterType && isSparkleAppcastName(file.Name):
			content, err := readInlineFeed(ctx, uploader, pending.Bucket, file.PendingKey)
			if err != nil {
				return err
			}
			meta, err := sparkle.ParseAppcast(content)
			if err != nil {
				return err
			}
			ctxQueryMap["sparkle_meta"] = meta
		}
	}
	return nil
}

// CompletePresignedUpload checks the staged objects against what init recorded, moves
// them to their final keys and creates the version exactly as a multipart upload would.
func CompletePresignedUpload(c *gin.Context, repository db.AppRepository, database *mongo.Database, rdb *redis.Client, performanceMode bool) {
	env := viper.GetViper()
	storageClient, uploader, ok := presignedStorage(c, env)
	if !ok {
		return
	}

	username, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var payload completePresignedPayload
	if err := c.ShouldBindJSON(&payload); err != nil || !isLowerHex(payload.UploadID, 32) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "upload_id is required"})
		return
	}

	ctx := c.Request.Context()
	collection := database.Collection(pendingUploadsCollection)
	var pending pendingUpload
	// Claiming the upload makes concurrent or repeated completes fail instead of creating the version twice.
	err = collection.FindOneAndUpdate(ctx,
		bson.M{"_id": payload.UploadID, "username": username, "state": pendingStatePending, "expires_at": bson.M{"$gt": time.Now()}},
		bson.M{"$set": bson.M{"state": pendingStateCompleting}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&pending)
	if errors.Is(err, mongo.ErrNoDocuments) {
		c.JSON(http.StatusNotFound, gin.H{"error": "upload not found, expired or already completed"})
		return
	}
	if err != nil {
		logrus.Errorf("failed to claim pending upload %s: %v", payload.UploadID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load upload"})
		return
	}

	// Until the version is written, a failed complete can be retried, e.g. after re-sending a PUT.
	release := func() {
		if _, err := collection.UpdateOne(context.Background(), bson.M{"_id": pending.ID}, bson.M{"$set": bson.M{"state": pendingStatePending}}); err != nil {
			logrus.Errorf("failed to release pending upload %s: %v", pending.ID, err)
		}
	}

	ctxQueryMap, err := utils.ParseUploadData(pending.Data)
	if err != nil {
		release()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if pending.Intermediate != "" {
		ctxQueryMap["intermediate"] = pending.Intermediate
	}
	if err := validateAPITokenAppScope(c, database, pending.Owner, pending.AppName); err != nil {
		release()
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	if err := utils.EnsureTeamUserUploadAccess(ctx, username, ctxQueryMap, database); err != nil {
		logrus.Error(err)
		release()
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	checkAppVisibility, ok := ResolveAppVisibility(c, database, pending.AppName, pending.Owner, ctxQueryMap)
	if !ok {
		release()
		return
	}
	if checkAppVisibility != pending.Private {
		release()
		c.JSON(http.StatusConflict, gin.H{"error": "app visibility changed since the upload started, start a new upload"})
		return
	}

	var failures []string
	for i, file := range pending.Files {
		if file.Inline {
			continue
		}
		size, err := verifyPresignedFile(ctx, uploader, pending.Bucket, file)
		if err != nil {
			logrus.Errorf("Presigned upload %s: file %s failed verification: %v", pending.ID, file.Name, err)
			failures = append(failures, fmt.Sprintf("%s: %v", file.Name, err))
			continue
		}
		// The length stored with the artifact always comes from storage, declared or not.
		pending.Files[i].Length = size
	}
	if len(failures) > 0 {
		release()
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "uploaded files do not match the upload manifest", "files": failures})
		return
	}

	updaterType, _ := ctxQueryMap["updater"].(string)
	if err := ingestInlineFeeds(ctx, uploader, pending, ctxQueryMap, updaterType); err != nil {
		logrus.Errorf("Presigned upload %s: failed to read feed: %v", pending.ID, err)
		release()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read feed file"})
		return
	}

	// Final keys are deterministic, so a version uploaded since init must be caught before its objects are overwritten.
	extensionList := make([]string, 0, len(pending.Files))
	for _, file := range pending.Files {
		extensionList = append(extensionList, file.Extension)
	}
	conflict, err := findArtifactConflict(ctx, database, pending.Owner, ctxQueryMap, extensionList)
	if err != nil {
		logrus.Errorf("Presigned upload %s: failed to check artifact conflicts: %v", pending.ID, err)
		release()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check existing artifacts"})
		return
	}
	if conflict != "" {
		release()
		c.JSON(http.StatusConflict, gin.H{"error": conflict})
		return
	}

	for _, file := range pending.Files {
		if err := storageClient.CopyObject(ctx, pending.Bucket, file.PendingKey, file.Key, pending.Public); err != nil {
			logrus.Errorf("Presigned upload %s: failed to move %s to %s: %v", pending.ID, file.PendingKey, file.Key, err)
			release()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file to S3"})
			return
		}
	}

	fileNames := make([]string, 0, len(pending.Files))
	var results []interface{}
	for _, file := range pending.Files {
		fileNames = append(fileNames, file.Name)
		link := file.DownloadLink
		if pending.Public {
			link = uploader.PublicObjectURL(pending.Bucket, file.Key)
		}

		fileCtxQuery := make(map[string]interface{})
		for k, v := range ctxQueryMap {
			fileCtxQuery[k] = v
		}
		fileCtxQuery["hashes"] = file.Hashes
		fileCtxQuery["length"] = file.Length
		// Client-declared hashes stay unverified until TUF publish checks them against storage.
		fileCtxQuery["hashes_verified"] = file.Inline
		fileCtxQuery["is_feed"] = updaters.IsFeedFile(file.Name, updaterType)
		if _, ok := ctxQueryMap["velopack_meta"]; ok {
			fileCtxQuery["file_name"] = file.Name
		}
		if _, ok := ctxQueryMap["sparkle_meta"]; ok {
			fileCtxQuery["file_name"] = file.Name
		}

		result, err := repository.Upload(fileCtxQuery, link, file.Extension, username, ctx, rdb, env, checkAppVisibility)
		if err != nil {
			logrus.Error(err)
			if len(results) == 0 {
				release()
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, result)
	}

	FinalizeUpload(ctx, database, rdb, performanceMode, ctxQueryMap, pending.Owner, pending.AppName, fileNames, checkAppVisibility, env)

	pendingKeys := make([]string, 0, len(pending.Files))
	for _, file := range pending.Files {
		pendingKeys = append(pendingKeys, file.PendingKey)
	}
	if err := storageClient.DeleteObjects(ctx, pending.Bucket, pendingKeys); err != nil {
		logrus.Errorf("Presigned upload %s: failed to delete staged objects: %v", pending.ID, err)
	}
	if _, err := collection.DeleteOne(ctx, bson.M{"_id": pending.ID}); err != nil {
		logrus.Errorf("Presigned upload %s: failed to delete pending record: %v", pending.ID, err)
	}

	if len(results) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no results found. Please check your files."})
		return
	}
	if appData, ok := results[0].(model.SpecificApp); ok {
		c.JSON(http.StatusOK, gin.H{"uploadResult.Uploaded": appData.ID.Hex()})
		NotifySlackForApp(repository, appData.ID, pending.Owner, rdb, env)
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid result type"})
	}
}
