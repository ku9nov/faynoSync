package storage

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"testing"
	"time"

	"faynoSync/server/utils"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStorageClient records UploadPublicObject, DownloadObject, and ListObjects arguments and optionally returns an error.
type mockStorageClient struct {
	uploadCalls       []uploadCall
	uploadErr         error
	downloadCalls     []downloadCall
	downloadErr       error
	downloadBody      []byte // content written to filePath on successful download
	listObjectsCalls  []listCall
	listObjectsResult []string
	listObjectsErr    error
}

type listCall struct {
	Bucket string
	Prefix string
}

type uploadCall struct {
	Bucket      string
	ObjectKey   string
	ContentType string
	Body        []byte
}

type downloadCall struct {
	Bucket    string
	ObjectKey string
	FilePath  string
}

func (m *mockStorageClient) UploadPublicObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) (string, error) {
	var body []byte
	if fileReader != nil {
		var err error
		body, err = io.ReadAll(fileReader)
		if err != nil {
			return "", err
		}
	}
	m.uploadCalls = append(m.uploadCalls, uploadCall{
		Bucket:      bucketName,
		ObjectKey:   objectKey,
		ContentType: contentType,
		Body:        body,
	})
	if m.uploadErr != nil {
		return "", m.uploadErr
	}
	return "https://example.com/" + bucketName + "/" + objectKey, nil
}

func (m *mockStorageClient) UploadObject(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType string) error {
	panic("not used in tests")
}

func (m *mockStorageClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	panic("not used in tests")
}

func (m *mockStorageClient) GeneratePresignedURL(ctx context.Context, bucketName, objectKey string, expiration time.Duration) (string, error) {
	panic("not used in tests")
}

func (m *mockStorageClient) DownloadObject(ctx context.Context, bucketName, objectKey string, filePath string) error {
	m.downloadCalls = append(m.downloadCalls, downloadCall{
		Bucket:    bucketName,
		ObjectKey: objectKey,
		FilePath:  filePath,
	})
	if m.downloadErr != nil {
		return m.downloadErr
	}
	body := m.downloadBody
	if body == nil {
		body = []byte(`{"signed":{},"signatures":[]}`)
	}
	return os.WriteFile(filePath, body, 0644)
}

func (m *mockStorageClient) ListObjects(ctx context.Context, bucketName, prefix string) ([]string, error) {
	m.listObjectsCalls = append(m.listObjectsCalls, listCall{Bucket: bucketName, Prefix: prefix})
	if m.listObjectsErr != nil {
		return nil, m.listObjectsErr
	}
	if m.listObjectsResult == nil {
		return nil, nil
	}
	return m.listObjectsResult, nil
}

// mockStorageFactory returns a fixed client (for tests).
type mockStorageFactory struct {
	client utils.StorageClient
	err    error
}

func (m *mockStorageFactory) CreateStorageClient() (utils.StorageClient, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.client, nil
}

// To verify: In uploadWithClient change contentType to "text/plain" or skip calling client.UploadPublicObject; test will fail (wrong ContentType or no upload call).
func Test_uploadWithClient_Success(t *testing.T) {
	dir := t.TempDir()
	content := []byte(`{"signed":{},"signatures":[]}`)
	filePath := filepath.Join(dir, "root.json")
	require.NoError(t, os.WriteFile(filePath, content, 0644))
	mock := &mockStorageClient{}
	ctx := context.Background()
	bucket, s3Key, contentType := "my-bucket", "tuf_metadata/admin/app/root.json", "application/json"

	err := uploadWithClient(ctx, mock, bucket, s3Key, filePath, contentType)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	require.Len(t, mock.uploadCalls, 1, "Expected exactly one UploadPublicObject call")
	call := mock.uploadCalls[0]
	assert.Equal(t, bucket, call.Bucket, "Bucket should match input")
	assert.Equal(t, s3Key, call.ObjectKey, "ObjectKey (S3 key) should match input")
	assert.Equal(t, contentType, call.ContentType, "ContentType should be application/json")
	assert.Equal(t, content, call.Body, "Uploaded body should match file content")
}

// To verify: In uploadWithClient remove the os.Open check or return nil instead of error on open failure; test will fail (no error or wrong message).
func Test_uploadWithClient_OpenFileFails(t *testing.T) {

	mock := &mockStorageClient{}
	ctx := context.Background()
	nonexistentPath := "/nonexistent/path/file.json"

	err := uploadWithClient(ctx, mock, "bucket", "key", nonexistentPath, "application/json")

	require.Error(t, err, "Expected error when file does not exist")
	assert.Contains(t, err.Error(), "failed to open file", "Error message should mention failed to open file (expected %q, got %q)", "failed to open file", err.Error())
	assert.Contains(t, err.Error(), nonexistentPath, "Error should include the path that failed")
	assert.Len(t, mock.uploadCalls, 0, "UploadPublicObject must not be called when file open fails")
}

// To verify: In UploadMetadataToS3 change s3Key format to "metadata/%s/%s/%s" or use wrong bucket from env; test will fail (wrong ObjectKey or Bucket).
func Test_UploadMetadataToS3_Success(t *testing.T) {

	dir := t.TempDir()
	content := []byte(`{"signed":{},"signatures":[]}`)
	filePath := filepath.Join(dir, "snapshot.json")
	require.NoError(t, os.WriteFile(filePath, content, 0644))
	adminName, appName, filename := "admin1", "app1", "snapshot.json"
	mockClient := &mockStorageClient{}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")

	savedGetViper := getViperForUpload
	savedFactory := storageFactoryForUpload
	getViperForUpload = func() *viper.Viper { return mockViper }
	storageFactoryForUpload = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{client: mockClient}
	}
	defer func() {
		getViperForUpload = savedGetViper
		storageFactoryForUpload = savedFactory
	}()

	ctx := context.Background()
	err := UploadMetadataToS3(ctx, adminName, appName, filename, filePath)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	require.Len(t, mockClient.uploadCalls, 1, "Expected exactly one upload call")
	call := mockClient.uploadCalls[0]
	expectedKey := "tuf_metadata/admin1/app1/snapshot.json"
	assert.Equal(t, "test-bucket", call.Bucket, "Bucket should come from S3_BUCKET_NAME")
	assert.Equal(t, expectedKey, call.ObjectKey, "ObjectKey should be tuf_metadata/admin/app/filename (expected %q, got %q)", expectedKey, call.ObjectKey)
	assert.Equal(t, "application/json", call.ContentType, "ContentType should be application/json")
	assert.Equal(t, content, call.Body, "Uploaded body should match file content")
}

// To verify: In UploadMetadataToS3 remove the bucketName empty check or return nil when S3_BUCKET_NAME is empty; test will fail (no error returned).
func Test_UploadMetadataToS3_MissingBucket(t *testing.T) {

	dir := t.TempDir()
	filePath := filepath.Join(dir, "root.json")
	require.NoError(t, os.WriteFile(filePath, []byte("{}"), 0644))
	mockViper := viper.New()
	// S3_BUCKET_NAME not set (empty)

	savedGetViper := getViperForUpload
	savedFactory := storageFactoryForUpload
	getViperForUpload = func() *viper.Viper { return mockViper }
	storageFactoryForUpload = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{client: &mockStorageClient{}}
	}
	defer func() {
		getViperForUpload = savedGetViper
		storageFactoryForUpload = savedFactory
	}()

	ctx := context.Background()
	err := UploadMetadataToS3(ctx, "admin", "app", "root.json", filePath)

	require.Error(t, err, "Expected error when S3_BUCKET_NAME is not configured")
	assert.Contains(t, err.Error(), "S3_BUCKET_NAME is not configured", "Error should mention S3_BUCKET_NAME (expected substring in %q)", err.Error())
}

// To verify: In UploadMetadataToS3 ignore factory.CreateStorageClient() error and proceed; test will fail (no error or wrong message).
func Test_UploadMetadataToS3_CreateClientFails(t *testing.T) {

	dir := t.TempDir()
	filePath := filepath.Join(dir, "root.json")
	require.NoError(t, os.WriteFile(filePath, []byte("{}"), 0644))
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "bucket")

	savedGetViper := getViperForUpload
	savedFactory := storageFactoryForUpload
	getViperForUpload = func() *viper.Viper { return mockViper }
	storageFactoryForUpload = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{err: utils.ErrUnknownStorageDriver}
	}
	defer func() {
		getViperForUpload = savedGetViper
		storageFactoryForUpload = savedFactory
	}()

	ctx := context.Background()
	err := UploadMetadataToS3(ctx, "admin", "app", "root.json", filePath)

	require.Error(t, err, "Expected error when storage client creation fails")
	assert.Contains(t, err.Error(), "failed to create storage client", "Error should wrap client creation failure (expected substring in %q)", err.Error())
}

// To verify: In UploadMetadataToS3 ignore UploadPublicObject error or return nil; test will fail (no error or wrong message).
func Test_UploadMetadataToS3_UploadFails(t *testing.T) {

	dir := t.TempDir()
	filePath := filepath.Join(dir, "root.json")
	require.NoError(t, os.WriteFile(filePath, []byte("{}"), 0644))
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "bucket")
	mockClient := &mockStorageClient{uploadErr: utils.ErrUploadFailed}

	savedGetViper := getViperForUpload
	savedFactory := storageFactoryForUpload
	getViperForUpload = func() *viper.Viper { return mockViper }
	storageFactoryForUpload = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{client: mockClient}
	}
	defer func() {
		getViperForUpload = savedGetViper
		storageFactoryForUpload = savedFactory
	}()

	ctx := context.Background()
	err := UploadMetadataToS3(ctx, "admin", "app", "root.json", filePath)

	require.Error(t, err, "Expected error when upload fails")
	assert.Contains(t, err.Error(), "failed to upload root.json to S3", "Error should mention failed to upload and filename (expected substring in %q)", err.Error())
}

// --- DownloadMetadataFromS3 tests ---

// To verify: In DownloadMetadataFromS3 change s3Key format to "metadata/%s/%s/%s" or use wrong bucket from env; test will fail (wrong ObjectKey or Bucket).
func TestDownloadMetadataFromS3_Success(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "root.json")
	adminName, appName, filename := "admin1", "app1", "root.json"
	mockClient := &mockStorageClient{downloadBody: []byte(`{"signed":{},"signatures":[]}`)}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")

	savedGetViper := getViperForDownload
	savedFactory := storageFactoryForDownload
	getViperForDownload = func() *viper.Viper { return mockViper }
	storageFactoryForDownload = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{client: mockClient}
	}
	defer func() {
		getViperForDownload = savedGetViper
		storageFactoryForDownload = savedFactory
	}()

	ctx := context.Background()
	err := DownloadMetadataFromS3(ctx, adminName, appName, filename, outPath)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	require.Len(t, mockClient.downloadCalls, 1, "Expected exactly one download call")
	call := mockClient.downloadCalls[0]
	expectedKey := "tuf_metadata/admin1/app1/root.json"
	assert.Equal(t, "test-bucket", call.Bucket, "Bucket should come from S3_BUCKET_NAME")
	assert.Equal(t, expectedKey, call.ObjectKey, "ObjectKey should be tuf_metadata/admin/app/filename (expected %q, got %q)", expectedKey, call.ObjectKey)
	assert.Equal(t, outPath, call.FilePath, "FilePath should match input")
	content, readErr := os.ReadFile(outPath)
	require.NoError(t, readErr, "Downloaded file should be readable")
	assert.Equal(t, []byte(`{"signed":{},"signatures":[]}`), content, "Downloaded file content should match mock body")
}

// To verify: In DownloadMetadataFromS3 remove the bucketName empty check or return nil when S3_BUCKET_NAME is empty; test will fail (no error returned).
func TestDownloadMetadataFromS3_MissingBucket(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "root.json")
	mockViper := viper.New()
	// S3_BUCKET_NAME not set (empty)

	savedGetViper := getViperForDownload
	savedFactory := storageFactoryForDownload
	getViperForDownload = func() *viper.Viper { return mockViper }
	storageFactoryForDownload = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{client: &mockStorageClient{}}
	}
	defer func() {
		getViperForDownload = savedGetViper
		storageFactoryForDownload = savedFactory
	}()

	ctx := context.Background()
	err := DownloadMetadataFromS3(ctx, "admin", "app", "root.json", outPath)

	require.Error(t, err, "Expected error when S3_BUCKET_NAME is not configured")
	assert.Contains(t, err.Error(), "S3_BUCKET_NAME is not configured", "Error should mention S3_BUCKET_NAME (expected substring in %q)", err.Error())
}

// To verify: In DownloadMetadataFromS3 ignore factory.CreateStorageClient() error and proceed; test will fail (no error or wrong message).
func TestDownloadMetadataFromS3_CreateClientFails(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "root.json")
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "bucket")

	savedGetViper := getViperForDownload
	savedFactory := storageFactoryForDownload
	getViperForDownload = func() *viper.Viper { return mockViper }
	storageFactoryForDownload = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{err: utils.ErrUnknownStorageDriver}
	}
	defer func() {
		getViperForDownload = savedGetViper
		storageFactoryForDownload = savedFactory
	}()

	ctx := context.Background()
	err := DownloadMetadataFromS3(ctx, "admin", "app", "root.json", outPath)

	require.Error(t, err, "Expected error when storage client creation fails")
	assert.Contains(t, err.Error(), "failed to create storage client", "Error should wrap client creation failure (expected substring in %q)", err.Error())
}

// To verify: In DownloadMetadataFromS3 ignore DownloadObject error or return nil; test will fail (no error or wrong message).
func TestDownloadMetadataFromS3_DownloadFails(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "root.json")
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "bucket")
	downloadErr := fmt.Errorf("download failed")
	mockClient := &mockStorageClient{downloadErr: downloadErr}

	savedGetViper := getViperForDownload
	savedFactory := storageFactoryForDownload
	getViperForDownload = func() *viper.Viper { return mockViper }
	storageFactoryForDownload = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{client: mockClient}
	}
	defer func() {
		getViperForDownload = savedGetViper
		storageFactoryForDownload = savedFactory
	}()

	ctx := context.Background()
	err := DownloadMetadataFromS3(ctx, "admin", "app", "root.json", outPath)

	require.Error(t, err, "Expected error when download fails")
	assert.Contains(t, err.Error(), "failed to download root.json from S3", "Error should mention failed to download and filename (expected substring in %q)", err.Error())
}

// --- ListMetadataFromS3 tests ---

// To verify: In ListMetadataFromS3 change s3Prefix format or metadataPrefix; test will fail (wrong Prefix or filenames).
func TestListMetadataFromS3_Success(t *testing.T) {
	adminName, appName, prefix := "admin1", "app1", ""
	metadataPrefix := "tuf_metadata/admin1/app1/"
	objects := []string{
		metadataPrefix + "root.json",
		metadataPrefix + "1.snapshot.json",
		metadataPrefix + "timestamp.json",
	}
	mockClient := &mockStorageClient{listObjectsResult: objects}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "test-bucket")

	savedGetViper := getViperForList
	savedFactory := storageFactoryForList
	getViperForList = func() *viper.Viper { return mockViper }
	storageFactoryForList = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{client: mockClient}
	}
	defer func() {
		getViperForList = savedGetViper
		storageFactoryForList = savedFactory
	}()

	ctx := context.Background()
	filenames, err := ListMetadataFromS3(ctx, adminName, appName, prefix)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	require.Len(t, mockClient.listObjectsCalls, 1, "Expected exactly one ListObjects call")
	call := mockClient.listObjectsCalls[0]
	expectedS3Prefix := "tuf_metadata/admin1/app1/"
	assert.Equal(t, "test-bucket", call.Bucket, "Bucket should come from S3_BUCKET_NAME")
	assert.Equal(t, expectedS3Prefix, call.Prefix, "Prefix should be tuf_metadata/admin/app/prefix (expected %q, got %q)", expectedS3Prefix, call.Prefix)
	expectedFilenames := []string{"root.json", "1.snapshot.json", "timestamp.json"}
	assert.Equal(t, expectedFilenames, filenames, "Filenames should be stripped of metadata prefix")
}

// To verify: In ListMetadataFromS3 remove the bucketName empty check or return nil when S3_BUCKET_NAME is empty; test will fail (no error returned).
func TestListMetadataFromS3_MissingBucket(t *testing.T) {
	mockViper := viper.New()
	// S3_BUCKET_NAME not set (empty)

	savedGetViper := getViperForList
	savedFactory := storageFactoryForList
	getViperForList = func() *viper.Viper { return mockViper }
	storageFactoryForList = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{client: &mockStorageClient{}}
	}
	defer func() {
		getViperForList = savedGetViper
		storageFactoryForList = savedFactory
	}()

	ctx := context.Background()
	filenames, err := ListMetadataFromS3(ctx, "admin", "app", "")

	require.Error(t, err, "Expected error when S3_BUCKET_NAME is not configured")
	assert.Contains(t, err.Error(), "S3_BUCKET_NAME is not configured", "Error should mention S3_BUCKET_NAME (expected substring in %q)", err.Error())
	assert.Nil(t, filenames, "Filenames should be nil on error")
}

// To verify: In ListMetadataFromS3 ignore factory.CreateStorageClient() error and proceed; test will fail (no error or wrong message).
func TestListMetadataFromS3_CreateClientFails(t *testing.T) {
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "bucket")

	savedGetViper := getViperForList
	savedFactory := storageFactoryForList
	getViperForList = func() *viper.Viper { return mockViper }
	storageFactoryForList = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{err: utils.ErrUnknownStorageDriver}
	}
	defer func() {
		getViperForList = savedGetViper
		storageFactoryForList = savedFactory
	}()

	ctx := context.Background()
	filenames, err := ListMetadataFromS3(ctx, "admin", "app", "")

	require.Error(t, err, "Expected error when storage client creation fails")
	assert.Contains(t, err.Error(), "failed to create storage client", "Error should wrap client creation failure (expected substring in %q)", err.Error())
	assert.Nil(t, filenames, "Filenames should be nil on error")
}

// To verify: In ListMetadataFromS3 ignore ListObjects error or return nil; test will fail (no error or wrong message).
func TestListMetadataFromS3_ListFails(t *testing.T) {
	listErr := fmt.Errorf("list failed")
	mockClient := &mockStorageClient{listObjectsErr: listErr}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "bucket")

	savedGetViper := getViperForList
	savedFactory := storageFactoryForList
	getViperForList = func() *viper.Viper { return mockViper }
	storageFactoryForList = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{client: mockClient}
	}
	defer func() {
		getViperForList = savedGetViper
		storageFactoryForList = savedFactory
	}()

	ctx := context.Background()
	filenames, err := ListMetadataFromS3(ctx, "admin", "app", "")

	require.Error(t, err, "Expected error when list fails")
	assert.Contains(t, err.Error(), "failed to list objects from S3", "Error should mention failed to list objects (expected substring in %q)", err.Error())
	assert.Nil(t, filenames, "Filenames should be nil on error")
}

// To verify: In ListMetadataFromS3 change the filenames extraction (e.g. skip objects with len(obj) <= len(metadataPrefix)); test may fail if empty handling is wrong.
func TestListMetadataFromS3_EmptyResult(t *testing.T) {
	mockClient := &mockStorageClient{listObjectsResult: []string{}}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "bucket")

	savedGetViper := getViperForList
	savedFactory := storageFactoryForList
	getViperForList = func() *viper.Viper { return mockViper }
	storageFactoryForList = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{client: mockClient}
	}
	defer func() {
		getViperForList = savedGetViper
		storageFactoryForList = savedFactory
	}()

	ctx := context.Background()
	filenames, err := ListMetadataFromS3(ctx, "admin", "app", "")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	assert.Empty(t, filenames, "Filenames should be empty when no objects returned")
}

// To verify: In ListMetadataFromS3 objects shorter than metadataPrefix are skipped; change condition to len(obj) >= len(metadataPrefix) and test will include wrong entry.
func TestListMetadataFromS3_SkipsShortKeys(t *testing.T) {
	metadataPrefix := "tuf_metadata/a/b/"
	objects := []string{
		metadataPrefix + "root.json",
		"tuf_metadata/a/b", // same length as prefix, should be skipped (len(obj) > len(metadataPrefix) is false)
		metadataPrefix + "snapshot.json",
	}
	mockClient := &mockStorageClient{listObjectsResult: objects}
	mockViper := viper.New()
	mockViper.Set("S3_BUCKET_NAME", "bucket")

	savedGetViper := getViperForList
	savedFactory := storageFactoryForList
	getViperForList = func() *viper.Viper { return mockViper }
	storageFactoryForList = func(*viper.Viper) storageFactory {
		return &mockStorageFactory{client: mockClient}
	}
	defer func() {
		getViperForList = savedGetViper
		storageFactoryForList = savedFactory
	}()

	ctx := context.Background()
	filenames, err := ListMetadataFromS3(ctx, "a", "b", "")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	// Only keys longer than metadataPrefix are included; "tuf_metadata/a/b" has len == len(metadataPrefix) so skipped
	expected := []string{"root.json", "snapshot.json"}
	assert.Equal(t, expected, filenames, "Short keys (len <= metadataPrefix) should be skipped")
}

// --- FindLatestMetadataVersion tests ---

// To verify: In FindLatestMetadataVersion change roleName check to "other" or remove early return for "timestamp"; test will fail (wrong version/filename or call to list).
func TestFindLatestMetadataVersion_TimestampRole(t *testing.T) {
	ctx := context.Background()
	ver, filename, err := FindLatestMetadataVersion(ctx, "admin", "app", "timestamp")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	assert.Equal(t, 0, ver, "Timestamp role should return version 0")
	assert.Equal(t, "timestamp.json", filename, "Timestamp role should return timestamp.json")
}

// To verify: In FindLatestMetadataVersion ignore listMetadataForLatest error; test will fail (no error or wrong message).
func TestFindLatestMetadataVersion_ListFails(t *testing.T) {
	listErr := fmt.Errorf("list failed")
	saved := listMetadataForLatest
	listMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return nil, listErr
	}
	defer func() { listMetadataForLatest = saved }()

	ctx := context.Background()
	ver, filename, err := FindLatestMetadataVersion(ctx, "admin", "app", "snapshot")

	require.Error(t, err, "Expected error when list fails")
	assert.Contains(t, err.Error(), "failed to list metadata files", "Error should wrap list failure (expected substring in %q)", err.Error())
	assert.Equal(t, 0, ver, "Version should be 0 on error")
	assert.Equal(t, "", filename, "Filename should be empty on error")
}

// To verify: In FindLatestMetadataVersion return (1, expectedSuffix, nil) when latestFilename is empty; test will fail (no error returned).
func TestFindLatestMetadataVersion_NoFileForRole(t *testing.T) {
	saved := listMetadataForLatest
	listMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"root.json", "timestamp.json"}, nil // no snapshot.json
	}
	defer func() { listMetadataForLatest = saved }()

	ctx := context.Background()
	ver, filename, err := FindLatestMetadataVersion(ctx, "admin", "app", "snapshot")

	require.Error(t, err, "Expected error when no metadata file for role")
	assert.Contains(t, err.Error(), "no metadata file found for role: snapshot", "Error should mention role name (expected substring in %q)", err.Error())
	assert.Equal(t, 0, ver, "Version should be 0 on error")
	assert.Equal(t, "", filename, "Filename should be empty on error")
}

// To verify: In FindLatestMetadataVersion change unversioned handling (filename == expectedSuffix) to set maxVersion=0 or skip; test will fail (wrong version/filename).
func TestFindLatestMetadataVersion_UnversionedRole(t *testing.T) {
	saved := listMetadataForLatest
	listMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"snapshot.json"}, nil // only unversioned
	}
	defer func() { listMetadataForLatest = saved }()

	ctx := context.Background()
	ver, filename, err := FindLatestMetadataVersion(ctx, "admin", "app", "snapshot")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	assert.Equal(t, 1, ver, "Unversioned role file should be treated as version 1")
	assert.Equal(t, "snapshot.json", filename, "Filename should be snapshot.json")
}

// To verify: In FindLatestMetadataVersion change version comparison to >= or use wrong max; test will fail (wrong version or filename).
func TestFindLatestMetadataVersion_VersionedRole(t *testing.T) {
	saved := listMetadataForLatest
	listMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.snapshot.json", "2.snapshot.json", "3.snapshot.json"}, nil
	}
	defer func() { listMetadataForLatest = saved }()

	ctx := context.Background()
	ver, filename, err := FindLatestMetadataVersion(ctx, "admin", "app", "snapshot")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	assert.Equal(t, 3, ver, "Should return highest version")
	assert.Equal(t, "3.snapshot.json", filename, "Filename should be latest versioned file")
}

// To verify: In FindLatestMetadataVersion change filtering (expectedSuffix or namePart); test will fail (wrong filename or include other role).
func TestFindLatestMetadataVersion_IgnoresOtherRoles(t *testing.T) {
	saved := listMetadataForLatest
	listMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"root.json", "timestamp.json", "1.snapshot.json", "2.targets.json"}, nil
	}
	defer func() { listMetadataForLatest = saved }()

	ctx := context.Background()
	ver, filename, err := FindLatestMetadataVersion(ctx, "admin", "app", "snapshot")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	assert.Equal(t, 1, ver, "Should pick snapshot role only")
	assert.Equal(t, "1.snapshot.json", filename, "Filename should be snapshot role file only")
}

// To verify: In FindLatestMetadataVersion skip invalid version (Atoi failure) and still pick valid one
func TestFindLatestMetadataVersion_IgnoresInvalidVersion(t *testing.T) {
	saved := listMetadataForLatest
	listMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"x.snapshot.json", "1.snapshot.json"}, nil // x.snapshot.json has non-numeric version
	}
	defer func() { listMetadataForLatest = saved }()

	ctx := context.Background()
	ver, filename, err := FindLatestMetadataVersion(ctx, "admin", "app", "snapshot")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	assert.Equal(t, 1, ver, "Should use valid version and skip invalid")
	assert.Equal(t, "1.snapshot.json", filename, "Filename should be valid versioned file")
}

// To verify: In FindLatestMetadataVersion when only invalid/unmatched files exist return error; remove "no metadata file found" check and test will fail (wrong return).
func TestFindLatestMetadataVersion_OnlyInvalidVersionReturnsError(t *testing.T) {
	saved := listMetadataForLatest
	listMetadataForLatest = func(context.Context, string, string, string) ([]string, error) {
		return []string{"x.snapshot.json"}, nil // Atoi fails, no valid version
	}
	defer func() { listMetadataForLatest = saved }()

	ctx := context.Background()
	ver, filename, err := FindLatestMetadataVersion(ctx, "admin", "app", "snapshot")

	require.Error(t, err, "Expected error when no valid metadata file for role")
	assert.Contains(t, err.Error(), "no metadata file found for role: snapshot", "Error should mention role (expected substring in %q)", err.Error())
	assert.Equal(t, 0, ver, "Version should be 0 on error")
	assert.Equal(t, "", filename, "Filename should be empty on error")
}

// --- GetAllDelegatedRoles tests ---

// To verify: In GetAllDelegatedRoles ignore listMetadataForGetAllDelegatedRoles error; test will fail (no error or wrong message).
func TestGetAllDelegatedRoles_ListFails(t *testing.T) {
	listErr := fmt.Errorf("list failed")
	saved := listMetadataForGetAllDelegatedRoles
	listMetadataForGetAllDelegatedRoles = func(context.Context, string, string, string) ([]string, error) {
		return nil, listErr
	}
	defer func() { listMetadataForGetAllDelegatedRoles = saved }()

	ctx := context.Background()
	roles, err := GetAllDelegatedRoles(ctx, "admin", "app")

	require.Error(t, err, "Expected error when list fails")
	assert.Contains(t, err.Error(), "failed to list metadata files", "Error should wrap list failure (expected substring in %q)", err.Error())
	assert.Nil(t, roles, "Roles should be nil on error")
}

// To verify: In GetAllDelegatedRoles change logic so known roles are included; test will fail (roles not empty).
func TestGetAllDelegatedRoles_OnlyKnownRolesReturnsEmpty(t *testing.T) {
	saved := listMetadataForGetAllDelegatedRoles
	listMetadataForGetAllDelegatedRoles = func(context.Context, string, string, string) ([]string, error) {
		return []string{"root.json", "targets.json", "snapshot.json", "timestamp.json", "1.snapshot.json"}, nil
	}
	defer func() { listMetadataForGetAllDelegatedRoles = saved }()

	ctx := context.Background()
	roles, err := GetAllDelegatedRoles(ctx, "admin", "app")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	assert.Empty(t, roles, "Known roles (root, targets, snapshot, timestamp) should be excluded; delegated roles should be empty")
}

// To verify: In GetAllDelegatedRoles change unversioned delegated role handling (lastDotIndex == -1); test will fail (missing role).
func TestGetAllDelegatedRoles_UnversionedDelegatedRole(t *testing.T) {
	saved := listMetadataForGetAllDelegatedRoles
	listMetadataForGetAllDelegatedRoles = func(context.Context, string, string, string) ([]string, error) {
		return []string{"myrole.json"}, nil // no dot in nameWithoutExt -> delegated role "myrole"
	}
	defer func() { listMetadataForGetAllDelegatedRoles = saved }()

	ctx := context.Background()
	roles, err := GetAllDelegatedRoles(ctx, "admin", "app")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	assert.ElementsMatch(t, []string{"myrole"}, roles, "Unversioned delegated role myrole.json should yield role 'myrole'")
}

// To verify: In GetAllDelegatedRoles change versioned delegated role handling (Atoi check); test will fail (missing role).
func TestGetAllDelegatedRoles_VersionedDelegatedRole(t *testing.T) {
	saved := listMetadataForGetAllDelegatedRoles
	listMetadataForGetAllDelegatedRoles = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.delegated.json"}, nil // versionStr "1" -> role "delegated"
	}
	defer func() { listMetadataForGetAllDelegatedRoles = saved }()

	ctx := context.Background()
	roles, err := GetAllDelegatedRoles(ctx, "admin", "app")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	assert.ElementsMatch(t, []string{"delegated"}, roles, "Versioned file 1.delegated.json should yield role 'delegated'")
}

// To verify: In GetAllDelegatedRoles change known-role filter or role extraction; test will fail (wrong set of roles).
func TestGetAllDelegatedRoles_MixKnownAndDelegated(t *testing.T) {
	saved := listMetadataForGetAllDelegatedRoles
	listMetadataForGetAllDelegatedRoles = func(context.Context, string, string, string) ([]string, error) {
		return []string{"root.json", "timestamp.json", "1.snapshot.json", "2.delegated.json", "targets.json"}, nil
	}
	defer func() { listMetadataForGetAllDelegatedRoles = saved }()

	ctx := context.Background()
	roles, err := GetAllDelegatedRoles(ctx, "admin", "app")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	// root, timestamp, snapshot, targets are known and skipped; only "delegated" from 2.delegated.json
	assert.ElementsMatch(t, []string{"delegated"}, roles, "Only delegated roles should be returned; known roles skipped")
}

// To verify: In GetAllDelegatedRoles change logic so invalid version (non-numeric prefix) is included; test will fail (roles contain delegated).
func TestGetAllDelegatedRoles_IgnoresInvalidVersionedName(t *testing.T) {
	saved := listMetadataForGetAllDelegatedRoles
	listMetadataForGetAllDelegatedRoles = func(context.Context, string, string, string) ([]string, error) {
		return []string{"x.delegated.json"}, nil // Atoi("x") fails -> not added
	}
	defer func() { listMetadataForGetAllDelegatedRoles = saved }()

	ctx := context.Background()
	roles, err := GetAllDelegatedRoles(ctx, "admin", "app")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	assert.Empty(t, roles, "x.delegated.json has non-numeric version prefix; should be skipped, no delegated role added")
}

// To verify: In GetAllDelegatedRoles deduplicate by role name; test will fail if duplicates appear.
func TestGetAllDelegatedRoles_MultipleFilesSameRole(t *testing.T) {
	saved := listMetadataForGetAllDelegatedRoles
	listMetadataForGetAllDelegatedRoles = func(context.Context, string, string, string) ([]string, error) {
		return []string{"1.delegated.json", "2.delegated.json", "delegated.json"}, nil
	}
	defer func() { listMetadataForGetAllDelegatedRoles = saved }()

	ctx := context.Background()
	roles, err := GetAllDelegatedRoles(ctx, "admin", "app")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	// "delegated" from all three; result should be single "delegated"
	assert.ElementsMatch(t, []string{"delegated"}, roles, "Multiple files for same role should yield role once")
}

// To verify: In GetAllDelegatedRoles empty filenames return empty roles; remove early return or change logic and test may fail.
func TestGetAllDelegatedRoles_EmptyList(t *testing.T) {
	saved := listMetadataForGetAllDelegatedRoles
	listMetadataForGetAllDelegatedRoles = func(context.Context, string, string, string) ([]string, error) {
		return []string{}, nil
	}
	defer func() { listMetadataForGetAllDelegatedRoles = saved }()

	ctx := context.Background()
	roles, err := GetAllDelegatedRoles(ctx, "admin", "app")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	assert.Empty(t, roles, "Empty filenames should yield empty roles slice")
}
