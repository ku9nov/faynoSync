package storage

import (
	"context"
	"crypto/md5"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

var (
	_ PresignedUploader = (*AWSS3Client)(nil)
	_ PresignedUploader = (*DigitalOceanSpacesClient)(nil)
	_ PresignedUploader = (*GoogleCloudStorageClient)(nil)
)

func TestMinioIsNotPresignedUploader(t *testing.T) {
	var client StorageClient = &MinioClient{}
	if _, ok := client.(PresignedUploader); ok {
		t.Fatal("MinIO must not advertise presigned uploads")
	}
}

func newTestAWSClient(t *testing.T) *AWSS3Client {
	t.Helper()
	env := viper.New()
	env.Set("S3_ACCESS_KEY", "AKIDEXAMPLE")
	env.Set("S3_SECRET_KEY", "secret")
	env.Set("S3_REGION", "eu-central-1")
	env.Set("S3_ENDPOINT", "https://bucket.s3.amazonaws.com")
	client, err := NewAWSS3Client(env)
	if err != nil {
		t.Fatalf("NewAWSS3Client: %v", err)
	}
	return client
}

// The signature must bind the body through Content-MD5 and Content-Length only: an
// SDK-added flexible checksum would be computed over an empty body and fail every PUT,
// and a query-string SHA-256 is silently ignored by AWS and DO.
func TestPresignPutObjectSignsMD5AndLength(t *testing.T) {
	client := newTestAWSClient(t)
	digest := md5.Sum([]byte("payload"))

	req, err := client.PresignPutObject(context.Background(), "bucket", "pending/abc/My App.exe", digest[:], 7, "application/octet-stream", 15*time.Minute)
	if err != nil {
		t.Fatalf("PresignPutObject: %v", err)
	}

	if got := req.Headers.Get("Content-Md5"); got != "Mhw89IbtUJFk7eweGYH+yA==" {
		t.Errorf("Content-MD5 = %q", got)
	}
	if got := req.Headers.Get("Content-Length"); got != "7" {
		t.Errorf("Content-Length = %q", got)
	}
	if got := req.Headers.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q", got)
	}
	if req.Headers.Get("Host") != "" {
		t.Error("Host must not be returned, HTTP clients set it themselves")
	}

	parsed, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if !strings.HasSuffix(parsed.Path, "/pending/abc/My App.exe") {
		t.Errorf("URL path %q does not end with the object key", parsed.Path)
	}
	for name := range parsed.Query() {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-checksum") || strings.HasPrefix(strings.ToLower(name), "x-amz-sdk-checksum") {
			t.Errorf("unexpected checksum parameter %q in presigned URL", name)
		}
	}
	for name := range req.Headers {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-checksum") || strings.HasPrefix(strings.ToLower(name), "x-amz-sdk-checksum") {
			t.Errorf("unexpected checksum header %q", name)
		}
	}
	if parsed.Query().Get("X-Amz-Expires") != "900" {
		t.Errorf("X-Amz-Expires = %q, want 900", parsed.Query().Get("X-Amz-Expires"))
	}
}

func TestPresignPutObjectRejectsInvalidInput(t *testing.T) {
	client := newTestAWSClient(t)
	digest := md5.Sum([]byte("payload"))

	if _, err := client.PresignPutObject(context.Background(), "bucket", "k", digest[:8], 7, "", time.Minute); err == nil {
		t.Error("short MD5 accepted")
	}
	if _, err := client.PresignPutObject(context.Background(), "bucket", "k", digest[:], -1, "", time.Minute); err == nil {
		t.Error("negative length accepted")
	}
}

// An undeclared length is left out of the signature; the signed MD5 still pins the bytes.
func TestPresignPutObjectWithoutLength(t *testing.T) {
	client := newTestAWSClient(t)
	digest := md5.Sum([]byte("payload"))

	req, err := client.PresignPutObject(context.Background(), "bucket", "k", digest[:], 0, "", time.Minute)
	if err != nil {
		t.Fatalf("PresignPutObject: %v", err)
	}
	if req.Headers.Get("Content-Length") != "" {
		t.Errorf("Content-Length signed without a declared length: %v", req.Headers)
	}
	if req.Headers.Get("Content-Md5") == "" {
		t.Error("Content-MD5 must always be signed")
	}
}

func TestMD5FromETag(t *testing.T) {
	cases := map[string]string{
		`"fed304a43b43b889ac1b948e073928d0"`:   "fed304a43b43b889ac1b948e073928d0",
		`"FED304A43B43B889AC1B948E073928D0"`:   "fed304a43b43b889ac1b948e073928d0",
		`"fed304a43b43b889ac1b948e073928d0-3"`: "",
		`"zzz304a43b43b889ac1b948e073928d0"`:   "",
		"":                                     "",
	}
	for etag, want := range cases {
		if got := md5FromETag(etag); got != want {
			t.Errorf("md5FromETag(%q) = %q, want %q", etag, got, want)
		}
	}
}

func TestSHA256FromChecksum(t *testing.T) {
	cases := map[string]string{
		"1zQo1OISid5T+pZCdO0dwOOaT1jjgl/GlhfJ097jZtc=":   "d73428d4e21289de53fa964274ed1dc0e39a4f58e3825fc69617c9d3dee366d7",
		"1zQo1OISid5T+pZCdO0dwOOaT1jjgl/GlhfJ097jZtc=-2": "",
		"/tMEpDtDuImsG5SOBzko0A==":                       "",
		"":                                               "",
	}
	for checksum, want := range cases {
		if got := sha256FromChecksum(checksum); got != want {
			t.Errorf("sha256FromChecksum(%q) = %q, want %q", checksum, got, want)
		}
	}
}

func TestPublicObjectURLKeepsProviderFormat(t *testing.T) {
	env := viper.New()
	env.Set("S3_ENDPOINT", "https://bucket.s3.amazonaws.com/")
	aws := &AWSS3Client{BaseS3Client: &BaseS3Client{env: env}}
	if got := aws.PublicObjectURL("bucket", "app/My App.exe"); got != "https://bucket.s3.amazonaws.com/app/My%20App.exe" {
		t.Errorf("AWS = %q", got)
	}

	doEnv := viper.New()
	doEnv.Set("S3_ENDPOINT", "sfo3.digitaloceanspaces.com")
	do := &DigitalOceanSpacesClient{BaseS3Client: &BaseS3Client{env: doEnv}}
	if got := do.PublicObjectURL("bucket", "app/My App.exe"); got != "https://bucket.sfo3.digitaloceanspaces.com/app/My%20App.exe" {
		t.Errorf("DO = %q", got)
	}

	gcs := &GoogleCloudStorageClient{env: viper.New()}
	if got := gcs.PublicObjectURL("bucket", "app/MyApp.exe"); got != "https://storage.googleapis.com/bucket/app/MyApp.exe" {
		t.Errorf("GCS = %q", got)
	}
}
