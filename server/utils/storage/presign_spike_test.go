//go:build presignspike

package storage

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/spf13/viper"
)

func spikeEnv(t *testing.T) *viper.Viper {
	t.Helper()
	env := viper.New()
	env.SetConfigType("env")
	env.SetConfigName(".env")
	env.AddConfigPath("../../..")
	if err := env.ReadInConfig(); err != nil {
		t.Logf(".env not read (%v), falling back to process environment", err)
	}
	env.AutomaticEnv()
	return env
}

// spikeClient builds the client exactly as production does for the configured driver,
// so the probe measures the provider and not a different endpoint style.
func spikeClient(t *testing.T, env *viper.Viper, bucket string) (*s3.Client, *s3.PresignClient) {
	t.Helper()

	driver := env.GetString("STORAGE_DRIVER")
	t.Logf("driver: %s, endpoint: %s, path style: %v, region: %s",
		driver, env.GetString("S3_ENDPOINT"), env.GetBool("S3_FORCE_PATH_STYLE"), env.GetString("S3_REGION"))

	storageClient, err := NewStorageFactory(env).CreateStorageClient()
	if err != nil {
		t.Fatalf("create storage client: %v", err)
	}

	var base *BaseS3Client
	switch c := storageClient.(type) {
	case *AWSS3Client:
		base = c.BaseS3Client
	case *DigitalOceanSpacesClient:
		base = c.BaseS3Client
	default:
		t.Skipf("driver %q does not use the S3 SDK, nothing to presign here", driver)
	}

	client := base.clientFor(bucket)
	// Without this the SDK adds its own CRC32 checksum, which would end up in the signature.
	presigner := s3.NewPresignClient(client, func(o *s3.PresignOptions) {
		o.ClientOptions = append(o.ClientOptions, func(co *s3.Options) {
			co.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		})
	})

	return client, presigner
}

func s3ErrorCode(body []byte) string {
	s := string(body)
	start := strings.Index(s, "<Code>")
	if start < 0 {
		if len(s) > 200 {
			return s[:200]
		}
		return s
	}
	end := strings.Index(s[start:], "</Code>")
	if end < 0 {
		return "?"
	}
	return s[start+len("<Code>") : start+end]
}

func putSigned(t *testing.T, url string, headers map[string][]string, body []byte) (int, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for name, values := range headers {
		for _, v := range values {
			req.Header.Set(name, v)
		}
	}
	req.ContentLength = int64(len(body))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	code := ""
	if resp.StatusCode >= 300 {
		code = s3ErrorCode(respBody)
	}
	return resp.StatusCode, code
}

// Does a presigned PUT whose signature covers x-amz-checksum-sha256 and Content-Length
// actually make the storage verify the bytes, and does HeadObject give the checksum back?
func TestPresignPutChecksumSpike(t *testing.T) {
	env := spikeEnv(t)
	bucket := env.GetString("S3_BUCKET_NAME")
	client, presigner := spikeClient(t, env, bucket)
	key := fmt.Sprintf("pending/spike-%d/artifact.bin", time.Now().UnixNano())
	t.Logf("bucket: %s, key: %s", bucket, key)

	payload := []byte("faynoSync presigned upload spike payload")
	sum := sha256.Sum256(payload)
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	t.Logf("x-amz-checksum-sha256 (base64): %s", checksum)

	signed, err := presigner.PresignPutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:         aws.String(bucket),
		Key:            aws.String(key),
		ChecksumSHA256: aws.String(checksum),
		ContentLength:  aws.Int64(int64(len(payload))),
	}, s3.WithPresignExpires(15*time.Minute))
	if err != nil {
		t.Fatalf("presign: %v", err)
	}
	if host := strings.SplitN(strings.TrimPrefix(strings.TrimPrefix(signed.URL, "https://"), "http://"), "/", 2); len(host) > 0 {
		t.Logf("presigned host: %s", host[0])
	}
	t.Logf("signed headers the client must send: %v", signed.SignedHeader)
	if parsed, perr := neturl.Parse(signed.URL); perr == nil {
		names := make([]string, 0, len(parsed.Query()))
		for name := range parsed.Query() {
			names = append(names, name)
		}
		sort.Strings(names)
		t.Logf("query parameter names: %v", names)
		t.Logf("checksum travels in query: %v", parsed.Query().Get("x-amz-checksum-sha256") == checksum || parsed.Query().Get("X-Amz-Checksum-Sha256") == checksum)
	}

	t.Run("tampered bytes are rejected", func(t *testing.T) {
		tampered := append([]byte{}, payload...)
		tampered[0] ^= 0xff
		status, code := putSigned(t, signed.URL, signed.SignedHeader, tampered)
		t.Logf("PUT tampered -> %d %s", status, code)
		if status < 400 {
			t.Errorf("tampered payload accepted with %d: storage does NOT verify the signed checksum", status)
		}
	})

	t.Run("wrong length is rejected", func(t *testing.T) {
		status, code := putSigned(t, signed.URL, signed.SignedHeader, payload[:len(payload)-1])
		t.Logf("PUT short body -> %d %s", status, code)
		if status < 400 {
			t.Errorf("short payload accepted with %d: Content-Length is not enforced", status)
		}
	})

	t.Run("correct bytes are accepted", func(t *testing.T) {
		status, code := putSigned(t, signed.URL, signed.SignedHeader, payload)
		t.Logf("PUT correct -> %d %s", status, code)
		if status >= 300 {
			t.Fatalf("correct payload rejected with %d %s", status, code)
		}
	})

	t.Run("head returns the checksum", func(t *testing.T) {
		head, err := client.HeadObject(context.TODO(), &s3.HeadObjectInput{
			Bucket:       aws.String(bucket),
			Key:          aws.String(key),
			ChecksumMode: types.ChecksumModeEnabled,
		})
		if err != nil {
			t.Fatalf("HeadObject: %v", err)
		}
		got := aws.ToString(head.ChecksumSHA256)
		t.Logf("HeadObject ContentLength=%d ChecksumSHA256=%q", aws.ToInt64(head.ContentLength), got)
		if got == "" {
			t.Error("HeadObject returned no ChecksumSHA256: complete() cannot read the hash back from storage")
		} else if got != checksum {
			t.Errorf("HeadObject checksum %q != uploaded %q", got, checksum)
		}
	})

	t.Cleanup(func() {
		if _, err := client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}); err != nil {
			t.Logf("cleanup delete failed: %v", err)
		}
	})
}

// Fallback probe for providers without flexible checksums: Content-MD5 is part of the
// original S3 API, and it is a signed header, so the provider has to verify the body
// against a digest the presigner fixed.
func TestPresignPutContentMD5Spike(t *testing.T) {
	env := spikeEnv(t)
	bucket := env.GetString("S3_BUCKET_NAME")
	client, presigner := spikeClient(t, env, bucket)

	key := fmt.Sprintf("pending/spike-md5-%d/artifact.bin", time.Now().UnixNano())
	payload := []byte("faynoSync presigned upload spike payload")
	digest := md5.Sum(payload)
	contentMD5 := base64.StdEncoding.EncodeToString(digest[:])
	t.Logf("bucket: %s, key: %s, Content-MD5: %s", bucket, key, contentMD5)

	signed, err := presigner.PresignPutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		ContentMD5:    aws.String(contentMD5),
		ContentLength: aws.Int64(int64(len(payload))),
	}, s3.WithPresignExpires(15*time.Minute))
	if err != nil {
		t.Fatalf("presign: %v", err)
	}
	t.Logf("signed headers the client must send: %v", signed.SignedHeader)

	t.Run("tampered bytes are rejected", func(t *testing.T) {
		tampered := append([]byte{}, payload...)
		tampered[0] ^= 0xff
		status, code := putSigned(t, signed.URL, signed.SignedHeader, tampered)
		t.Logf("PUT tampered -> %d %s", status, code)
		if status < 400 {
			t.Errorf("tampered payload accepted with %d: Content-MD5 is not verified either", status)
		}
	})

	t.Run("correct bytes are accepted", func(t *testing.T) {
		status, code := putSigned(t, signed.URL, signed.SignedHeader, payload)
		t.Logf("PUT correct -> %d %s", status, code)
		if status >= 300 {
			t.Fatalf("correct payload rejected with %d %s", status, code)
		}
	})

	t.Cleanup(func() {
		if _, err := client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}); err != nil {
			t.Logf("cleanup delete failed: %v", err)
		}
	})
}

// Can complete() get a storage-computed digest of the stored bytes without downloading
// them? Two candidates: the ETag of a single-part PUT (MD5 everywhere), and asking the
// provider to compute a SHA-256 while it copies pending -> final server side.
func TestStoredDigestsWithoutDownloadSpike(t *testing.T) {
	env := spikeEnv(t)
	bucket := env.GetString("S3_BUCKET_NAME")
	client, presigner := spikeClient(t, env, bucket)

	stamp := time.Now().UnixNano()
	pendingKey := fmt.Sprintf("pending/spike-copy-%d/artifact.bin", stamp)
	finalKey := fmt.Sprintf("pending/spike-copy-%d/final.bin", stamp)

	payload := []byte("faynoSync presigned upload spike payload")
	sha := sha256.Sum256(payload)
	wantSHA := base64.StdEncoding.EncodeToString(sha[:])
	md := md5.Sum(payload)
	wantETag := hex.EncodeToString(md[:])

	// A plain presigned PUT, the way an upload lands when the provider verifies nothing.
	signed, err := presigner.PresignPutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(pendingKey),
	}, s3.WithPresignExpires(15*time.Minute))
	if err != nil {
		t.Fatalf("presign: %v", err)
	}
	if status, code := putSigned(t, signed.URL, signed.SignedHeader, payload); status >= 300 {
		t.Fatalf("plain PUT rejected with %d %s", status, code)
	}

	t.Run("etag is the md5 of the stored bytes", func(t *testing.T) {
		head, err := client.HeadObject(context.TODO(), &s3.HeadObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(pendingKey),
		})
		if err != nil {
			t.Fatalf("HeadObject: %v", err)
		}
		etag := strings.Trim(aws.ToString(head.ETag), `"`)
		t.Logf("ETag=%q want md5=%q ContentLength=%d", etag, wantETag, aws.ToInt64(head.ContentLength))
		if etag != wantETag {
			t.Errorf("ETag %q is not the MD5 of the stored bytes", etag)
		}
	})

	t.Run("copy can compute sha256 server side", func(t *testing.T) {
		_, err := client.CopyObject(context.TODO(), &s3.CopyObjectInput{
			Bucket:            aws.String(bucket),
			Key:               aws.String(finalKey),
			CopySource:        aws.String(bucket + "/" + pendingKey),
			ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		})
		if err != nil {
			t.Fatalf("CopyObject with ChecksumAlgorithm=SHA256: %v", err)
		}

		head, err := client.HeadObject(context.TODO(), &s3.HeadObjectInput{
			Bucket:       aws.String(bucket),
			Key:          aws.String(finalKey),
			ChecksumMode: types.ChecksumModeEnabled,
		})
		if err != nil {
			t.Fatalf("HeadObject(final): %v", err)
		}
		got := aws.ToString(head.ChecksumSHA256)
		t.Logf("copied object ChecksumSHA256=%q want %q", got, wantSHA)
		if got == "" {
			t.Error("copy did not produce a checksum: sha256 cannot be obtained without downloading")
		} else if got != wantSHA {
			t.Errorf("copy checksum %q != %q", got, wantSHA)
		}
	})

	t.Cleanup(func() {
		for _, key := range []string{pendingKey, finalKey} {
			if _, err := client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(key),
			}); err != nil {
				t.Logf("cleanup delete %s failed: %v", key, err)
			}
		}
	})
}
