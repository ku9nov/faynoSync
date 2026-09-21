package info

import (
	"context"
	"io"
	"mime/multipart"
	"testing"
	"time"

	"faynoSync/server/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
)

type cdnUpload struct {
	key  string
	body string
}

type blockingCDNClient struct {
	utils.StorageClient
	release chan struct{}
	uploads chan cdnUpload
}

func (b *blockingCDNClient) GetObjectETag(ctx context.Context, bucketName, objectKey string) (string, bool, error) {
	<-b.release
	return "", false, nil
}

func (b *blockingCDNClient) UploadPublicObjectWithCacheControl(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType, cacheControl string) (string, error) {
	body, _ := io.ReadAll(fileReader)
	b.uploads <- cdnUpload{key: objectKey, body: string(body)}
	return "", nil
}

func withCDNClient(t *testing.T, client utils.StorageClient) {
	t.Helper()
	viper.Set("S3_BUCKET_NAME_CDN", "cdn-bucket")
	cdnClientMu.Lock()
	cdnClient = client
	cdnClientMu.Unlock()
	t.Cleanup(func() {
		viper.Set("S3_BUCKET_NAME_CDN", "")
		cdnClientMu.Lock()
		cdnClient = nil
		cdnClientMu.Unlock()
	})
}

func cdnTestParams() map[string]interface{} {
	return map[string]interface{}{
		"owner": "admin", "app_name": "app", "channel": "stable", "platform": "darwin", "arch": "arm64", "updater": "manual", "version": "1.0.0",
	}
}

func TestPublishResponseToCDNDoesNotWaitForStorage(t *testing.T) {
	client := &blockingCDNClient{release: make(chan struct{}), uploads: make(chan cdnUpload, 1)}
	withCDNClient(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		publishResponseToCDN(ctx, nil, "", cdnTestParams(), gin.H{"update_available": true})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publishResponseToCDN blocked on storage")
	}

	// The request context ends with the response; the background publish must survive it.
	cancel()
	close(client.release)

	select {
	case upload := <-client.uploads:
		if upload.key != "responses/admin/app/stable/darwin/arm64/manual/1.0.0.json" {
			t.Fatalf("unexpected key %q", upload.key)
		}
		if upload.body != `{"update_available":true}` {
			t.Fatalf("unexpected body %q", upload.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("response was never published to CDN")
	}
}

func TestPublishResponseToCDNSkipsWhenSlotsAreBusy(t *testing.T) {
	client := &blockingCDNClient{release: make(chan struct{}), uploads: make(chan cdnUpload, 1)}
	close(client.release)
	withCDNClient(t, client)

	for i := 0; i < cap(cdnPublishSlots); i++ {
		cdnPublishSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < cap(cdnPublishSlots); i++ {
			<-cdnPublishSlots
		}
	})

	publishResponseToCDN(context.Background(), nil, "", cdnTestParams(), gin.H{"update_available": false})

	select {
	case upload := <-client.uploads:
		t.Fatalf("publish was not skipped while slots are busy: %q", upload.key)
	case <-time.After(200 * time.Millisecond):
	}
}

func cdnTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	server := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return rdb
}

func TestPublishResponseToCDNSkipsWhenEpochChanged(t *testing.T) {
	client := &blockingCDNClient{release: make(chan struct{}), uploads: make(chan cdnUpload, 1)}
	close(client.release)
	withCDNClient(t, client)

	rdb := cdnTestRedis(t)
	ctx := context.Background()
	epoch := ReadCDNEpoch(ctx, rdb, "admin", "app")
	// The upload that invalidates the CDN lands after the response was read but before it is published.
	BumpCDNEpoch(ctx, rdb, "admin", "app")

	publishResponseToCDN(ctx, rdb, epoch, cdnTestParams(), gin.H{"update_available": false})

	select {
	case upload := <-client.uploads:
		t.Fatalf("stale response was published to CDN: %q", upload.key)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPublishResponseToCDNPublishesWhenEpochUnchanged(t *testing.T) {
	client := &blockingCDNClient{release: make(chan struct{}), uploads: make(chan cdnUpload, 1)}
	close(client.release)
	withCDNClient(t, client)

	rdb := cdnTestRedis(t)
	ctx := context.Background()
	BumpCDNEpoch(ctx, rdb, "admin", "app")
	epoch := ReadCDNEpoch(ctx, rdb, "admin", "app")
	if epoch == "" {
		t.Fatal("epoch was not stored")
	}

	publishResponseToCDN(ctx, rdb, epoch, cdnTestParams(), gin.H{"update_available": true})

	select {
	case upload := <-client.uploads:
		if upload.key != "responses/admin/app/stable/darwin/arm64/manual/1.0.0.json" {
			t.Fatalf("unexpected key %q", upload.key)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("response was never published to CDN")
	}
}

type invalidatingCDNClient struct {
	utils.StorageClient
	rdb     *redis.Client
	uploads chan cdnUpload
	deletes chan string
}

func (c *invalidatingCDNClient) GetObjectETag(ctx context.Context, bucketName, objectKey string) (string, bool, error) {
	return "", false, nil
}

func (c *invalidatingCDNClient) UploadPublicObjectWithCacheControl(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType, cacheControl string) (string, error) {
	body, _ := io.ReadAll(fileReader)
	// The invalidation sweep lands while this object is being written.
	BumpCDNEpoch(context.Background(), c.rdb, "admin", "app")
	c.uploads <- cdnUpload{key: objectKey, body: string(body)}
	return "", nil
}

func (c *invalidatingCDNClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	c.deletes <- objectKey
	return nil
}

func TestPublishResponseToCDNRemovesObjectWrittenAfterInvalidation(t *testing.T) {
	rdb := cdnTestRedis(t)
	client := &invalidatingCDNClient{rdb: rdb, uploads: make(chan cdnUpload, 1), deletes: make(chan string, 1)}
	withCDNClient(t, client)

	ctx := context.Background()
	BumpCDNEpoch(ctx, rdb, "admin", "app")
	epoch := ReadCDNEpoch(ctx, rdb, "admin", "app")

	publishResponseToCDN(ctx, rdb, epoch, cdnTestParams(), gin.H{"update_available": true})

	select {
	case <-client.uploads:
	case <-time.After(2 * time.Second):
		t.Fatal("response was never published to CDN")
	}

	select {
	case key := <-client.deletes:
		if key != "responses/admin/app/stable/darwin/arm64/manual/1.0.0.json" {
			t.Fatalf("unexpected deleted key %q", key)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stale object written after invalidation was not removed")
	}
}

type redisLosingCDNClient struct {
	utils.StorageClient
	rdb     *redis.Client
	uploads chan cdnUpload
	deletes chan string
}

func (c *redisLosingCDNClient) GetObjectETag(ctx context.Context, bucketName, objectKey string) (string, bool, error) {
	return "", false, nil
}

func (c *redisLosingCDNClient) UploadPublicObjectWithCacheControl(ctx context.Context, bucketName, objectKey string, fileReader multipart.File, contentType, cacheControl string) (string, error) {
	body, _ := io.ReadAll(fileReader)
	// Redis goes away between the freshness check and the post-write re-check.
	c.rdb.Close()
	c.uploads <- cdnUpload{key: objectKey, body: string(body)}
	return "", nil
}

func (c *redisLosingCDNClient) DeleteObject(ctx context.Context, bucketName, objectKey string) error {
	c.deletes <- objectKey
	return nil
}

func TestPublishResponseToCDNKeepsObjectWhenEpochIsUnreadable(t *testing.T) {
	rdb := cdnTestRedis(t)
	client := &redisLosingCDNClient{rdb: rdb, uploads: make(chan cdnUpload, 1), deletes: make(chan string, 1)}
	withCDNClient(t, client)

	ctx := context.Background()
	BumpCDNEpoch(ctx, rdb, "admin", "app")
	epoch := ReadCDNEpoch(ctx, rdb, "admin", "app")

	publishResponseToCDN(ctx, rdb, epoch, cdnTestParams(), gin.H{"update_available": true})

	select {
	case <-client.uploads:
	case <-time.After(2 * time.Second):
		t.Fatal("response was never published to CDN")
	}

	select {
	case key := <-client.deletes:
		t.Fatalf("fresh object was deleted because the epoch could not be read: %q", key)
	case <-time.After(300 * time.Millisecond):
	}
}
