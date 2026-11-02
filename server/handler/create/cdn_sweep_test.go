package create

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"faynoSync/mongod"
	"faynoSync/server/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// listingS3 is a path-style S3 endpoint with PUT, ListObjectsV2 and DeleteObjects.
type listingS3 struct {
	mu      sync.Mutex
	objects map[string]bool
}

func (s *listingS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(path, "/")
	switch {
	case r.Method == http.MethodPost && r.URL.Query().Has("delete"):
		var req struct {
			Objects []struct {
				Key string `xml:"Key"`
			} `xml:"Object"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = xml.Unmarshal(body, &req)
		for _, o := range req.Objects {
			delete(s.objects, bucket+"/"+o.Key)
		}
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><DeleteResult></DeleteResult>`)
	case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		prefix := r.URL.Query().Get("prefix")
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>false</IsTruncated>`)
		for _, k := range s.keysLocked(bucket + "/" + prefix) {
			fmt.Fprintf(&b, "<Contents><Key>%s</Key></Contents>", strings.TrimPrefix(k, bucket+"/"))
		}
		b.WriteString(`</ListBucketResult>`)
		fmt.Fprint(w, b.String())
	case r.Method == http.MethodPut:
		s.objects[bucket+"/"+key] = true
		w.Header().Set("ETag", `"0"`)
	case r.Method == http.MethodDelete:
		delete(s.objects, bucket+"/"+key)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *listingS3) keysLocked(prefix string) []string {
	var keys []string
	for k := range s.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func (s *listingS3) keys(prefix string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keysLocked(prefix)
}

// Response copies published while cdn_edge was on (or before the v2.3.0 backfill turned it off
// for private apps) must still be swept when the flag is now off.
// To verify: In InvalidateAppCaches sweep only when the app's current cdn_edge flag is true; test will fail (objects kept).
func TestInvalidateAppCaches_SweepsCDNResponsesWhenFlagIsOff(t *testing.T) {
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	client, configDB := mongod.ConnectToDatabase(mongoURL)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	db := client.Database(configDB.Database)
	repo := mongod.NewAppRepository(&configDB, client)
	owner := "cdnsweep" + primitive.NewObjectID().Hex()[16:]
	ctx := utils.WithPrincipal(context.Background(), utils.Principal{Type: utils.PrincipalAdmin, Username: owner})
	t.Cleanup(func() { _, _ = db.Collection("apps_meta").DeleteMany(context.Background(), bson.M{"owner": owner}) })

	s3 := &listingS3{objects: map[string]bool{}}
	srv := httptest.NewServer(s3)
	t.Cleanup(srv.Close)
	env := viper.New()
	for k, v := range map[string]any{
		"STORAGE_DRIVER": "aws", "S3_API_ENDPOINT": srv.URL, "S3_ENDPOINT": srv.URL, "S3_FORCE_PATH_STYLE": true,
		"S3_REGION": "us-east-1", "S3_ACCESS_KEY": "test", "S3_SECRET_KEY": "test",
		"S3_BUCKET_NAME": "public", "S3_BUCKET_NAME_CDN": "cdn", "S3_DISABLE_OBJECT_ACL": true,
	} {
		env.Set(k, v)
	}
	rdb := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})

	for name, private := range map[string]bool{"public app with cdn off": false, "private app": true} {
		t.Run(name, func(t *testing.T) {
			appName := fmt.Sprintf("%s%t", owner, private)
			_, err := repo.CreateApp(appName, "", "", private, "", false, false, false, owner, ctx)
			require.NoError(t, err)
			stale := fmt.Sprintf("cdn/responses/%s/%s/stable/linux/x64/manual/1.0.0.json", owner, appName)
			other := fmt.Sprintf("cdn/responses/%s/%sother/stable/linux/x64/manual/1.0.0.json", owner, appName)
			s3.mu.Lock()
			s3.objects[stale], s3.objects[other] = true, true
			s3.mu.Unlock()

			InvalidateAppCaches(context.Background(), db, rdb, false, owner, appName, []string{"stable"}, env)

			assert.Empty(t, s3.keys(fmt.Sprintf("cdn/responses/%s/%s/", owner, appName)), "stale public CDN responses must be removed")
			assert.Equal(t, []string{other}, s3.keys(other), "other apps' responses must stay")
		})
	}
}
