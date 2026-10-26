package update

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type fakeS3 struct {
	mu   sync.Mutex
	puts map[string][]byte
}

func (s *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.puts[r.URL.Path] = body
		s.mu.Unlock()
		w.Header().Set("ETag", `"0"`)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *fakeS3) written() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]byte, len(s.puts))
	for k, v := range s.puts {
		out[k] = v
	}
	return out
}

// The storage client is cached per process for the global viper, so one fake
// endpoint serves every test in this package.
var (
	fakeS3Once   sync.Once
	sharedFakeS3 = &fakeS3{puts: map[string][]byte{}}
)

func useFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	fakeS3Once.Do(func() {
		srv := httptest.NewServer(sharedFakeS3)
		env := viper.GetViper()
		env.Set("STORAGE_DRIVER", "aws")
		env.Set("S3_API_ENDPOINT", srv.URL)
		env.Set("S3_ENDPOINT", srv.URL)
		env.Set("S3_FORCE_PATH_STYLE", true)
		env.Set("S3_REGION", "us-east-1")
		env.Set("S3_ACCESS_KEY", "test")
		env.Set("S3_SECRET_KEY", "test")
		env.Set("S3_BUCKET_NAME", "test-bucket")
		env.Set("S3_DISABLE_OBJECT_ACL", true)
	})
	sharedFakeS3.mu.Lock()
	sharedFakeS3.puts = map[string][]byte{}
	sharedFakeS3.mu.Unlock()
	return sharedFakeS3
}

func testRepository(t *testing.T) (mongod.AppRepository, *mongo.Database) {
	t.Helper()
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	client, configDB := mongod.ConnectToDatabase(mongoURL)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	return mongod.NewAppRepository(&configDB, client), client.Database(configDB.Database)
}

type uploadedFile struct{ name, content string }

const sparkleAppcastXML = `<?xml version="1.0" standalone="yes"?>
<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" version="2.0">
    <channel>
        <item>
            <title>1.0.0</title>
            <sparkle:version>1</sparkle:version>
            <enclosure url="http://cdn/MyApp-1.0.0.zip" length="10" type="application/octet-stream" sparkle:edSignature="SIG=="/>
        </item>
    </channel>
</rss>`

// A team user with apps.edit restricted to app A updates a version of app X
// through /apps/update. The grant must be checked before anything is written.
// To verify: In UpdateSpecificApp upload files before checking the team user's allowed apps; test will fail (object written under X).
func TestUpdateSpecificApp_TeamUserOutsideAllowedApps_NothingWritten(t *testing.T) {
	assertUpdateOutsideGrantWritesNothing(t, "linux", "electron-builder",
		uploadedFile{"latest.yml", "version: 1.0.0\npath: attacker-marker.exe\n"})
}

// Same as above for sparkle, whose appcast is also a managed feed key.
// To verify: In UpdateSpecificApp upload files before checking the team user's allowed apps; test will fail (appcast written under X).
func TestUpdateSpecificApp_TeamUserOutsideAllowedApps_Sparkle_NothingWritten(t *testing.T) {
	assertUpdateOutsideGrantWritesNothing(t, "macos", "sparkle",
		uploadedFile{"appcast.xml", sparkleAppcastXML}, uploadedFile{"MyApp-1.0.0.zip", "attacker-marker"})
}

func assertUpdateOutsideGrantWritesNothing(t *testing.T, platform, updater string, files ...uploadedFile) {
	t.Helper()
	repo, db := testRepository(t)
	s3 := useFakeS3(t)
	suffix := primitive.NewObjectID().Hex()[16:]
	owner := "upscope-admin-" + suffix
	ctx := utils.WithPrincipal(context.Background(), utils.Principal{Type: utils.PrincipalAdmin, Username: owner})
	teamUser := "upscope-team-" + suffix
	appA, appX := "upscopea"+suffix, "upscopex"+suffix

	for _, app := range []string{appA, appX} {
		_, err := repo.CreateApp(app, "", "", false, "", false, false, false, owner, ctx)
		require.NoError(t, err)
	}
	_, err := repo.CreateChannel("stable", owner, ctx)
	require.NoError(t, err)
	_, err = repo.CreatePlatform(platform, []model.Updater{{Type: updater, Default: true}}, owner, ctx)
	require.NoError(t, err)
	_, err = repo.CreateArch("x64", owner, ctx)
	require.NoError(t, err)

	var metaA, metaX, metaChannel struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	require.NoError(t, db.Collection("apps_meta").FindOne(ctx, bson.M{"app_name": appA, "owner": owner}).Decode(&metaA))
	require.NoError(t, db.Collection("apps_meta").FindOne(ctx, bson.M{"app_name": appX, "owner": owner}).Decode(&metaX))
	require.NoError(t, db.Collection("apps_meta").FindOne(ctx, bson.M{"channel_name": "stable", "owner": owner}).Decode(&metaChannel))
	versionX := primitive.NewObjectID()
	_, err = db.Collection("apps").InsertOne(ctx, bson.M{"_id": versionX, "app_id": metaX.ID, "version": "1.0.0", "channel_id": metaChannel.ID, "owner": owner, "artifacts": bson.A{}})
	require.NoError(t, err)
	_, err = db.Collection("team_users").InsertOne(ctx, bson.M{
		"_id": primitive.NewObjectID(), "username": teamUser, "owner": owner,
		"permissions": bson.M{"apps": bson.M{"edit": true, "allowed": []string{metaA.ID.Hex()}}},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.Collection("apps_meta").DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = db.Collection("apps").DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = db.Collection("team_users").DeleteMany(ctx, bson.M{"owner": owner})
	})

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	data, err := json.Marshal(map[string]string{
		"id": versionX.Hex(), "app_name": appX, "version": "1.0.0",
		"channel": "stable", "platform": platform, "arch": "x64", "updater": updater,
	})
	require.NoError(t, err)
	require.NoError(t, mw.WriteField("data", string(data)))
	for _, f := range files {
		part, err := mw.CreateFormFile("file", f.name)
		require.NoError(t, err)
		_, err = part.Write([]byte(f.content))
		require.NoError(t, err)
	}
	require.NoError(t, mw.Close())

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/apps/update",
		func(c *gin.Context) {
			var u struct {
				ID primitive.ObjectID `bson:"_id"`
			}
			_ = db.Collection("team_users").FindOne(c, bson.M{"username": teamUser}).Decode(&u)
			c.Set("username", teamUser)
			c.Request = c.Request.WithContext(utils.WithPrincipal(c.Request.Context(), utils.Principal{Type: utils.PrincipalTeam, ID: u.ID, Username: teamUser}))
		},
		utils.CheckPermission(utils.PermissionEdit, utils.ResourceApps, db),
		func(c *gin.Context) { UpdateSpecificApp(c, repo, db, rdb, false) },
	)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/apps/update", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.Empty(t, s3.written(), "no object may be written for an app outside the team user's grant")
}
