package info

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	db "faynoSync/mongod"
	"faynoSync/server/utils"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	vfDatabase    = "faynosync_velopack_feed_test"
	vfOwner       = "vfowner"
	vfStableToken = "vf-stable-token"
	vfBetaToken   = "vf-beta-token"
)

func vfSetup(t *testing.T) *gin.Engine {
	t.Helper()
	viper.SetConfigType("env")
	viper.SetConfigFile("../../../.env")
	if err := viper.ReadInConfig(); err != nil {
		t.Skipf("no .env: %v", err)
	}
	ctx := context.Background()
	client, conn := db.ConnectToDatabase(viper.GetString("MONGODB_URL_TESTS"))
	t.Cleanup(func() { client.Disconnect(ctx) })
	conn.Database = vfDatabase
	database := client.Database(vfDatabase)
	_ = database.Drop(ctx)
	t.Cleanup(func() { database.Drop(ctx) })
	vfSeed(t, ctx, database)

	repo := db.NewAppRepository(&conn, client)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/velopack/:owner/:app/:platform/:arch/*feed", func(c *gin.Context) {
		FindVelopackFeed(c, repo, database)
	})
	return router
}

func vfSeed(t *testing.T, ctx context.Context, database *mongo.Database) {
	t.Helper()
	stable, beta := primitive.NewObjectID(), primitive.NewObjectID()
	windows, x64 := primitive.NewObjectID(), primitive.NewObjectID()
	meta := []interface{}{
		bson.M{"_id": stable, "channel_name": "stable", "owner": vfOwner},
		bson.M{"_id": beta, "channel_name": "beta", "owner": vfOwner},
		bson.M{"_id": windows, "platform_name": "windows", "owner": vfOwner},
		bson.M{"_id": x64, "arch_id": "x64", "owner": vfOwner},
	}
	var versions []interface{}
	apps := []bson.M{
		{"app_name": "vfpublic", "private": false},
		{"app_name": "vfstrict", "private": true, "download_mode": utils.DownloadModeStrict},
		{"app_name": "vfunlisted", "private": true, "download_mode": utils.DownloadModeUnlisted},
	}
	var strictID primitive.ObjectID
	for _, app := range apps {
		id := primitive.NewObjectID()
		name := app["app_name"].(string)
		if name == "vfstrict" {
			strictID = id
		}
		app["_id"], app["owner"] = id, vfOwner
		meta = append(meta, app)
		file := name + "-1.0.0-full.nupkg"
		versions = append(versions, bson.M{
			"app_id": id, "version": "1.0.0", "channel_id": stable, "published": true, "owner": vfOwner,
			"artifacts": []bson.M{{
				"link": "https://s3/" + file, "platform": windows, "arch": x64, "package": ".nupkg",
				"velopack": bson.M{"type": "Full", "file_name": file, "sha1": "a", "sha256": "b", "size": 1},
			}},
		})
	}
	if _, err := database.Collection("apps_meta").InsertMany(ctx, meta); err != nil {
		t.Fatalf("seed apps_meta: %v", err)
	}
	if _, err := database.Collection("apps").InsertMany(ctx, versions); err != nil {
		t.Fatalf("seed apps: %v", err)
	}
	_, err := database.Collection("download_tokens").InsertMany(ctx, []interface{}{
		bson.M{"token_hash": utils.HashAPIToken(vfStableToken), "app_id": strictID, "channel_id": stable, "owner": vfOwner},
		bson.M{"token_hash": utils.HashAPIToken(vfBetaToken), "app_id": strictID, "channel_id": beta, "owner": vfOwner},
	})
	if err != nil {
		t.Fatalf("seed download_tokens: %v", err)
	}
}

func vfGet(router *gin.Engine, app, feed string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/velopack/"+vfOwner+"/"+app+"/windows/x64/"+feed, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestFindVelopackFeedPrivateGate(t *testing.T) {
	router := vfSetup(t)

	unknownFeed := vfGet(router, "vfmissing", "releases.stable.json", nil)
	unknownPkg := vfGet(router, "vfmissing", "vfmissing-1.0.0-full.nupkg", nil)
	if unknownFeed.Code != http.StatusOK || unknownPkg.Code != http.StatusNotFound {
		t.Fatalf("unknown app baseline: feed %d, package %d", unknownFeed.Code, unknownPkg.Code)
	}

	stableToken := map[string]string{utils.DownloadTokenHeader: vfStableToken}
	cases := []struct {
		name    string
		app     string
		headers map[string]string
		allowed bool
	}{
		{"public app is readable anonymously", "vfpublic", nil, true},
		{"unlisted app is readable anonymously", "vfunlisted", nil, true},
		{"strict app denies anonymous reads", "vfstrict", nil, false},
		{"strict app denies a token of another channel", "vfstrict", map[string]string{utils.DownloadTokenHeader: vfBetaToken}, false},
		{"strict app denies an invalid session", "vfstrict", map[string]string{"Authorization": "Bearer not-a-session"}, false},
		{"strict app allows a token of its channel", "vfstrict", stableToken, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := tc.app + "-1.0.0-full.nupkg"
			feed := vfGet(router, tc.app, "releases.stable.json", tc.headers)
			pkg := vfGet(router, tc.app, file, tc.headers)

			if tc.allowed {
				if feed.Code != http.StatusOK || !strings.Contains(feed.Body.String(), file) {
					t.Fatalf("feed: want %s listed, got %d %s", file, feed.Code, feed.Body.String())
				}
				if pkg.Code != http.StatusFound || pkg.Header().Get("Location") != "https://s3/"+file {
					t.Fatalf("package: want 302 to its link, got %d %q", pkg.Code, pkg.Header().Get("Location"))
				}
				return
			}
			if feed.Code != unknownFeed.Code || feed.Body.String() != unknownFeed.Body.String() {
				t.Fatalf("feed must look like an unknown app: got %d %s", feed.Code, feed.Body.String())
			}
			if pkg.Code != unknownPkg.Code || pkg.Body.String() != unknownPkg.Body.String() {
				t.Fatalf("package must look like an unknown app: got %d %s", pkg.Code, pkg.Body.String())
			}
		})
	}
}
