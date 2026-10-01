package info

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	db "faynoSync/mongod"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	ldDatabase = "faynosync_latest_download_test"
	ldOwner    = "ldowner"
	ldApp      = "ldapp"
)

type ldMeta struct {
	app, stable, beta, darwin, windows, arm64, x64 primitive.ObjectID
}

func ldSeed(t *testing.T, ctx context.Context, database *mongo.Database) {
	t.Helper()
	m := ldMeta{
		app: primitive.NewObjectID(), stable: primitive.NewObjectID(), beta: primitive.NewObjectID(),
		darwin: primitive.NewObjectID(), windows: primitive.NewObjectID(), arm64: primitive.NewObjectID(), x64: primitive.NewObjectID(),
	}
	_, err := database.Collection("apps_meta").InsertMany(ctx, []interface{}{
		bson.M{"_id": m.app, "app_name": ldApp, "owner": ldOwner},
		bson.M{"_id": m.stable, "channel_name": "stable", "owner": ldOwner},
		bson.M{"_id": m.beta, "channel_name": "beta", "owner": ldOwner},
		bson.M{"_id": m.darwin, "platform_name": "darwin", "owner": ldOwner},
		bson.M{"_id": m.windows, "platform_name": "windows", "owner": ldOwner},
		bson.M{"_id": m.arm64, "arch_id": "arm64", "owner": ldOwner},
		bson.M{"_id": m.x64, "arch_id": "x64", "owner": ldOwner},
	})
	if err != nil {
		t.Fatalf("seed apps_meta: %v", err)
	}

	artifact := func(platform, arch primitive.ObjectID, pkg string, isFeed bool) bson.M {
		return bson.M{"link": "https://s3/" + pkg, "platform": platform, "arch": arch, "package": pkg, "is_feed": isFeed}
	}
	version := func(v string, channel primitive.ObjectID, published bool, extra bson.M, artifacts ...bson.M) bson.M {
		doc := bson.M{"app_id": m.app, "version": v, "channel_id": channel, "published": published, "owner": ldOwner, "artifacts": artifacts}
		for k, val := range extra {
			doc[k] = val
		}
		return doc
	}
	_, err = database.Collection("apps").InsertMany(ctx, []interface{}{
		version("1.0.1", m.stable, true, nil, artifact(m.darwin, m.arm64, ".dmg", false), artifact(m.darwin, m.arm64, ".zip", false)),
		version("1.0.2", m.stable, true, nil, artifact(m.windows, m.x64, ".exe", false)),
		version("1.0.3", m.stable, true, bson.M{"rollout_percent": 100}, artifact(m.darwin, m.arm64, ".dmg", false), artifact(m.darwin, m.arm64, ".tar.gz", false)),
		version("1.0.4", m.stable, true, bson.M{"rollout_percent": 10}, artifact(m.darwin, m.arm64, ".dmg", false)),
		version("1.0.5", m.stable, false, nil, artifact(m.darwin, m.arm64, ".dmg", false)),
		version("1.0.6", m.stable, true, nil, artifact(m.darwin, m.arm64, ".nupkg", false), artifact(m.darwin, m.arm64, ".json", true), artifact(m.darwin, m.arm64, ".app.tar.gz", false)),
		version("1.0.10", m.stable, true, nil, artifact(m.windows, m.x64, ".exe", false), artifact(m.windows, m.x64, ".blockmap", false), artifact(m.windows, m.x64, "", true)),
		version("2.0.0", m.beta, true, nil, artifact(m.darwin, m.arm64, ".dmg", false)),
	})
	if err != nil {
		t.Fatalf("seed apps: %v", err)
	}
}

func ldSetup(t *testing.T) (context.Context, *mongo.Database, db.AppRepository) {
	t.Helper()
	viper.SetConfigType("env")
	viper.SetConfigFile("../../../.env")
	if err := viper.ReadInConfig(); err != nil {
		t.Skipf("no .env: %v", err)
	}
	ctx := context.Background()
	client, conn := db.ConnectToDatabase(viper.GetString("MONGODB_URL_TESTS"))
	t.Cleanup(func() { client.Disconnect(ctx) })
	conn.Database = ldDatabase
	database := client.Database(ldDatabase)
	_ = database.Drop(ctx)
	t.Cleanup(func() { database.Drop(ctx) })
	ldSeed(t, ctx, database)
	return ctx, database, db.NewAppRepository(&conn, client)
}

func TestFetchLatestVersionOfAppPerPlatform(t *testing.T) {
	ctx, _, repo := ldSetup(t)

	type pick struct {
		version  string
		packages []string
	}
	cases := []struct {
		name                string
		platform, arch, pkg string
		want                map[string]pick
	}{
		{
			name: "each platform from its own newest installer version",
			want: map[string]pick{
				"darwin/arm64": {"1.0.3", []string{".dmg", ".tar.gz"}},
				"windows/x64":  {"1.0.10", []string{".exe"}},
			},
		},
		{
			name:     "platform missing from newest release still resolves",
			platform: "darwin", arch: "arm64",
			want: map[string]pick{"darwin/arm64": {"1.0.3", []string{".dmg", ".tar.gz"}}},
		},
		{
			name:     "package falls back to the newest version that has it",
			platform: "darwin", arch: "arm64", pkg: "zip",
			want: map[string]pick{"darwin/arm64": {"1.0.1", []string{".zip"}}},
		},
		{
			name:     "non-installer package never matches",
			platform: "darwin", arch: "arm64", pkg: "nupkg",
			want: map[string]pick{},
		},
		{
			name:     "unknown platform",
			platform: "linux",
			want:     map[string]pick{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repo.FetchLatestVersionOfApp(ldApp, "stable", tc.platform, tc.arch, tc.pkg, ctx, ldOwner)
			if err != nil {
				t.Fatalf("FetchLatestVersionOfApp: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d tuples %+v, want %d", len(got), got, len(tc.want))
			}
			for _, d := range got {
				want, ok := tc.want[d.Platform+"/"+d.Arch]
				if !ok {
					t.Fatalf("unexpected tuple %s/%s", d.Platform, d.Arch)
				}
				if d.Version != want.version {
					t.Errorf("%s/%s version = %s, want %s", d.Platform, d.Arch, d.Version, want.version)
				}
				var pkgs []string
				for _, a := range d.Artifacts {
					pkgs = append(pkgs, a.Package)
				}
				if len(pkgs) != len(want.packages) {
					t.Fatalf("%s/%s packages = %v, want %v", d.Platform, d.Arch, pkgs, want.packages)
				}
				for i := range pkgs {
					if pkgs[i] != want.packages[i] {
						t.Errorf("%s/%s packages = %v, want %v", d.Platform, d.Arch, pkgs, want.packages)
					}
				}
			}
		})
	}
}

func TestFetchLatestVersionOfAppHandlerResponse(t *testing.T) {
	_, _, repo := ldSetup(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/apps/latest", func(c *gin.Context) { FetchLatestVersionOfApp(c, repo, nil, false) })

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apps/latest?app_name="+ldApp+"&channel=stable&owner="+ldOwner, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var body map[string]map[string]map[string]map[string]map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := body["stable"]["darwin"]["arm64"]["dmg"]; got["version"] != "1.0.3" || got["url"] != "https://s3/.dmg" {
		t.Errorf("darwin dmg = %v", got)
	}
	if got := body["stable"]["windows"]["x64"]["exe"]; got["version"] != "1.0.10" {
		t.Errorf("windows exe = %v", got)
	}
	if n := len(body["stable"]["windows"]["x64"]); n != 1 {
		t.Errorf("windows entries = %v, want exe only", body["stable"]["windows"]["x64"])
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apps/latest?app_name="+ldApp+"&channel=stable&platform=darwin&arch=arm64&package=zip&owner="+ldOwner, nil))
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://s3/.zip" {
		t.Errorf("package=zip = %d %q, want 302 to the 1.0.1 zip", w.Code, w.Header().Get("Location"))
	}
}
