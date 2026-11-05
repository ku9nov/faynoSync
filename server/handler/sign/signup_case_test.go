package sign

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"faynoSync/mongod"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Admins "Bob" and "bob" would share ONLINE_KEY_DIR/<admin>/ on a case-insensitive filesystem.
// To verify: In UsernameTaken drop the case-insensitive collation; test will fail (admin created).
func TestSignUp_CaseVariantOfExistingName_Rejected(t *testing.T) {
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	client, configDB := mongod.ConnectToDatabase(mongoURL)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	db := client.Database(configDB.Database)
	ctx := context.Background()

	suffix := primitive.NewObjectID().Hex()[16:]
	admin, teamUser := "signupcaseadmin"+suffix, "signupcaseteam"+suffix
	_, err := db.Collection("admins").InsertOne(ctx, bson.M{"username": admin})
	require.NoError(t, err)
	_, err = db.Collection("team_users").InsertOne(ctx, bson.M{"username": teamUser, "owner": admin})
	require.NoError(t, err)
	variants := []string{strings.ToUpper(admin), strings.ToUpper(teamUser)}
	t.Cleanup(func() {
		_, _ = db.Collection("admins").DeleteMany(ctx, bson.M{"username": bson.M{"$in": append(variants, admin)}})
		_, _ = db.Collection("team_users").DeleteMany(ctx, bson.M{"owner": admin})
	})
	t.Setenv("API_KEY", "signup-test-key")
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/signup", func(c *gin.Context) { SignUp(c, db, client, nil) })

	for _, name := range variants {
		raw, err := json.Marshal(map[string]string{"username": name, "password": "p", "api_key": "signup-test-key"})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/signup", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.NotEqual(t, http.StatusOK, w.Code, w.Body.String())
		count, err := db.Collection("admins").CountDocuments(ctx, bson.M{"username": name})
		require.NoError(t, err)
		assert.Zero(t, count, "admin %q must not be created next to a name that differs only by case", name)
	}
}
