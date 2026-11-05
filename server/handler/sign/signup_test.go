package sign

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"faynoSync/mongod"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// A new admin named like an existing team user would make ResolveRequestOwner
// map that admin to the team user's tenant.
// To verify: In SignUp check the username only against admins; test will fail (admin created).
func TestSignUp_UsernameOfTeamUser_Rejected(t *testing.T) {
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	client, configDB := mongod.ConnectToDatabase(mongoURL)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	db := client.Database(configDB.Database)
	ctx := context.Background()

	suffix := primitive.NewObjectID().Hex()[16:]
	owner, name := "signupowner"+suffix, "signupteam"+suffix
	_, err := db.Collection("team_users").InsertOne(ctx, bson.M{"username": name, "owner": owner})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.Collection("team_users").DeleteMany(ctx, bson.M{"owner": owner})
		_, _ = db.Collection("admins").DeleteMany(ctx, bson.M{"username": name})
	})
	t.Setenv("API_KEY", "signup-test-key")

	raw, err := json.Marshal(map[string]string{"username": name, "password": "p", "api_key": "signup-test-key"})
	require.NoError(t, err)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/signup", func(c *gin.Context) { SignUp(c, db, client, nil) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/signup", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code, w.Body.String())
	count, err := db.Collection("admins").CountDocuments(ctx, bson.M{"username": name})
	require.NoError(t, err)
	assert.Zero(t, count, "admin %q must not be created while a team user holds the name", name)
}
