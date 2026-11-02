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

// Admin names are storage key segments ("<app>-<owner>/", "<owner>/<app>/"), so '-' and '/'
// make keys of different tenants collide.
// To verify: In SignUp accept any username; test will fail (admin created).
func TestSignUp_UsernameWithKeySeparator_Rejected(t *testing.T) {
	mongoURL := os.Getenv("MONGODB_URL_TESTS")
	if mongoURL == "" {
		t.Skip("MONGODB_URL_TESTS not set, skipping Mongo-dependent test")
	}
	client, configDB := mongod.ConnectToDatabase(mongoURL)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	db := client.Database(configDB.Database)
	ctx := context.Background()

	suffix := primitive.NewObjectID().Hex()[16:]
	names := []string{"x-bob" + suffix, "x/bob" + suffix}
	t.Cleanup(func() {
		_, _ = db.Collection("admins").DeleteMany(ctx, bson.M{"username": bson.M{"$in": names}})
	})
	t.Setenv("API_KEY", "signup-test-key")
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/signup", func(c *gin.Context) { SignUp(c, db, client, nil) })

	for _, name := range names {
		raw, err := json.Marshal(map[string]string{"username": name, "password": "p", "api_key": "signup-test-key"})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/signup", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "%s: %s", name, w.Body.String())
		count, err := db.Collection("admins").CountDocuments(ctx, bson.M{"username": name})
		require.NoError(t, err)
		assert.Zero(t, count, "admin %q must not be created", name)
	}
}
