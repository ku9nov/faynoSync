package team

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

// '/' is a path separator in storage keys and online key dirs; '-' stays allowed for team users (e.g. "name-qa").
// To verify: In CreateTeamUser accept any username; test will fail (200).
func TestCreateTeamUser_UsernameWithSlash_Rejected(t *testing.T) {
	db := identityTestDB(t)
	admin, _ := identityNames(t, db)
	name := admin + "/qa"

	w := callAsAdmin(t, admin, func(c *gin.Context) { CreateTeamUser(c, db) },
		map[string]any{"username": name, "password": "p", "permissions": map[string]any{}})

	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	count, err := db.Collection("team_users").CountDocuments(context.Background(), bson.M{"username": name})
	require.NoError(t, err)
	assert.Zero(t, count)
}

// To verify: In UpdateTeamUser accept any new username; test will fail (renamed).
func TestUpdateTeamUser_RenameWithSlash_Rejected(t *testing.T) {
	db := identityTestDB(t)
	admin, _ := identityNames(t, db)
	w := callAsAdmin(t, admin, func(c *gin.Context) { CreateTeamUser(c, db) },
		map[string]any{"username": admin + "-qa", "password": "p", "permissions": map[string]any{}})
	require.Equal(t, http.StatusOK, w.Code, "a hyphen must stay allowed in team usernames: %s", w.Body.String())

	w = callAsAdmin(t, admin, func(c *gin.Context) { UpdateTeamUser(c, db) },
		map[string]any{"id": teamUserID(t, db, admin+"-qa", admin), "username": admin + "/qa"})

	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	count, err := db.Collection("team_users").CountDocuments(context.Background(), bson.M{"username": admin + "-qa"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "team user must keep its name")
}
