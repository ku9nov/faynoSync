package team

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

// Online keys live in ONLINE_KEY_DIR/<admin>/<app>/; on a case-insensitive filesystem
// names that differ only by case share a directory.
// To verify: In UsernameTaken drop the case-insensitive collation; test will fail (200).
func TestCreateTeamUser_CaseVariantOfAdmin_Rejected(t *testing.T) {
	db := identityTestDB(t)
	attacker, victim := identityNames(t, db)
	variant := strings.ToUpper(victim)

	w := callAsAdmin(t, attacker, func(c *gin.Context) { CreateTeamUser(c, db) },
		map[string]any{"username": variant, "password": "p", "permissions": map[string]any{}})

	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	count, err := db.Collection("team_users").CountDocuments(context.Background(), bson.M{"username": variant})
	require.NoError(t, err)
	assert.Zero(t, count)
}

// To verify: In UsernameTaken drop the case-insensitive collation; test will fail (200).
func TestCreateTeamUser_CaseVariantOfTeamUser_Rejected(t *testing.T) {
	db := identityTestDB(t)
	attacker, _ := identityNames(t, db)
	w := callAsAdmin(t, attacker, func(c *gin.Context) { CreateTeamUser(c, db) },
		map[string]any{"username": attacker + "-ci", "password": "p", "permissions": map[string]any{}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = callAsAdmin(t, attacker, func(c *gin.Context) { CreateTeamUser(c, db) },
		map[string]any{"username": attacker + "-CI", "password": "p", "permissions": map[string]any{}})

	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

// To verify: In UsernameTaken drop the case-insensitive collation; test will fail (200, renamed).
func TestUpdateTeamUser_RenameToCaseVariantOfAdmin_Rejected(t *testing.T) {
	db := identityTestDB(t)
	attacker, victim := identityNames(t, db)
	w := callAsAdmin(t, attacker, func(c *gin.Context) { CreateTeamUser(c, db) },
		map[string]any{"username": attacker + "-ci", "password": "p", "permissions": map[string]any{}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	id := teamUserID(t, db, attacker+"-ci", attacker)

	w = callAsAdmin(t, attacker, func(c *gin.Context) { UpdateTeamUser(c, db) },
		map[string]any{"id": id, "username": strings.ToUpper(victim)})

	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.Equal(t, id, teamUserID(t, db, attacker+"-ci", attacker), "team user must keep its name")
}

// To verify: In UsernameTaken drop the excludeTeamUserID filter; test will fail (409).
func TestUpdateTeamUser_RenameToOwnCaseVariant_Allowed(t *testing.T) {
	db := identityTestDB(t)
	attacker, _ := identityNames(t, db)
	w := callAsAdmin(t, attacker, func(c *gin.Context) { CreateTeamUser(c, db) },
		map[string]any{"username": attacker + "-ci", "password": "p", "permissions": map[string]any{}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = callAsAdmin(t, attacker, func(c *gin.Context) { UpdateTeamUser(c, db) },
		map[string]any{"id": teamUserID(t, db, attacker+"-ci", attacker), "username": attacker + "-CI"})

	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
