package utils

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Maybe use the same flow for main API?

const ownerContextKey = "owner"

// ResolveRequestOwner resolves the tenant of the principal in ctx; username must be
// that principal's name and is never looked up on its own.
func ResolveRequestOwner(ctx context.Context, username string, database *mongo.Database) (string, error) {
	principal, ok := PrincipalFromContext(ctx)
	if !ok {
		return "", errNoPrincipal
	}
	if principal.Username != username {
		return "", errors.New("username does not match the authenticated principal")
	}
	teamUser, err := CallerTeamUser(ctx, database)
	if err != nil {
		return "", err
	}
	if teamUser != nil {
		return teamUser.Owner, nil
	}
	return principal.Username, nil
}

func ResolveOwnerMiddleware(database *mongo.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, err := GetUsernameFromContext(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		owner, err := ResolveRequestOwner(c.Request.Context(), username, database)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve owner"})
			c.Abort()
			return
		}

		c.Set(ownerContextKey, owner)
		c.Next()
	}
}

// ErrAccessDenied matches the refusals of EnsureTeamUser*; any other error they return is internal.
var ErrAccessDenied = errors.New("access denied")

type accessDeniedError struct{ entity string }

func (e accessDeniedError) Error() string { return "you don't have access to this " + e.entity }

func (e accessDeniedError) Is(target error) bool { return target == ErrAccessDenied }

// RespondTeamAccessError answers a failed EnsureTeamUser* check without exposing internal errors.
func RespondTeamAccessError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrAccessDenied):
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case errors.Is(err, errSessionRevoked):
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check access"})
	}
}

// EnsureTeamUserAppAccess verifies that a team user may act on the given app.
func EnsureTeamUserAppAccess(ctx context.Context, appName string, database *mongo.Database) error {
	teamUser, err := CallerTeamUser(ctx, database)
	if err != nil {
		return err
	}
	if teamUser == nil {
		return nil
	}

	var appMeta struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	err = database.Collection("apps_meta").FindOne(ctx, bson.M{
		"app_name": appName,
		"owner":    teamUser.Owner,
	}).Decode(&appMeta)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return accessDeniedError{"app"}
		}
		return err
	}

	for _, allowedAppID := range teamUser.Permissions.Apps.Allowed {
		if allowedAppID == appMeta.ID.Hex() {
			return nil
		}
	}

	return accessDeniedError{"app"}
}

// EnsureTeamUserUploadAccess applies the app, channel, platform and arch allowed lists that
// repository.Upload enforces, so a denied upload is rejected before anything reaches storage.
func EnsureTeamUserUploadAccess(ctx context.Context, params map[string]interface{}, database *mongo.Database) error {
	teamUser, err := CallerTeamUser(ctx, database)
	if err != nil {
		return err
	}
	if teamUser == nil {
		return nil
	}

	checks := []struct {
		field, param, entity string
		allowed              []string
	}{
		{"app_name", "app_name", "app", teamUser.Permissions.Apps.Allowed},
		{"channel_name", "channel", "channel", teamUser.Permissions.Channels.Allowed},
		{"platform_name", "platform", "platform", teamUser.Permissions.Platforms.Allowed},
		{"arch_id", "arch", "architecture", teamUser.Permissions.Archs.Allowed},
	}
	for _, check := range checks {
		value, _ := params[check.param].(string)
		// Channel, platform and arch are optional, and repository.Upload skips them when empty.
		if value == "" && check.param != "app_name" {
			continue
		}
		var meta struct {
			ID primitive.ObjectID `bson:"_id"`
		}
		err := database.Collection("apps_meta").FindOne(ctx, bson.M{check.field: value, "owner": teamUser.Owner}).Decode(&meta)
		if errors.Is(err, mongo.ErrNoDocuments) {
			return accessDeniedError{check.entity}
		}
		if err != nil {
			return err
		}
		if !slices.Contains(check.allowed, meta.ID.Hex()) {
			return accessDeniedError{check.entity}
		}
	}
	return nil
}

func GetOwnerFromContext(c *gin.Context) (string, error) {
	if owner, exists := c.Get(ownerContextKey); exists {
		ownerString, ok := owner.(string)
		if ok && ownerString != "" {
			return ownerString, nil
		}
	}

	if principal, ok := PrincipalFromContext(c.Request.Context()); ok && principal.Type == PrincipalAdmin {
		return principal.Username, nil
	}
	return "", errors.New("owner not found in context")
}

// CaseInsensitiveCollation compares names the way a case-insensitive filesystem would.
var CaseInsensitiveCollation = &options.Collation{Locale: "en", Strength: 2, Normalization: true}

// UsernameTaken reports whether username, compared case-insensitively, belongs to any admin or team user:
// online keys live in ONLINE_KEY_DIR/<admin>/, which a case-insensitive filesystem cannot tell apart.
func UsernameTaken(ctx context.Context, username string, excludeTeamUserID *primitive.ObjectID, database *mongo.Database) (bool, error) {
	caseInsensitive := options.FindOne().SetCollation(CaseInsensitiveCollation)
	err := database.Collection("admins").FindOne(ctx, bson.M{"username": username}, caseInsensitive).Err()
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return false, err
	}

	filter := bson.M{"username": username}
	if excludeTeamUserID != nil {
		filter["_id"] = bson.M{"$ne": *excludeTeamUserID}
	}
	err = database.Collection("team_users").FindOne(ctx, filter, caseInsensitive).Err()
	if err == nil {
		return true, nil
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return false, nil
	}
	return false, err
}
