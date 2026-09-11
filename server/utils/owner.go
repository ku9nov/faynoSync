package utils

import (
	"context"
	"errors"
	"net/http"

	"faynoSync/server/model"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// Maybe use the same flow for main API?

const ownerContextKey = "owner"

func ResolveRequestOwner(ctx context.Context, username string, database *mongo.Database) (string, error) {
	teamUsersCollection := database.Collection("team_users")
	var teamUser model.TeamUser
	err := teamUsersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&teamUser)
	if err == nil {
		return teamUser.Owner, nil
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return username, nil
	}
	return "", err
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

// EnsureTeamUserAppAccess verifies that a team user may act on the given app.
func EnsureTeamUserAppAccess(ctx context.Context, username, appName string, database *mongo.Database) error {
	var teamUser model.TeamUser
	err := database.Collection("team_users").FindOne(ctx, bson.M{"username": username}).Decode(&teamUser)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil
	}
	if err != nil {
		return err
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
			return errors.New("you don't have access to this app")
		}
		return err
	}

	for _, allowedAppID := range teamUser.Permissions.Apps.Allowed {
		if allowedAppID == appMeta.ID.Hex() {
			return nil
		}
	}

	return errors.New("you don't have access to this app")
}

func GetOwnerFromContext(c *gin.Context) (string, error) {
	if owner, exists := c.Get(ownerContextKey); exists {
		ownerString, ok := owner.(string)
		if ok && ownerString != "" {
			return ownerString, nil
		}
	}

	return GetUsernameFromContext(c)
}
