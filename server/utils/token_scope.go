package utils

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func IsAPITokenRequest(c *gin.Context) bool {
	isAPIToken, exists := c.Get("is_api_token")
	if !exists {
		return false
	}
	apiTokenBool, ok := isAPIToken.(bool)
	return ok && apiTokenBool
}

func ValidateAPITokenAppScope(c *gin.Context, database *mongo.Database, owner, appName string) error {
	if !IsAPITokenRequest(c) {
		return nil
	}

	allowedAppsRaw, exists := c.Get("allowed_apps")
	if !exists {
		return fmt.Errorf("api token scope is missing")
	}

	allowedApps, ok := allowedAppsRaw.([]string)
	if !ok || len(allowedApps) == 0 {
		return fmt.Errorf("api token has no allowed applications")
	}

	allowedSet := make(map[string]struct{}, len(allowedApps))
	for _, appID := range allowedApps {
		allowedSet[appID] = struct{}{}
	}

	var appMeta struct {
		ID primitive.ObjectID `bson:"_id"`
	}

	metaCollection := database.Collection("apps_meta")
	if err := metaCollection.FindOne(
		c.Request.Context(),
		bson.M{"app_name": appName, "owner": owner},
	).Decode(&appMeta); err != nil {
		return fmt.Errorf("app_name not found in apps_meta collection or you don't have permission to access it")
	}

	if _, hasAccess := allowedSet[appMeta.ID.Hex()]; !hasAccess {
		return fmt.Errorf("api token has no access to this app")
	}

	return nil
}
