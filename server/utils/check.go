package utils

import (
	"errors"
	"net/http/httputil"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func DumpRequest(c *gin.Context) {
	requestDump, err := httputil.DumpRequest(c.Request, true)
	if err != nil {
		logrus.Errorln("Error dumping request:", err)
	}
	logrus.Debugln("Request data:", string(requestDump))
}

func CheckPlatforms(input string, db *mongo.Database, ctx *gin.Context) error {
	if input == "" {
		filter := bson.M{"platform_name": bson.M{"$exists": true}}
		count, err := db.Collection("apps_meta").CountDocuments(ctx, filter)
		if err != nil {
			return err
		}

		if count > 0 {
			return errors.New("you have a created platforms, setting platform is required")
		}

		return nil
	}
	// Check if the platform exists in the database
	cursor, err := db.Collection("apps_meta").Find(ctx, bson.M{"platform_name": input})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	// Check if any documents were returned
	if !cursor.Next(ctx) {
		return errors.New("wrong name of platform. Platform does not exist")
	}

	// If a document was returned, the channel exists
	return nil
}

func CheckArchsLatest(input string, db *mongo.Database, ctx *gin.Context) (string, error) {
	if input == "" {
		filter := bson.M{"arch_id": bson.M{"$exists": true}}
		count, err := db.Collection("apps_meta").CountDocuments(ctx, filter)
		if err != nil {
			return "", err
		}

		if count > 0 {
			return "", nil
		}

		return "", nil
	} else {
		// Check if the channel exists in the database
		cursor, err := db.Collection("apps_meta").Find(ctx, bson.M{"arch_id": input})
		if err != nil {
			return "", err
		}
		defer cursor.Close(ctx)

		// Check if any documents were returned
		if !cursor.Next(ctx) {
			input = ""
		}
	}
	return input, nil
}

func CheckArchs(input string, db *mongo.Database, ctx *gin.Context) error {
	if input == "" {
		filter := bson.M{"arch_id": bson.M{"$exists": true}}
		count, err := db.Collection("apps_meta").CountDocuments(ctx, filter)
		if err != nil {
			return err
		}

		if count > 0 {
			return errors.New("you have a created archs, setting arch is required")
		}

		return nil
	}
	// Check if the channel exists in the database
	cursor, err := db.Collection("apps_meta").Find(ctx, bson.M{"arch_id": input})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	// Check if any documents were returned
	if !cursor.Next(ctx) {
		return errors.New("wrong name of arch. Arch does not exist")
	}

	// If a document was returned, the channel exists
	return nil
}

func CheckChannels(input string, db *mongo.Database, ctx *gin.Context) error {
	if input == "" {
		filter := bson.M{"channel_name": bson.M{"$exists": true}}
		count, err := db.Collection("apps_meta").CountDocuments(ctx, filter)
		if err != nil {
			return err
		}

		if count > 0 {
			return errors.New("you have a created channels, setting channel is required")
		}

		return nil
	}
	// Check if the channel exists in the database
	cursor, err := db.Collection("apps_meta").Find(ctx, bson.M{"channel_name": input})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	// Check if any documents were returned
	if !cursor.Next(ctx) {
		return errors.New("wrong name of channel. Channel does not exist")
	}

	// If a document was returned, the channel exists
	return nil
}

func CheckPlatformsLatest(input string, db *mongo.Database, ctx *gin.Context) (string, error) {
	if input == "" {
		filter := bson.M{"platform_name": bson.M{"$exists": true}}
		count, err := db.Collection("apps_meta").CountDocuments(ctx, filter)
		if err != nil {
			return "", err
		}

		if count > 0 {
			return "", nil
		}

		return "", nil
	} else {
		// Check if the platform exists in the database
		cursor, err := db.Collection("apps_meta").Find(ctx, bson.M{"platform_name": input})
		if err != nil {
			return "", err
		}
		defer cursor.Close(ctx)

		// Check if any documents were returned
		if !cursor.Next(ctx) {
			input = ""
		}

	}
	return input, nil
}

func CheckPrivate(input string, db *mongo.Database, ctx *gin.Context) (bool, error) {
	cursor, err := db.Collection("apps_meta").Find(ctx, bson.M{"app_name": input})
	if err != nil {
		return false, err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var document bson.M
		if err := cursor.Decode(&document); err != nil {
			logrus.Errorln("Error decoding document:", err)
			continue
		}
		if privateValue, ok := document["private"].(bool); ok {
			return privateValue, nil
		} else {
			return false, nil
		}
	}
	return false, nil
}
