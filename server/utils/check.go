package utils

import (
	"errors"
	"net/http/httputil"
	"strings"

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

func CheckPlatformsLatest(input string, updater string, db *mongo.Database, ctx *gin.Context) (string, string, error) {
	logrus.Debugf("CheckPlatformsLatest called with input: '%s', updater: '%s'", input, updater)

	if input == "" {
		logrus.Debug("Input is empty, checking for any platforms with platform_name field")
		filter := bson.M{"platform_name": bson.M{"$exists": true}}
		count, err := db.Collection("apps_meta").CountDocuments(ctx, filter)
		if err != nil {
			logrus.Debugf("Error counting documents: %v", err)
			return "", "", err
		}

		logrus.Debugf("Found %d documents with platform_name field", count)
		if count > 0 {
			logrus.Debug("Returning empty strings as platforms exist")
			return "", "", nil
		}

		logrus.Debug("No platforms found, returning empty strings")
		return "", "", nil
	} else {
		logrus.Debugf("Checking if platform '%s' exists in database", input)
		// Check if the platform exists in the database
		cursor, err := db.Collection("apps_meta").Find(ctx, bson.M{"platform_name": input})
		if err != nil {
			logrus.Debugf("Error finding platform '%s': %v", input, err)
			return "", "", err
		}
		defer cursor.Close(ctx)

		// Check if any documents were returned
		if !cursor.Next(ctx) {
			logrus.Debugf("Platform '%s' not found, setting input to empty", input)
			input = ""
		} else {
			logrus.Debugf("Platform '%s' found, proceeding with updater logic", input)
			cursor.Close(ctx)
			cursor, err = db.Collection("apps_meta").Find(ctx, bson.M{"platform_name": input})
			if err != nil {
				logrus.Debugf("Error finding platform '%s' for updater check: %v", input, err)
				return "", "", err
			}
			defer cursor.Close(ctx)

			// Handle updater logic
			if updater == "" {
				logrus.Debug("Updater is empty, looking for default updater")
				// If updater is empty, return default updater
				for cursor.Next(ctx) {
					var document bson.M
					if err := cursor.Decode(&document); err != nil {
						logrus.Debugf("Error decoding document: %v", err)
						continue
					}
					if updaters, ok := document["updaters"].(bson.A); ok {
						logrus.Debugf("Found %d updaters in document", len(updaters))
						for _, u := range updaters {
							if updaterObj, ok := u.(bson.M); ok {
								if isDefault, ok := updaterObj["default"].(bool); ok && isDefault {
									if updaterType, ok := updaterObj["type"].(string); ok {
										logrus.Debugf("Found default updater: %s", updaterType)
										return input, updaterType, nil
									}
								}
							}
						}
					} else {
						logrus.Debug("No updaters field found in document")
					}
				}
				logrus.Debug("No default updater found, returning empty updater")
				return input, "", nil
			} else {
				logrus.Debugf("Looking for specific updater: '%s'", updater)
				// If updater is specified, check if it exists
				foundUpdater := ""
				for cursor.Next(ctx) {
					var document bson.M
					if err := cursor.Decode(&document); err != nil {
						logrus.Debugf("Error decoding document: %v", err)
						continue
					}
					if updaters, ok := document["updaters"].(bson.A); ok {
						logrus.Debugf("Found %d updaters in document", len(updaters))
						for _, u := range updaters {
							if updaterObj, ok := u.(bson.M); ok {
								if updaterType, ok := updaterObj["type"].(string); ok {
									logrus.Debugf("Checking updater type: '%s' against requested: '%s'", updaterType, updater)

									if updaterType == updater {
										logrus.Debugf("Exact match found for updater: %s", updaterType)
										foundUpdater = updaterType
										break
									}
									// Check for prefix match (e.g., "squirrel" matches "squirrel_darwin")
									if strings.HasPrefix(updaterType, updater+"_") {
										logrus.Debugf("Prefix match found for updater: %s (matches %s)", updaterType, updater)
										foundUpdater = updaterType
										break
									}
								}
							}
						}
					} else {
						logrus.Debug("No updaters field found in document")
					}
				}

				if foundUpdater != "" {
					logrus.Debugf("Returning found updater: %s", foundUpdater)
					return input, foundUpdater, nil
				} else {
					logrus.Debugf("Updater '%s' not supported for platform '%s'", updater, input)
					return input, "updater not supported", nil
				}
			}
		}
	}
	logrus.Debug("Returning default values (input: '', updater: '')")
	return input, "", nil
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
