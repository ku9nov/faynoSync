package updaters

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// BuildResponse builds response based on updater type
func BuildResponse(response gin.H, found bool, updaterType string) (gin.H, int) {
	logrus.Debugf("New version found: %v, Updater type: %s, Building response: %v", found, updaterType, response)

	switch updaterType {
	case "squirrel_darwin":
		if !found {
			// Return 204 No Content for squirrel_darwin when no update found
			return gin.H{"status": "no_content"}, 204
		}
		// For squirrel_darwin, return all fields but rename update_url_zip to url and exclude other update_url_ fields
		squirrelResponse := gin.H{}
		zipFound := false
		for key, value := range response {
			if key == "update_url_zip" {
				squirrelResponse["url"] = value
				zipFound = true
			} else if !strings.HasPrefix(key, "update_url_") {
				squirrelResponse[key] = value
			}
		}
		if !zipFound {
			// Return 204 No Content if update_url_zip is not found
			return gin.H{"status": "no_content"}, 204
		}
		return squirrelResponse, 200

	case "squirrel_windows":
		// Test stub for squirrel_windows
		return gin.H{"status": "test_stub", "updater": "squirrel_windows"}, 200

	case "sparkle":
		// Test stub for sparkle
		return gin.H{"status": "test_stub", "updater": "sparkle"}, 200

	case "electron-builder_linux":
		// Test stub for electron-builder_linux
		return gin.H{"status": "test_stub", "updater": "electron-builder_linux"}, 200

	case "electron-builder_windows":
		// Test stub for electron-builder_windows
		return gin.H{"status": "test_stub", "updater": "electron-builder_windows"}, 200

	case "electron-builder_darwin":
		// Test stub for electron-builder_darwin
		return gin.H{"status": "test_stub", "updater": "electron-builder_darwin"}, 200

	default:
		// Default to standard response
		return response, 200
	}
}
