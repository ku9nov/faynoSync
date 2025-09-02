package updaters

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// BuildResponse builds response based on updater type
func BuildResponse(response gin.H, found bool, possibleRollback bool, latestVersion string, updaterType string) (gin.H, int) {
	logrus.Debugf("New version found: %v, Updater type: %s, Building response: %v", found, updaterType, response)

	switch updaterType {
	case "squirrel_darwin":
		if !found && !possibleRollback {
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
		logrus.Debugf("Response for squirrel_windows: %v", response)
		// For squirrel_windows, redirect to update_url
		releaseURL := ""
		for key, value := range response {
			if key == "update_url" {
				logrus.Debugf("Found update_url: %s", value)
				releaseURL = value.(string)
				break
			}
		}
		logrus.Debugf("Return http redirect to Release URL: %s", releaseURL)
		// Return redirect response with RELEASES URL
		return gin.H{"status": "redirect", "url": releaseURL}, 302

	case "sparkle":
		// Test stub for sparkle
		return gin.H{"status": "test_stub", "updater": "sparkle"}, 200

	case "electron-builder":
		if !found && !possibleRollback {
			return gin.H{"status": "no_content"}, 204
		}
		logrus.Debugf("Response for electron-builder: %v", response)
		// For electron-builder, redirect to update_url_yml
		ymlFound := false
		ymlURL := ""
		for key, value := range response {
			if key == "update_url_yml" {
				logrus.Debugf("Found update_url_yml: %s", value)
				ymlURL = value.(string)
				ymlFound = true
				break
			}
		}
		if !ymlFound {
			// Return 204 No Content if update_url_yml is not found
			return gin.H{"status": "no_content"}, 204
		}
		// Return redirect response with yml URL
		return gin.H{"status": "redirect", "url": ymlURL}, 302

	case "tauri":
		if !found && !possibleRollback {
			return gin.H{"status": "no_content"}, 204
		}
		logrus.Debugf("Response for tauri: %v", response)
		logrus.Debugf("Latest version: %s", latestVersion)

		// For tauri, build specific response format
		tauriResponse := gin.H{}
		tauriResponse["version"] = latestVersion
		// Map response fields to tauri format
		for key, value := range response {
			switch {
			case key == "changelog":
				tauriResponse["notes"] = value
			case strings.HasPrefix(key, "update_url"):
				tauriResponse["url"] = value
			case key == "signature":
				tauriResponse["signature"] = value
			}
		}

		return tauriResponse, 200

	default:
		// Default to standard response
		logrus.Debugf("Default response: %v", response)
		return response, 200
	}
}

// BuildS3Key builds S3 key based on updater type
func BuildS3Key(ctxQuery map[string]interface{}, owner string, newFileName string, oldFileName string, updaterType string) (string, string) {
	logrus.Debugf("Building S3 key for updater type: %s", updaterType)

	switch updaterType {

	case "squirrel_windows":
		// Squirrel Windows specific S3 key structure
		logrus.Debugf("Squirrel Windows specific S3 key structure")
		s3PathSegments := []string{fmt.Sprintf("squirrel_windows/%s-%s", ctxQuery["app_name"].(string), owner)}
		s3PathSegments = append(s3PathSegments, ctxQuery["version"].(string))
		if ctxQuery["channel"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["channel"].(string))
		}
		if ctxQuery["platform"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["platform"].(string))
		}
		if ctxQuery["arch"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["arch"].(string))
		}
		s3PathSegments = append(s3PathSegments, oldFileName)

		encodedPath := url.PathEscape(strings.Join(s3PathSegments, "/"))
		link := fmt.Sprintf("%s/download?key=%s", ctxQuery["api_url"].(string), encodedPath)
		s3Key := strings.Join(s3PathSegments, "/")
		return link, s3Key
	case "sparkle":
		// Sparkle specific S3 key structure
		logrus.Debugf("Sparkle specific S3 key structure")
		fallthrough
	case "electron-builder":
		// Electron Builder specific S3 key structure
		logrus.Debugf("Electron Builder specific S3 key structure")
		s3PathSegments := []string{fmt.Sprintf("electron-builder/%s-%s", ctxQuery["app_name"].(string), owner)}
		s3PathSegments = append(s3PathSegments, ctxQuery["version"].(string))
		if ctxQuery["channel"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["channel"].(string))
		}
		if ctxQuery["platform"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["platform"].(string))
		}
		if ctxQuery["arch"].(string) != "" {
			s3PathSegments = append(s3PathSegments, ctxQuery["arch"].(string))
		}
		s3PathSegments = append(s3PathSegments, oldFileName)

		encodedPath := url.PathEscape(strings.Join(s3PathSegments, "/"))
		link := fmt.Sprintf("%s/download?key=%s", ctxQuery["api_url"].(string), encodedPath)
		s3Key := strings.Join(s3PathSegments, "/")
		return link, s3Key

	default:
		// Default S3 key structure (original logic from s3.go)
		logrus.Debugf("Default S3 key structure")
		s3PathSegments := []string{fmt.Sprintf("%s-%s", ctxQuery["app_name"].(string), owner)}
		if ctxQuery["channel"].(string) == "" && ctxQuery["platform"].(string) == "" && ctxQuery["arch"].(string) == "" {
			s3PathSegments = append(s3PathSegments, newFileName)
		} else {
			if ctxQuery["channel"].(string) != "" {
				s3PathSegments = append(s3PathSegments, ctxQuery["channel"].(string))
			}
			if ctxQuery["platform"].(string) != "" {
				s3PathSegments = append(s3PathSegments, ctxQuery["platform"].(string))
			}
			if ctxQuery["arch"].(string) != "" {
				s3PathSegments = append(s3PathSegments, ctxQuery["arch"].(string))
			}
			s3PathSegments = append(s3PathSegments, newFileName)
		}

		encodedPath := url.PathEscape(strings.Join(s3PathSegments, "/"))
		link := fmt.Sprintf("%s/download?key=%s", ctxQuery["api_url"].(string), encodedPath)
		s3Key := strings.Join(s3PathSegments, "/")
		return link, s3Key
	}
}
