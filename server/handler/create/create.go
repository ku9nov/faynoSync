package create

import (
	"context"
	"encoding/json"
	db "faynoSync/mongod"
	"faynoSync/server/model"
	"faynoSync/server/utils"
	"faynoSync/server/utils/updaters"
	"net/http"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func CreateItem(c *gin.Context, repository db.AppRepository, itemType string) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Get username from JWT token
	owner, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "username not found in token"})
		return
	}

	var result interface{}
	var err error

	switch itemType {
	case "channel":
		var req model.CreateChannelRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		if err := utils.ValidateItemName(itemType, req.ChannelName); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		result, err = repository.CreateChannel(req.ChannelName, owner.(string), ctx)
	case "platform":
		var req model.CreatePlatformRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		if err := utils.ValidateItemName(itemType, req.PlatformName); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Validate updaters if provided
		if len(req.Updaters) > 0 {
			if err := updaters.ValidateUpdaters(req.Updaters); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		}
		result, err = repository.CreatePlatform(req.PlatformName, req.Updaters, owner.(string), ctx)
	case "arch":
		var req model.CreateArchRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		if err := utils.ValidateItemName(itemType, req.ArchID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		result, err = repository.CreateArch(req.ArchID, owner.(string), ctx)
	case "app":
		var logoLink string
		jsonData := c.PostForm("data")
		if jsonData == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No JSON data provided"})
			return
		}

		var params map[string]string
		if err := json.Unmarshal([]byte(jsonData), &params); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
			return
		}

		paramName := itemType
		paramValue, exists := params[paramName]
		if !exists || paramValue == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": paramName + " is required"})
			return
		}
		form, _ := c.MultipartForm()
		if form != nil {
			files := form.File["file"]
			if len(files) > 0 {
				file := files[0]
				logoLink, err = utils.UploadLogo(paramValue, owner.(string), file, c, viper.GetViper())
				if err != nil {
					logrus.Error(err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload logo to S3"})
					return
				}
			}
		}
		description := params["description"]
		private := utils.GetBoolParam(params["private"])
		result, err = repository.CreateApp(paramValue, logoLink, description, private, owner.(string), ctx)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item type"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var tag language.Tag
	titleCase := cases.Title(tag)

	capitalizedItemType := titleCase.String(itemType)
	c.JSON(http.StatusOK, gin.H{"create" + capitalizedItemType + "Result.Created": result})
}

func CreateChannel(c *gin.Context, repository db.AppRepository) {
	CreateItem(c, repository, "channel")
}

func CreatePlatform(c *gin.Context, repository db.AppRepository) {
	CreateItem(c, repository, "platform")
}

func CreateArch(c *gin.Context, repository db.AppRepository) {
	CreateItem(c, repository, "arch")
}

func CreateApp(c *gin.Context, repository db.AppRepository) {
	CreateItem(c, repository, "app")
}
