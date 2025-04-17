package create

import (
	"context"
	"encoding/json"
	db "faynoSync/mongod"
	"faynoSync/server/utils"
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
	if err := utils.ValidateItemName(itemType, paramValue); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var result interface{}
	var err error

	switch itemType {
	case "channel":
		result, err = repository.CreateChannel(paramValue, owner.(string), ctx)
	case "platform":
		result, err = repository.CreatePlatform(paramValue, owner.(string), ctx)
	case "arch":
		result, err = repository.CreateArch(paramValue, owner.(string), ctx)
	case "app":
		var logoLink string
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
