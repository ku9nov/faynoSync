package create

import (
	"context"
	"encoding/json"
	db "faynoSync/mongod"
	"net/http"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/gin-gonic/gin"
)

func CreateItem(c *gin.Context, repository db.AppRepository, itemType string) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

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

	var result interface{}
	var err error

	switch itemType {
	case "channel":
		result, err = repository.CreateChannel(paramValue, ctx)
	case "platform":
		result, err = repository.CreatePlatform(paramValue, ctx)
	case "arch":
		result, err = repository.CreateArch(paramValue, ctx)
	case "app":
		result, err = repository.CreateApp(paramValue, ctx)
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
