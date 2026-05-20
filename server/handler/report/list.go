package report

import (
	"context"
	db "faynoSync/mongod"
	"faynoSync/server/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func ListReportKeys(c *gin.Context, repository db.AppRepository) {
	requester, err := utils.GetUsernameFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	reportKeys, err := repository.ListReportKeys(requester, ctx)
	if err != nil {
		logrus.Errorf("Failed to list report keys: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"report_keys": reportKeys})
}
