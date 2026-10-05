package dashboard

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

const BasePath = "/dashboard"

// ui/.gitkeep keeps the embed pattern valid when the dashboard has not been built (plain `go build`, unit tests).
//
//go:embed all:ui
var uiFS embed.FS

const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: https: http:; font-src 'self' data:; connect-src 'self'; object-src 'none'; " +
	"base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

type Config struct {
	TUFMetadataURL string `json:"tufMetadataURL"`
}

func Register(router *gin.Engine, config Config) {
	files, err := fs.Sub(uiFS, "ui/dist")
	if err != nil {
		logrus.Fatalf("Failed to load embedded dashboard: %v", err)
	}
	if _, err := fs.Stat(files, "index.html"); err != nil {
		logrus.Warnln("Dashboard is not built into this binary; /dashboard/ returns 503. Run `yarn build` in dashboard/ before `go build`")
	}

	redirect := func(c *gin.Context) {
		c.Redirect(http.StatusFound, BasePath+"/")
	}
	handler := func(c *gin.Context) {
		serve(c, files, config)
	}
	// gin does not route HEAD to GET handlers; uptime checks and `curl -I` use HEAD
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		router.Handle(method, "/", redirect)
		router.Handle(method, BasePath+"/*filepath", handler)
	}
}

func serve(c *gin.Context, files fs.FS, config Config) {
	c.Header("Content-Security-Policy", contentSecurityPolicy)
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Referrer-Policy", "same-origin")

	name := strings.TrimPrefix(path.Clean(c.Param("filepath")), "/")

	if name == "config.json" {
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, config)
		return
	}

	if name != "" && name != "index.html" {
		if data, err := fs.ReadFile(files, name); err == nil {
			cacheControl := "no-cache"
			if strings.HasPrefix(name, "assets/") {
				cacheControl = "public, max-age=31536000, immutable"
			}
			c.Header("Cache-Control", cacheControl)
			c.Data(http.StatusOK, contentType(name), data)
			return
		}
		// A missing hashed asset must not fall back to index.html, or the browser parses HTML as JS/CSS
		if strings.HasPrefix(name, "assets/") {
			c.Status(http.StatusNotFound)
			return
		}
	}

	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		c.String(http.StatusServiceUnavailable, "Dashboard is not built into this binary.")
		return
	}
	c.Header("Cache-Control", "no-cache")
	c.Data(http.StatusOK, "text/html; charset=utf-8", index)
}

// Go's built-in MIME table has no font types and the image may have no /etc/mime.types
var fontTypes = map[string]string{
	".woff2": "font/woff2",
	".woff":  "font/woff",
}

func contentType(name string) string {
	ext := path.Ext(name)
	if t, ok := fontTypes[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	return "application/octet-stream"
}
