package velopack

import (
	"fmt"
	"net/url"
	"strings"
)

// BuildS3Key lays out velopack packages flat, in one folder per (owner, app,
// platform, arch): velopack/{owner}/{app}/{platform}/{arch}/{file}. Version and
// channel stay out of the path (they are already in the nupkg name)
func BuildS3Key(ctxQuery map[string]interface{}, owner string, fileName string) (string, string) {
	s3PathSegments := []string{fmt.Sprintf("velopack/%s", owner)}
	s3PathSegments = append(s3PathSegments, ctxQuery["app_name"].(string))
	if ctxQuery["platform"].(string) != "" {
		s3PathSegments = append(s3PathSegments, ctxQuery["platform"].(string))
	}
	if ctxQuery["arch"].(string) != "" {
		s3PathSegments = append(s3PathSegments, ctxQuery["arch"].(string))
	}
	s3PathSegments = append(s3PathSegments, fileName)

	encodedPath := url.PathEscape(strings.Join(s3PathSegments, "/"))
	link := fmt.Sprintf("%s/download?key=%s", ctxQuery["api_url"].(string), encodedPath)
	s3Key := strings.Join(s3PathSegments, "/")
	return link, s3Key
}
