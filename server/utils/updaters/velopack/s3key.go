package velopack

import (
	"fmt"
	"net/url"
	"strings"
)

func velopackBasePath(ctxQuery map[string]interface{}, owner string) []string {
	segments := []string{fmt.Sprintf("velopack/%s", owner), ctxQuery["app_name"].(string)}
	if ctxQuery["platform"].(string) != "" {
		segments = append(segments, ctxQuery["platform"].(string))
	}
	if ctxQuery["arch"].(string) != "" {
		segments = append(segments, ctxQuery["arch"].(string))
	}
	return segments
}

func IsInstallerFile(fileName string) bool {
	name := strings.ToLower(fileName)
	if strings.HasSuffix(name, ".nupkg") {
		return false
	}
	if strings.HasPrefix(name, "releases.") && strings.HasSuffix(name, ".json") {
		return false
	}
	return true
}

// InstallerVersionedName builds a collision-free installer name by appending
// version/platform/arch to the original stem, e.g.
// HelloVelopack-nightly-Setup.pkg -> HelloVelopack-nightly-Setup-1.2.3-amd64-x64.pkg
func InstallerVersionedName(fileName, version, platform, arch string) string {
	ext := ""
	if i := strings.LastIndex(fileName, "."); i > -1 {
		ext = fileName[i:]
	}
	name := strings.TrimSuffix(fileName, ext)
	for _, part := range []string{version, platform, arch} {
		if part != "" {
			name += "-" + part
		}
	}
	return name + ext
}

func InstallerVersionedKey(ctxQuery map[string]interface{}, owner, fileName string) string {
	versioned := InstallerVersionedName(fileName, ctxQuery["version"].(string), ctxQuery["platform"].(string), ctxQuery["arch"].(string))
	segments := append(velopackBasePath(ctxQuery, owner), "installers", versioned)
	return strings.Join(segments, "/")
}

func InstallerDefaultKey(ctxQuery map[string]interface{}, owner, fileName string) string {
	segments := append(velopackBasePath(ctxQuery, owner), fileName)
	return strings.Join(segments, "/")
}

// BuildS3Key lays out velopack packages flat, in one folder per (owner, app,
// platform, arch): velopack/{owner}/{app}/{platform}/{arch}/{file}. Installers
// are routed to the versioned installers/ copy so the persisted link is stable
// per version; the flat "latest" installer is materialized separately.
func BuildS3Key(ctxQuery map[string]interface{}, owner string, fileName string) (string, string) {
	segments := velopackBasePath(ctxQuery, owner)
	if IsInstallerFile(fileName) {
		versioned := InstallerVersionedName(fileName, ctxQuery["version"].(string), ctxQuery["platform"].(string), ctxQuery["arch"].(string))
		segments = append(segments, "installers", versioned)
	} else {
		segments = append(segments, fileName)
	}

	encodedPath := url.QueryEscape(strings.Join(segments, "/"))
	link := fmt.Sprintf("%s/download?key=%s", ctxQuery["api_url"].(string), encodedPath)
	s3Key := strings.Join(segments, "/")
	return link, s3Key
}
