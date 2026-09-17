package utils

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/viper"
)

const (
	DownloadModeUnlisted = "unlisted"
	DownloadModeStrict   = "strict"

	DownloadTokenHeader = "X-Download-Token"

	privateLinkMarker = "/download?key="
)

// DefaultDownloadMode keeps ENABLE_PRIVATE_APP_DOWNLOADING meaningful only as the default for private apps that have no mode yet.
func DefaultDownloadMode(env *viper.Viper) string {
	if env.GetBool("ENABLE_PRIVATE_APP_DOWNLOADING") {
		return DownloadModeUnlisted
	}
	return DownloadModeStrict
}

func ValidateDownloadMode(mode string) error {
	if mode != DownloadModeUnlisted && mode != DownloadModeStrict {
		return fmt.Errorf("download_mode must be %q or %q", DownloadModeUnlisted, DownloadModeStrict)
	}
	return nil
}

var ErrPrivateCdnEdge = errors.New("cdn cannot be enabled for private apps")

// ValidatePrivateCdnEdge rejects cdn_edge on private apps: CDN responses are public, so they would publish the private app's versions and links.
func ValidatePrivateCdnEdge(private, cdnEdge bool) error {
	if private && cdnEdge {
		return ErrPrivateCdnEdge
	}
	return nil
}

// PrivateObjectKey returns the private-bucket key a /download link points to, or "" for any other link.
// It ignores the host part so that links stay resolvable after API_URL changes.
func PrivateObjectKey(link string) string {
	_, encodedKey, found := strings.Cut(link, privateLinkMarker)
	if !found {
		return ""
	}
	key, err := url.QueryUnescape(encodedKey)
	if err != nil {
		return ""
	}
	return key
}
