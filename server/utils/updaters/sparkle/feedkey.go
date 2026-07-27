package sparkle

import "strings"

func AppcastObjectKey(owner, app, platform, arch, channel string) string {
	segments := []string{"sparkle", owner, app}
	if platform != "" {
		segments = append(segments, platform)
	}
	if arch != "" {
		segments = append(segments, arch)
	}
	fileName := "appcast.xml"
	if channel != "" {
		fileName = "appcast." + channel + ".xml"
	}
	return strings.Join(append(segments, fileName), "/")
}
