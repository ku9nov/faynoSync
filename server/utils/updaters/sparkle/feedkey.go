package sparkle

import "fmt"

func AppcastObjectKey(owner, app, platform, arch, channel string) string {
	return fmt.Sprintf("sparkle/%s/%s/%s/%s/appcast.%s.xml", owner, app, platform, arch, channel)
}
