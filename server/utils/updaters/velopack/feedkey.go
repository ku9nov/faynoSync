package velopack

import "fmt"

func FeedObjectKey(owner, app, platform, arch, channel string) string {
	return fmt.Sprintf("velopack/%s/%s/%s/%s/releases.%s.json", owner, app, platform, arch, channel)
}
