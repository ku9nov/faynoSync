package velopack

// CapAtVersion keeps only releases with version <= maxVersion, forcing the client
// to step through a mandatory intermediate version.
func CapAtVersion(releases []Release, maxVersion string, cmp func(a, b string) int) []Release {
	if maxVersion == "" {
		return releases
	}

	capped := make([]Release, 0, len(releases))
	for _, r := range releases {
		if cmp(r.Version, maxVersion) <= 0 {
			capped = append(capped, r)
		}
	}
	return capped
}
