package updaters

import "strings"

var NonInstallerPackages = []string{
	"nupkg",
	"delta",
	"blockmap",
	"sig",
	"app.tar.gz",
	"appimage.tar.gz",
	"nsis.zip",
	"msi.zip",
}

// IsInstallerArtifact takes the package without its leading dot, in any case.
func IsInstallerArtifact(packageType string, isFeed bool) bool {
	if isFeed {
		return false
	}
	packageType = strings.ToLower(packageType)
	for _, pkg := range NonInstallerPackages {
		if packageType == pkg {
			return false
		}
	}
	return true
}
