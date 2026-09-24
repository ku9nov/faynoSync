package sparkle

import (
	"fmt"
	"strings"
)

type FileValidator struct {
	updaterType string
}

func NewFileValidator(updaterType string) *FileValidator {
	return &FileValidator{updaterType: updaterType}
}

func (v *FileValidator) Validate(fileNames []string) error {
	appcastCount := 0
	hasFull := false

	for _, fileName := range fileNames {
		name := strings.ToLower(fileName)
		if IsAppcastFile(name) {
			appcastCount++
			continue
		}
		if isFullArchive(name) {
			hasFull = true
		}
		// .delta artifacts are accepted implicitly (referenced by <sparkle:deltas>)
	}

	if appcastCount != 1 {
		return fmt.Errorf("sparkle updater requires exactly one appcast*.xml feed file. Please include a single appcast.*.xml in your upload")
	}
	if !hasFull {
		return fmt.Errorf("sparkle updater requires at least one full archive (.zip/.dmg/.tar.*/.aar). Please include a full package in your upload")
	}

	return nil
}

func (v *FileValidator) IsFeedFile(fileName string) bool {
	return IsAppcastFile(fileName)
}

func (v *FileValidator) GetUpdaterType() string {
	return v.updaterType
}

// IsAppcastFile reports whether an uploaded file is the Sparkle appcast feed.
func IsAppcastFile(fileName string) bool {
	name := strings.ToLower(fileName)
	return strings.HasPrefix(name, "appcast") && strings.HasSuffix(name, ".xml")
}

// ValidateArchivesInAppcast ensures every uploaded archive/delta has a matching
// <enclosure> in the parsed appcast. Without this an archive whose version is
// absent from the appcast (e.g. a stale appcast) would be stored silently
// without Sparkle metadata and never appear in the materialized feed.
func ValidateArchivesInAppcast(fileNames []string, metas map[string]SparkleMeta) error {
	var missing []string
	for _, fileName := range fileNames {
		name := strings.ToLower(fileName)
		if !isFullArchive(name) && !strings.HasSuffix(name, ".delta") {
			continue
		}
		if _, ok := metas[fileName]; !ok {
			missing = append(missing, fileName)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("sparkle appcast has no matching <enclosure> for uploaded file(s): %s. Regenerate the appcast so it includes an item/enclosure for every uploaded archive and delta before uploading", strings.Join(missing, ", "))
	}
	return nil
}

func isFullArchive(name string) bool {
	if strings.HasSuffix(name, ".delta") {
		return false
	}
	if strings.HasSuffix(name, ".tar") || strings.Contains(name, ".tar.") {
		return true
	}
	for _, ext := range []string{".zip", ".dmg", ".aar"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
