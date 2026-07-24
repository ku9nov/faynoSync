package sparkle

import (
	"fmt"
	"mime/multipart"
	"strings"
)

type FileValidator struct {
	updaterType string
}

func NewFileValidator(updaterType string) *FileValidator {
	return &FileValidator{updaterType: updaterType}
}

func (v *FileValidator) Validate(files []*multipart.FileHeader) error {
	appcastCount := 0
	hasFull := false

	for _, file := range files {
		name := strings.ToLower(file.Filename)
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
func ValidateArchivesInAppcast(files []*multipart.FileHeader, metas map[string]SparkleMeta) error {
	var missing []string
	for _, file := range files {
		name := strings.ToLower(file.Filename)
		if !isFullArchive(name) && !strings.HasSuffix(name, ".delta") {
			continue
		}
		if _, ok := metas[file.Filename]; !ok {
			missing = append(missing, file.Filename)
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
