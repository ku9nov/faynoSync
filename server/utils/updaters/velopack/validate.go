package velopack

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
	hasFull := false
	releasesCount := 0

	for _, fileName := range fileNames {
		filename := strings.ToLower(fileName)
		if strings.HasSuffix(filename, "-full.nupkg") {
			hasFull = true
		}
		if IsFeedFile(filename) {
			releasesCount++
		}
	}

	if !hasFull {
		return fmt.Errorf("velopack updater requires at least one *-full.nupkg package. Please include a full package in your upload")
	}
	if releasesCount != 1 {
		return fmt.Errorf("velopack updater requires exactly one releases.{channel}.json feed file. Please include a single releases.*.json in your upload")
	}

	return nil
}

func (v *FileValidator) IsFeedFile(fileName string) bool {
	return IsFeedFile(fileName)
}

// IsFeedFile reports whether an uploaded file is the velopack releases feed.
func IsFeedFile(fileName string) bool {
	name := strings.ToLower(fileName)
	return strings.HasPrefix(name, "releases.") && strings.HasSuffix(name, ".json")
}

func (v *FileValidator) GetUpdaterType() string {
	return v.updaterType
}
