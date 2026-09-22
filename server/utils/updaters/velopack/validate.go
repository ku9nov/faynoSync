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
		if strings.HasPrefix(filename, "releases.") && strings.HasSuffix(filename, ".json") {
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

func (v *FileValidator) GetUpdaterType() string {
	return v.updaterType
}
