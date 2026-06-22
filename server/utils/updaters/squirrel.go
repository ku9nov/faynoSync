package updaters

import (
	"fmt"
	"mime/multipart"
	"strings"
)

type SquirrelUpdater struct {
	Type string `json:"type"`
}

type SquirrelWindowsFileValidator struct {
	updaterType string
}

func (v *SquirrelWindowsFileValidator) Validate(files []*multipart.FileHeader) error {
	hasRelease := false

	for _, file := range files {
		filename := strings.ToLower(file.Filename)
		if filename == "releases" {
			hasRelease = true
		}
	}

	if !hasRelease {
		return fmt.Errorf("squirrel windows updater requires a RELEASES file for update functionality. Please include a RELEASES file in your upload")
	}

	return nil
}

func (v *SquirrelWindowsFileValidator) GetUpdaterType() string {
	return v.updaterType
}

type SquirrelDarwinFileValidator struct {
	updaterType string
}

func (v *SquirrelDarwinFileValidator) Validate(files []*multipart.FileHeader) error {
	hasZip := false

	for _, file := range files {
		filename := strings.ToLower(file.Filename)
		if strings.HasSuffix(filename, ".zip") {
			hasZip = true
		}
	}

	if !hasZip {
		return fmt.Errorf("squirrel darwin updater requires a ZIP archive for update functionality. Please include a ZIP file in your upload")
	}

	return nil
}

func (v *SquirrelDarwinFileValidator) GetUpdaterType() string {
	return v.updaterType
}

// RewriteReleasesToAbsoluteURLs rewrites the filename column of a Squirrel
// RELEASES file to absolute URLs (baseURL + "/" + filename) so Squirrel fetches
// each package directly from storage instead of through the API.
func RewriteReleasesToAbsoluteURLs(content, baseURL string) string {
	lines := strings.Split(content, "\n")
	var b strings.Builder
	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		fields := strings.Fields(trimmed)
		if len(fields) >= 3 && !strings.Contains(fields[1], "://") {
			fields[1] = baseURL + "/" + fields[1]
			b.WriteString(strings.Join(fields, " "))
		} else {
			b.WriteString(trimmed)
		}
		if i < len(lines)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func ValidateSquirrelUpdater(updaterType string) error {
	validTypes := []string{"squirrel_darwin", "squirrel_windows"}

	for _, validType := range validTypes {
		if updaterType == validType {
			return nil
		}
	}

	return fmt.Errorf("invalid squirrel updater type: %s. Valid types are: %v", updaterType, validTypes)
}

func GetSquirrelUpdaterConfig(updaterType string) (*SquirrelUpdater, error) {
	if err := ValidateSquirrelUpdater(updaterType); err != nil {
		return nil, err
	}

	return &SquirrelUpdater{
		Type: updaterType,
	}, nil
}

func ValidateSquirrelWindowsFiles(files []*multipart.FileHeader) error {
	validator := &SquirrelWindowsFileValidator{updaterType: "squirrel_windows"}
	return validator.Validate(files)
}

func ValidateSquirrelDarwinFiles(files []*multipart.FileHeader) error {
	validator := &SquirrelDarwinFileValidator{updaterType: "squirrel_darwin"}
	return validator.Validate(files)
}
