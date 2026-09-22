package updaters

import (
	"fmt"
	"strings"
)

// ElectronBuilderUpdater represents the Electron Builder updater configuration
type ElectronBuilderUpdater struct {
	Type string `json:"type"`
}

type ElectronBuilderFileValidator struct {
	updaterType string
}

func (v *ElectronBuilderFileValidator) Validate(fileNames []string) error {
	hasYML := false
	hasYAML := false

	for _, fileName := range fileNames {
		filename := strings.ToLower(fileName)
		if strings.HasSuffix(filename, ".yml") {
			hasYML = true
		}
		if strings.HasSuffix(filename, ".yaml") {
			hasYAML = true
		}
	}

	if !hasYML && !hasYAML {
		return fmt.Errorf("electron-builder updater requires a YML/YAML file for update functionality. Please include a .yml or .yaml file in your upload")
	}

	return nil
}

func (v *ElectronBuilderFileValidator) GetUpdaterType() string {
	return v.updaterType
}

// ValidateElectronBuilderUpdater validates electron-builder updater configuration
func ValidateElectronBuilderUpdater(updaterType string) error {
	validTypes := []string{"electron-builder"}

	for _, validType := range validTypes {
		if updaterType == validType {
			return nil
		}
	}

	return fmt.Errorf("invalid electron-builder updater type: %s. Valid types are: %v", updaterType, validTypes)
}

// GetElectronBuilderUpdaterConfig returns electron-builder updater configuration
func GetElectronBuilderUpdaterConfig(updaterType string) (*ElectronBuilderUpdater, error) {
	if err := ValidateElectronBuilderUpdater(updaterType); err != nil {
		return nil, err
	}

	return &ElectronBuilderUpdater{
		Type: updaterType,
	}, nil
}

func ValidateElectronBuilderFiles(fileNames []string) error {
	validator := &ElectronBuilderFileValidator{updaterType: "electron-builder"}
	return validator.Validate(fileNames)
}
