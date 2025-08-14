package updaters

import (
	"fmt"
)

// ElectronBuilderUpdater represents the Electron Builder updater configuration
type ElectronBuilderUpdater struct {
	Type string `json:"type"`
}

// ValidateElectronBuilderUpdater validates electron-builder updater configuration
func ValidateElectronBuilderUpdater(updaterType string) error {
	validTypes := []string{"electron-builder_linux", "electron-builder_windows", "electron-builder_darwin"}

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
