package updaters

import (
	"faynoSync/server/model"
	"fmt"
)

// ValidUpdaterTypes contains all valid updater types
var ValidUpdaterTypes = []string{
	"manual",
	"squirrel_darwin",
	"squirrel_windows",
	"sparkle",
	"electron-builder_linux",
	"electron-builder_windows",
	"electron-builder_darwin",
}

// ValidateUpdater validates a single updater
func ValidateUpdater(updater model.Updater) error {
	isValid := false
	for _, validType := range ValidUpdaterTypes {
		if updater.Type == validType {
			isValid = true
			break
		}
	}

	if !isValid {
		return fmt.Errorf("invalid updater type: %s. Valid types are: %v", updater.Type, ValidUpdaterTypes)
	}

	return nil
}

func ValidateUpdaters(updaters []model.Updater) error {
	if len(updaters) == 0 {
		return fmt.Errorf("at least one updater is required")
	}

	typeCount := make(map[string]int)
	defaultCount := 0

	for _, updater := range updaters {
		if err := ValidateUpdater(updater); err != nil {
			return err
		}

		typeCount[updater.Type]++
		if updater.Default {
			defaultCount++
		}
	}

	for updaterType, count := range typeCount {
		if count > 1 {
			return fmt.Errorf("duplicate updater type: %s", updaterType)
		}
	}

	if defaultCount == 0 {
		return fmt.Errorf("exactly one updater must be set as default")
	}

	if defaultCount > 1 {
		return fmt.Errorf("only one updater can be set as default")
	}

	return nil
}
