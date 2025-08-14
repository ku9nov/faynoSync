package updaters

import (
	"fmt"
)

type SquirrelUpdater struct {
	Type string `json:"type"`
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
