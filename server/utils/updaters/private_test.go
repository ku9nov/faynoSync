package updaters

import (
	"errors"
	"testing"
)

func TestValidatePrivate(t *testing.T) {
	for _, updater := range []string{"squirrel_windows", "sparkle", "electron-builder", "velopack"} {
		if err := ValidatePrivate(updater, true); !errors.Is(err, ErrPrivateFeedUpdater) {
			t.Errorf("ValidatePrivate(%q, private) = %v, want ErrPrivateFeedUpdater", updater, err)
		}
		if err := ValidatePrivate(updater, false); err != nil {
			t.Errorf("ValidatePrivate(%q, public) = %v, want nil", updater, err)
		}
	}
	for _, updater := range []string{"", "manual", "tauri", "squirrel_darwin"} {
		if err := ValidatePrivate(updater, true); err != nil {
			t.Errorf("ValidatePrivate(%q, private) = %v, want nil", updater, err)
		}
	}
}
