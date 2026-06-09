package utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidEventType(t *testing.T) {
	valid := []string{"crash", "startup_failure", "update_failure", "install_failure", "rollback_failure"}
	for _, v := range valid {
		assert.Truef(t, IsValidEventType(v), "expected %q to be a valid event type", v)
	}

	invalid := []string{"", "Crash", "panic", "update-failure", "crash ", "unknown", "startup_failure_extra"}
	for _, v := range invalid {
		assert.Falsef(t, IsValidEventType(v), "expected %q to be an invalid event type", v)
	}
}

func TestIsValidEventReason(t *testing.T) {
	valid := []string{
		"checksum_mismatch",
		"disk_full",
		"panic.nil_pointer",
		"a",
		"A1._-",
		strings.Repeat("a", 128),
	}
	for _, v := range valid {
		assert.Truef(t, IsValidEventReason(v), "expected %q to be a valid reason", v)
	}

	invalid := []string{
		"",
		strings.Repeat("a", 129),
		"has space",
		"pipe|char",
		"slash/char",
		"emoji😀",
		"tab\tchar",
		"new\nline",
	}
	for _, v := range invalid {
		assert.Falsef(t, IsValidEventReason(v), "expected %q to be an invalid reason", v)
	}
}
