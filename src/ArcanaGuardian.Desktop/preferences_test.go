package main

import (
	"path/filepath"
	"testing"
)

func TestNotificationPreferencePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "desktop.json")
	for _, expected := range []bool{false, true} {
		if err := writeNotificationPreference(path, expected); err != nil {
			t.Fatal(err)
		}
		got, err := readNotificationPreference(path)
		if err != nil || got != expected {
			t.Fatalf("read notifications enabled = %t, want %t: %v", got, expected, err)
		}
	}
}
