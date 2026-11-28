package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type preferences struct {
	Notifications *bool `json:"notifications"`
}

func notificationPreferencesPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Arcana Guardian", "desktop.json"), nil
}

func readNotificationPreference(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	var pref preferences
	if err := json.Unmarshal(data, &pref); err != nil {
		return true, err
	}
	if pref.Notifications == nil {
		return true, nil
	}
	return *pref.Notifications, nil
}

func writeNotificationPreference(path string, enabled bool) error {
	if path == "" {
		return errors.New("the user configuration directory is unavailable")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "desktop-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	writeErr := json.NewEncoder(file).Encode(preferences{Notifications: &enabled})
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
