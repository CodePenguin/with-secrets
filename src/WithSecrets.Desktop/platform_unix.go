//go:build darwin || linux

package main

import (
	"os/exec"
	"runtime"
)

func trayIcon(png []byte) []byte { return png }

func openBrowser(link string) error {
	command := "xdg-open"
	if runtime.GOOS == "darwin" {
		command = "/usr/bin/open"
	}
	return exec.Command(command, link).Run()
}

func hideConsole(*exec.Cmd) {}
