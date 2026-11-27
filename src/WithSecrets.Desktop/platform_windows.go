package main

import (
	"encoding/binary"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func trayIcon(png []byte) []byte {
	// A single 64 x 64 PNG entry in a Windows ICO container.
	header := []byte{0, 0, 1, 0, 1, 0, 64, 64, 0, 0, 1, 0, 32, 0, 0, 0, 0, 0, 22, 0, 0, 0}
	binary.LittleEndian.PutUint32(header[14:18], uint32(len(png)))
	return append(header, png...)
}

func openBrowser(link string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	target, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}

func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
}
