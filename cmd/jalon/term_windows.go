//go:build windows

package main

import "golang.org/x/sys/windows"

// enableVT active les séquences ANSI dans la console Windows 10+.
func enableVT() {
	h := windows.Handle(windows.Stdout)
	var mode uint32
	if windows.GetConsoleMode(h, &mode) == nil {
		_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
}
