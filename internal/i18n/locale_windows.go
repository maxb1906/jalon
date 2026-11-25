//go:build windows

package i18n

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func osLocale() string {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultLocaleName")
	if proc.Find() != nil {
		return ""
	}
	buf := make([]uint16, 85)
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}
