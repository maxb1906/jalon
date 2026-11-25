//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// doubleClicked indique si Jalon a été lancé depuis l'Explorateur (double
// clic) : la console n'appartient alors qu'à ce seul processus et se
// fermera dès la sortie.
func doubleClicked() bool {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	if proc.Find() != nil {
		return false
	}
	var ids [4]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	return n == 1
}

// pause garde la fenêtre ouverte pour que le message reste lisible.
func pause(msg string) {
	fmt.Fprint(os.Stderr, "\n"+msg)
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
