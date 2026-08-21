//go:build linux

package ui

import "syscall"

// The termios ioctls on Linux. Named constants exist in the syscall package
// here, unlike on the BSDs, so they are simply aliased.
const (
	ioctlReadTermios  = syscall.TCGETS
	ioctlWriteTermios = syscall.TCSETS
)
