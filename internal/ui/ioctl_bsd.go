//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package ui

import "syscall"

// The BSD termios ioctls, which are spelled differently from Linux and are
// what macOS uses. Aliased here so raw_unix.go can stay platform-neutral.
const (
	ioctlReadTermios  = syscall.TIOCGETA
	ioctlWriteTermios = syscall.TIOCSETA
)
