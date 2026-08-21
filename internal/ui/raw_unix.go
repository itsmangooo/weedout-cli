//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ui

import (
	"os"
	"syscall"
	"unsafe"
)

// Raw terminal mode on Unix.
//
// Hand-rolled against syscall rather than pulling in golang.org/x/term, which
// is the obvious dependency and would be the only one in the module. A tool
// whose whole pitch is that it takes your dependency tree seriously should not
// add a package to read a keypress.
//
// The ioctl numbers differ between Linux and the BSDs, so they come from the
// per-platform constants in ioctl_*.go rather than being written here.

// makeRaw puts the terminal into a mode where a keypress arrives immediately
// and is not echoed, and returns a function that puts it back.
//
// Restoring matters more than usual: a process that exits with echo disabled
// leaves the user typing blind into their shell, and they have to run `stty
// sane` to fix a terminal that some other program broke. Every caller defers
// the restore, and the interrupt handler runs it too.
func makeRaw(file *os.File) (restore func(), err error) {
	fd := file.Fd()

	var original syscall.Termios
	if err := ioctl(fd, ioctlReadTermios, &original); err != nil {
		return nil, err
	}

	raw := original
	// Input: no CR-to-NL translation, no XON/XOFF, no break interrupt. Without
	// this an arrow key can arrive mangled or a stray Ctrl-S can freeze the
	// display with no way to tell why.
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK |
		syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	// Local: no echo, no line buffering, no signal generation. Signals are off
	// so Ctrl-C arrives as a byte this code can act on, which lets the menu
	// restore the terminal before exiting instead of dying with echo off.
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON |
		syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	// Return as soon as one byte is available, with no timeout.
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0

	if err := ioctl(fd, ioctlWriteTermios, &raw); err != nil {
		return nil, err
	}

	return func() {
		restored := original
		_ = ioctl(fd, ioctlWriteTermios, &restored)
	}, nil
}

func ioctl(fd uintptr, request uintptr, termios *syscall.Termios) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, fd, request, uintptr(unsafe.Pointer(termios)))
	if errno != 0 {
		return errno
	}
	return nil
}
