//go:build windows

package ui

import (
	"os"
	"syscall"
)

// Raw console mode on Windows.
//
// Two things have to change, and they are on different handles. Input needs
// line buffering and echo switched off so a keypress arrives immediately, and
// it needs ENABLE_VIRTUAL_TERMINAL_INPUT so the arrow keys arrive as the same
// escape sequences every other platform sends -- without it they come through
// as console key events this code would have to decode separately, and the
// menu would need two parsers for one keyboard.
//
// Output needs ENABLE_VIRTUAL_TERMINAL_PROCESSING so the cursor movement the
// menu uses to redraw itself is interpreted rather than printed literally.
const (
	enableProcessedInput       = 0x0001
	enableLineInput            = 0x0002
	enableEchoInput            = 0x0004
	enableVirtualTerminalInput = 0x0200

	enableVirtualTerminalProcessing = 0x0004
)

// SetConsoleMode is not in the standard library's syscall package, though its
// getter is, so it is resolved by hand.
//
// syscall.NewLazyDLL carries a documented warning about DLL preloading -- a
// planted kernel32.dll in the working directory getting loaded instead of the
// real one -- and the standard library points at golang.org/x/sys/windows for
// a hardened loader. That is a dependency this module will not take.
//
// It does not apply here regardless: kernel32.dll is on Windows' KnownDLLs
// list, which is resolved from the pre-loaded System32 section before any
// search path is consulted. The attack is real for ordinary DLLs and is not
// reachable for this one. Loading anything outside KnownDLLs this way would
// need a different approach.
var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

func setConsoleMode(handle syscall.Handle, mode uint32) error {
	ok, _, err := procSetConsoleMode.Call(uintptr(handle), uintptr(mode))
	if ok == 0 {
		return err
	}
	return nil
}

func makeRaw(file *os.File) (restore func(), err error) {
	inputHandle := syscall.Handle(file.Fd())

	var originalInput uint32
	if err := syscall.GetConsoleMode(inputHandle, &originalInput); err != nil {
		return nil, err
	}

	rawInput := originalInput
	rawInput &^= enableEchoInput | enableLineInput | enableProcessedInput
	rawInput |= enableVirtualTerminalInput
	if err := setConsoleMode(inputHandle, rawInput); err != nil {
		return nil, err
	}

	// Output is best-effort. A console old enough to refuse VT processing --
	// conhost on an unpatched Windows 10 -- can still run the menu; it will
	// just repaint by rewriting lines rather than moving the cursor. Failing
	// the whole interaction over it would be a worse trade than a plainer
	// looking menu.
	outputHandle := syscall.Handle(os.Stdout.Fd())
	var originalOutput uint32
	outputChanged := false
	if err := syscall.GetConsoleMode(outputHandle, &originalOutput); err == nil {
		if setConsoleMode(
			outputHandle, originalOutput|enableVirtualTerminalProcessing,
		) == nil {
			outputChanged = true
		}
	}

	return func() {
		_ = setConsoleMode(inputHandle, originalInput)
		if outputChanged {
			_ = setConsoleMode(outputHandle, originalOutput)
		}
	}, nil
}
