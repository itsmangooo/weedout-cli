package ui

import "bufio"

// Decoding keypresses from a raw terminal.
//
// Arrow keys are not characters. They arrive as an escape sequence -- ESC, '[',
// then a letter -- and the three bytes are three separate reads. The awkward
// case is a bare Escape, which is the same first byte with nothing after it,
// and cannot be told apart from the start of a sequence by looking at one byte.
//
// This resolves it by peeking at the buffered reader rather than by waiting to
// see whether more bytes turn up. A timeout would be the other approach and is
// worse: it either makes Escape feel sluggish or misreads a slow connection's
// arrow key as an Escape followed by junk.

type key int

const (
	keyUnknown key = iota
	keyUp
	keyDown
	keyEnter
	keyCancel

	// keyDigitBase is added to a digit so '1' through '9' survive as distinct
	// values without colliding with the named keys above.
	keyDigitBase key = 100
)

const (
	escape   = 0x1b
	ctrlC    = 0x03
	ctrlD    = 0x04
	carriage = '\r'
	newline  = '\n'
)

// readKey blocks until one keypress is decoded.
func readKey(reader *bufio.Reader) key {
	first, err := reader.ReadByte()
	if err != nil {
		// The terminal went away. Treat it as a cancel so callers unwind and
		// restore the terminal, rather than spinning on a dead reader.
		return keyCancel
	}

	switch first {
	case ctrlC, ctrlD, 'q', 'Q':
		return keyCancel
	case carriage, newline, ' ':
		return keyEnter
	case 'k', 'K':
		return keyUp
	case 'j', 'J':
		return keyDown
	case escape:
		return readEscapeSequence(reader)
	}

	if first >= '1' && first <= '9' {
		return keyDigitBase + key(first-'1')
	}
	return keyUnknown
}

// readEscapeSequence decides whether an ESC began a sequence or stood alone.
func readEscapeSequence(reader *bufio.Reader) key {
	// Nothing buffered behind the ESC means it was pressed on its own. This is
	// the whole reason for peeking: Buffered() reports what has already
	// arrived without blocking, so a lone Escape is recognised immediately
	// instead of hanging until the next keypress.
	if reader.Buffered() == 0 {
		return keyCancel
	}

	second, err := reader.ReadByte()
	if err != nil {
		return keyCancel
	}
	// CSI is '[', and SS3 is 'O' -- some terminals send arrows in application
	// mode as ESC O A. Both spellings appear on real hardware and both mean
	// the same key.
	if second != '[' && second != 'O' {
		return keyUnknown
	}

	third, err := reader.ReadByte()
	if err != nil {
		return keyCancel
	}
	switch third {
	case 'A':
		return keyUp
	case 'B':
		return keyDown
	case 'C', 'D':
		// Left and right do nothing in a single-column menu, but they must be
		// swallowed rather than falling through to the digit branch.
		return keyUnknown
	}

	// A longer sequence: Home, Page Up, a modified arrow. Consume the rest so
	// its trailing bytes are not read back as separate keypresses -- Page Down
	// arriving as ESC [ 6 ~ would otherwise register as the digit 6.
	if third >= '0' && third <= '9' {
		for {
			next, err := reader.ReadByte()
			if err != nil || (next >= '@' && next <= '~') {
				break
			}
		}
	}
	return keyUnknown
}
