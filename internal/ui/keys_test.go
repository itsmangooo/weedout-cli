package ui

import (
	"bufio"
	"strings"
	"testing"
)

func decode(t *testing.T, input string) key {
	t.Helper()
	return readKey(bufio.NewReader(strings.NewReader(input)))
}

func TestArrowKeysDecode(t *testing.T) {
	if got := decode(t, "\x1b[A"); got != keyUp {
		t.Errorf("up: got %v", got)
	}
	if got := decode(t, "\x1b[B"); got != keyDown {
		t.Errorf("down: got %v", got)
	}
}

func TestApplicationModeArrowsAlsoDecode(t *testing.T) {
	// Some terminals send ESC O A instead of ESC [ A. Both are real.
	if got := decode(t, "\x1bOA"); got != keyUp {
		t.Errorf("application-mode up: got %v", got)
	}
}

func TestALoneEscapeCancels(t *testing.T) {
	// The hard case: the same first byte as an arrow key, with nothing behind
	// it. Getting this wrong either hangs on Escape or eats an arrow key.
	if got := decode(t, "\x1b"); got != keyCancel {
		t.Errorf("bare escape: got %v", got)
	}
}

func TestEnterAndSpaceChoose(t *testing.T) {
	for _, input := range []string{"\r", "\n", " "} {
		if got := decode(t, input); got != keyEnter {
			t.Errorf("%q: got %v", input, got)
		}
	}
}

func TestCtrlCAndQCancel(t *testing.T) {
	for _, input := range []string{"\x03", "\x04", "q", "Q"} {
		if got := decode(t, input); got != keyCancel {
			t.Errorf("%q: got %v", input, got)
		}
	}
}

func TestVimKeysMove(t *testing.T) {
	if decode(t, "k") != keyUp || decode(t, "j") != keyDown {
		t.Error("j/k should move")
	}
}

func TestDigitsSelectDirectly(t *testing.T) {
	if got := decode(t, "1"); got != keyDigitBase {
		t.Errorf("1: got %v", got)
	}
	if got := decode(t, "3"); got != keyDigitBase+2 {
		t.Errorf("3: got %v", got)
	}
}

func TestALongSequenceIsConsumedWhole(t *testing.T) {
	// Page Down is ESC [ 6 ~. If the tail is not consumed, the "6" comes back
	// on the next read as a digit and the menu jumps to entry six.
	reader := bufio.NewReader(strings.NewReader("\x1b[6~\x1b[A"))

	if got := readKey(reader); got != keyUnknown {
		t.Errorf("page down should be ignored, got %v", got)
	}
	if got := readKey(reader); got != keyUp {
		t.Errorf("the key after a long sequence was lost: got %v", got)
	}
}

func TestHorizontalArrowsAreSwallowedNotMisreadAsDigits(t *testing.T) {
	if got := decode(t, "\x1b[C"); got != keyUnknown {
		t.Errorf("right arrow: got %v", got)
	}
}

func TestAClosedTerminalCancelsRatherThanSpinning(t *testing.T) {
	if got := decode(t, ""); got != keyCancel {
		t.Errorf("EOF: got %v", got)
	}
}

func TestConsecutiveKeysDecodeIndependently(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\x1b[B\x1b[B\r"))
	want := []key{keyDown, keyDown, keyEnter}
	for i, expected := range want {
		if got := readKey(reader); got != expected {
			t.Errorf("key %d: got %v, want %v", i, got, expected)
		}
	}
}
