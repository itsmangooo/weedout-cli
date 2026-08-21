package ui

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
)

// An arrow-key menu, and a typed-number menu for when that is not possible.
//
// The fallback is not a lesser version to be embarrassed about -- it is the
// one that runs in a pipe, over a serial console, inside an editor's terminal
// pane, and on any platform this package has no raw-mode implementation for.
// Both are supported paths, and Select picks between them by asking whether it
// is talking to a terminal rather than by guessing from the platform.

// Choice is one option in a menu.
type Choice struct {
	// Label is the line the user reads.
	Label string
	// Hint is the dim explanation beside it. Optional.
	Hint string
	// Value is what Select returns. Not shown.
	Value string
}

// ErrCancelled is returned when the user backs out with Escape, q, or Ctrl-C.
//
// A distinct error rather than an empty result, because "chose nothing" and
// "decided not to" are different outcomes: the first is a bug, the second
// should exit quietly with no scolding.
var ErrCancelled = fmt.Errorf("cancelled")

// Select asks the user to pick one of the choices and returns its Value.
func (p *Printer) Select(title string, choices []Choice) (string, error) {
	if len(choices) == 0 {
		return "", fmt.Errorf("nothing to choose from")
	}

	if restore, err := p.makeRawInput(); err == nil {
		defer restore()
		// A terminal left without echo after a Ctrl-C is a broken terminal,
		// and the user has to know to type `stty sane` to fix something they
		// did not break. Catching the signal means the restore above always
		// runs before the process ends.
		stop := onInterrupt(func() {
			restore()
			showCursor(p.out)
		})
		defer stop()

		return p.selectWithArrows(title, choices)
	}

	return p.selectByNumber(title, choices)
}

// makeRawInput puts this Printer's input into raw mode, when it is a terminal.
func (p *Printer) makeRawInput() (func(), error) {
	if p.inFile == nil {
		return nil, fmt.Errorf("input is not a terminal")
	}
	return makeRaw(p.inFile)
}

// selectWithArrows draws a menu and moves a cursor through it.
func (p *Printer) selectWithArrows(title string, choices []Choice) (string, error) {
	selected := 0
	hideCursor(p.out)
	defer showCursor(p.out)

	p.drawMenu(title, choices, selected, false)

	for {
		key := readKey(p.in)
		switch key {
		case keyUp:
			// Wrapping rather than stopping at the ends. With four items on
			// screen, "up from the top goes to the bottom" is faster than
			// pressing down three times and is what every menu like this does.
			selected = (selected - 1 + len(choices)) % len(choices)
		case keyDown:
			selected = (selected + 1) % len(choices)
		case keyEnter:
			p.settleMenu(title, choices, selected)
			return choices[selected].Value, nil
		case keyCancel:
			p.settleMenu(title, choices, selected)
			return "", ErrCancelled
		case keyUnknown:
			continue
		default:
			// A digit jumps straight to that entry, so somebody who already
			// knows what they want does not have to arrow down to it.
			if index := int(key - keyDigitBase); index >= 0 && index < len(choices) {
				selected = index
			}
			continue
		}
		p.redrawMenu(title, choices, selected)
	}
}

// drawMenu paints the whole menu.
func (p *Printer) drawMenu(title string, choices []Choice, selected int, final bool) {
	p.Line()
	p.Line("  ", p.Bold(title))
	p.Line()

	for i, choice := range choices {
		p.Line(p.menuRow(i, choice, i == selected))
	}

	p.Line()
	if final {
		return
	}
	p.Line(p.Dim("  Up and down to move, Enter to choose, q to cancel."))
}

// menuRow renders one line of the menu.
func (p *Printer) menuRow(index int, choice Choice, current bool) string {
	marker := "  "
	label := choice.Label
	if current {
		marker = p.Symbol("arrow") + " "
		// Bold as well as the marker. Colour alone would leave the selection
		// invisible to anyone whose terminal has it off, which includes every
		// NO_COLOR user and every screen reader.
		label = p.Bold(label)
	}

	row := fmt.Sprintf("  %s%d. %s", marker, index+1, label)
	if choice.Hint != "" {
		row += p.Dim("  " + choice.Hint)
	}
	return row
}

// menuHeight is how many lines drawMenu emits with its hint.
//
// Derived from what drawMenu actually does -- a blank line, the title, a blank
// line, one line per choice, a blank line, and the hint -- rather than being a
// number kept in step by hand. A line added to the menu and not to this count
// would make the display crawl down the screen a row at a time.
func menuHeight(choices []Choice) int { return len(choices) + 5 }

// redrawMenu repaints in place by moving the cursor back up over the menu.
func (p *Printer) redrawMenu(title string, choices []Choice, selected int) {
	fmt.Fprintf(p.out, "\033[%dA", menuHeight(choices))
	p.drawMenu(title, choices, selected, false)
}

// settleMenu leaves the finished menu on screen without its hint.
//
// It has to repaint over the live menu rather than below it, or choosing an
// option prints a second copy underneath the first. The final version is one
// line shorter, so the leftover hint is erased with a clear-to-end-of-screen;
// without that, the instructions stay on screen after they stop being true.
func (p *Printer) settleMenu(title string, choices []Choice, selected int) {
	fmt.Fprintf(p.out, "\033[%dA", menuHeight(choices))
	p.drawMenu(title, choices, selected, true)
	fmt.Fprint(p.out, "\033[J")
}

func hideCursor(out io.Writer) { fmt.Fprint(out, "\033[?25l") }
func showCursor(out io.Writer) { fmt.Fprint(out, "\033[?25h") }

// selectByNumber is the menu for anything that is not an interactive terminal.
func (p *Printer) selectByNumber(title string, choices []Choice) (string, error) {
	p.Line()
	p.Line("  ", p.Bold(title))
	p.Line()
	for i, choice := range choices {
		p.Line(p.menuRow(i, choice, false))
	}
	p.Line()

	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(p.out, "  Choose 1-%d (or q to cancel): ", len(choices))

		line, err := p.in.ReadString('\n')
		if err != nil {
			// EOF: stdin is closed or empty, which is what happens when this
			// runs in a pipeline. Cancelling beats looping forever on a
			// reader that will never produce anything.
			p.Line()
			return "", ErrCancelled
		}

		answer := strings.TrimSpace(line)
		if answer == "q" || answer == "Q" || answer == "" {
			return "", ErrCancelled
		}
		if number, err := strconv.Atoi(answer); err == nil {
			if number >= 1 && number <= len(choices) {
				return choices[number-1].Value, nil
			}
		}
		p.Line(p.Dim(fmt.Sprintf("  Not one of the options. Type a number from 1 to %d.", len(choices))))
	}

	// Three bad answers in a row is somebody who cannot see the prompt, or a
	// process feeding it noise. Either way, stopping beats an endless loop.
	return "", ErrCancelled
}

// Confirm asks a yes or no question. Defaults to no.
//
// The default matters: this is used before things like replacing the binary,
// and somebody who hits Enter to get their prompt back should not have thereby
// agreed to it.
func (p *Printer) Confirm(question string) bool {
	fmt.Fprintf(p.out, "  %s [y/N] ", question)

	line, err := p.in.ReadString('\n')
	if err != nil {
		p.Line()
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// onInterrupt runs a function on Ctrl-C and returns a function to stop
// listening.
func onInterrupt(action func()) func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)

	done := make(chan struct{})
	go func() {
		select {
		case <-signals:
			action()
			os.Exit(130) // 128 + SIGINT, the shell convention.
		case <-done:
		}
	}()

	return func() {
		signal.Stop(signals)
		close(done)
	}
}
