// Package ui prints results the way they should read in a build log.
//
// Colour is hand-rolled ANSI rather than a library. It is about thirty lines,
// and this tool's whole pitch is that it takes your dependencies seriously —
// pulling in a package to emit "\033[31m" would be a poor advertisement.
package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// Printer writes coloured or plain output depending on where it is going.
//
// It also owns the input side, because the menu needs both and they have to
// agree: a Printer reading from a string in a test must not try to put a
// terminal that is not there into raw mode.
type Printer struct {
	out    io.Writer
	colour bool
	fancy  bool

	// in is where keypresses and typed answers come from. Buffered once and
	// kept, because the escape-sequence decoder relies on peeking at what is
	// already buffered, and a fresh reader per keypress would discard it.
	in *bufio.Reader
	// inFile is the same stream as an *os.File when it is one, and nil when
	// input has been substituted. Raw mode needs a real file descriptor, so a
	// nil here is what routes a test to the typed-number menu.
	inFile *os.File
}

// New builds a Printer for a stream.
//
// Colour is off when NO_COLOR is set (the de-facto standard) or when the
// stream is not a terminal, so a CI log does not fill with escape sequences.
func New(out io.Writer) *Printer {
	return &Printer{
		out:    out,
		colour: useColour(out),
		fancy:  useUnicode(),
		in:     bufio.NewReader(os.Stdin),
		inFile: os.Stdin,
	}
}

// WithInput returns a copy that reads from r instead of standard input.
//
// The copy has no *os.File, so it takes the typed-number path rather than
// attempting raw mode. That is exactly the path worth testing: it is what runs
// over a pipe, a serial console, and any platform without a raw-mode
// implementation.
func (p *Printer) WithInput(r io.Reader) *Printer {
	clone := *p
	clone.in = bufio.NewReader(r)
	clone.inFile = nil
	return &clone
}

// Writer is the stream this Printer writes to.
//
// Exposed so a caller emitting something that is not prose -- JSON for a
// pipeline to parse -- can write to the same place without a second handle on
// stdout, and without going through the colouring helpers.
func (p *Printer) Writer() io.Writer { return p.out }

func useColour(out io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	// Some CI systems set this and do render colour.
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// useUnicode decides whether the arrows and bullets are safe to emit.
//
// A Windows console still commonly runs a legacy code page, where printing "→"
// produces mojibake. A security tool that garbles its own results is worse than
// one that prints ASCII, so the symbol set follows what the console can show.
func useUnicode() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	// Windows Terminal sets this; the old conhost does not.
	return os.Getenv("WT_SESSION") != "" || strings.Contains(os.Getenv("TERM"), "xterm")
}

// Symbol returns a glyph the stream can actually render.
func (p *Printer) Symbol(name string) string {
	fancy := map[string]string{"arrow": "→", "sep": "·", "bullet": "•", "alert": "!"}
	plain := map[string]string{"arrow": "->", "sep": "-", "bullet": "*", "alert": "!"}
	if p.fancy {
		return fancy[name]
	}
	return plain[name]
}

func (p *Printer) wrap(text, code string) string {
	if !p.colour {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

// Dim renders secondary text.
func (p *Printer) Dim(text string) string { return p.wrap(text, "2") }

// Bold renders emphasised text.
func (p *Printer) Bold(text string) string { return p.wrap(text, "1") }

// Red renders an urgent tier.
func (p *Printer) Red(text string) string { return p.wrap(text, "31") }

// Yellow renders a warning tier.
func (p *Printer) Yellow(text string) string { return p.wrap(text, "33") }

// Green renders a clear result.
func (p *Printer) Green(text string) string { return p.wrap(text, "32") }

// Line writes one line.
func (p *Printer) Line(text ...string) {
	if len(text) == 0 {
		fmt.Fprintln(p.out)
		return
	}
	fmt.Fprintln(p.out, strings.Join(text, ""))
}

// IsTerminal reports whether a stream is a terminal rather than a pipe or file.
func IsTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// CanPrompt reports whether it is safe to wait for a human.
//
// Both directions have to be a terminal. Output alone is not enough -- a
// process reading from a pipe with its output on a screen would sit waiting
// for a keypress that is never coming, which in a pipeline is a hung build
// rather than an error anyone can read.
//
// CI is excluded outright, even when it does allocate a terminal, which some
// runners do. A pipeline that pauses for input is broken regardless of whether
// it technically could receive some.
func CanPrompt() bool {
	if InCI() {
		return false
	}
	return IsTerminal(os.Stdin) && IsTerminal(os.Stdout)
}

// InCI reports whether this looks like an automated build.
//
// Checked by name against the variables the major systems set. There is no
// standard for this, so the list is what it is; being wrong in the direction
// of "assume CI" is the safe error, since the cost is a menu that does not
// appear rather than a build that hangs.
func InCI() bool {
	for _, name := range []string{
		"CI",               // GitHub Actions, GitLab, CircleCI, Travis
		"BUILD_NUMBER",     // Jenkins, TeamCity
		"TF_BUILD",         // Azure Pipelines
		"BUILDKITE",        // Buildkite
		"TEAMCITY_VERSION", // TeamCity
		"bamboo_buildKey",  // Bamboo
		"GITHUB_ACTIONS",   // belt and braces
	} {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}
