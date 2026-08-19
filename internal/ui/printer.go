// Package ui prints results the way they should read in a build log.
//
// Colour is hand-rolled ANSI rather than a library. It is about thirty lines,
// and this tool's whole pitch is that it takes your dependencies seriously —
// pulling in a package to emit "\033[31m" would be a poor advertisement.
package ui

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// Printer writes coloured or plain output depending on where it is going.
type Printer struct {
	out    io.Writer
	colour bool
	fancy  bool
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
	}
}

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
