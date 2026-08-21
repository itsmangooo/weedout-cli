package ui

import (
	"fmt"
	"strings"
)

// Charts for a terminal.
//
// The rule these follow is that a chart which does not say what it is measured
// against is decoration. A bar twenty characters long means nothing on its own,
// so every chart here prints the scale it was drawn to and the real number
// beside each row. Someone reading a build log should be able to ignore the
// bars entirely and lose nothing.
//
// Glyphs follow the Printer's judgement about the console: a Windows terminal
// on a legacy code page renders block characters as mojibake, and a chart made
// of question marks is worse than one made of hashes.

// BarWidth is how wide a full bar is drawn. Narrow enough that a row still fits
// an 80-column terminal after its label and value.
const BarWidth = 28

// Bar is one row of a bar chart.
type Bar struct {
	Label string
	Value int
	// Colour is applied to the filled part only, and is never the only thing
	// distinguishing one row from another -- every row is labelled and carries
	// its number.
	Colour func(string) string
}

// Bars draws a horizontal bar chart, scaled to the largest value present.
//
// Scaling to the data rather than to a fixed ceiling is the right choice for a
// severity breakdown, where the interesting comparison is between the rows
// rather than against some absolute. The scale is printed so that is not a
// hidden assumption.
func (p *Printer) Bars(rows []Bar) {
	if len(rows) == 0 {
		return
	}

	max, width := 0, 0
	for _, row := range rows {
		if row.Value > max {
			max = row.Value
		}
		if len(row.Label) > width {
			width = len(row.Label)
		}
	}
	// Nothing to compare. Drawing four empty tracks would suggest a
	// measurement was taken and came back zero-shaped, which is noise.
	if max == 0 {
		return
	}

	fill, track := "█", "░"
	if !p.fancy {
		fill, track = "#", "."
	}

	for _, row := range rows {
		filled := row.Value * BarWidth / max
		// A non-zero value must never round away to an empty bar: "one
		// critical" and "no criticals" are the two most different rows here.
		if filled == 0 && row.Value > 0 {
			filled = 1
		}

		drawn := strings.Repeat(fill, filled)
		if row.Colour != nil {
			drawn = row.Colour(drawn)
		}

		p.Line(
			"  ",
			row.Label, strings.Repeat(" ", width-len(row.Label)+2),
			drawn, p.Dim(strings.Repeat(track, BarWidth-filled)),
			fmt.Sprintf("  %d", row.Value),
		)
	}
	p.Line(p.Dim(fmt.Sprintf("  %sscale: full bar = %d", strings.Repeat(" ", width+2), max)))
}

// sparkLevels are the eight heights a sparkline can draw.
var sparkLevels = []rune("▁▂▃▄▅▆▇█")

// Spark draws a sparkline of a series, oldest first.
//
// Returned as a string rather than printed, so the caller can put it on a line
// with its own label and range. A sparkline without its range is the classic
// dishonest chart -- the same shape can mean "0 to 2" or "0 to 900".
func (p *Printer) Spark(values []int) string {
	if len(values) == 0 {
		return ""
	}

	low, high := values[0], values[0]
	for _, value := range values {
		if value < low {
			low = value
		}
		if value > high {
			high = value
		}
	}

	if !p.fancy {
		// No block glyphs available. A flat run of dashes with the numbers
		// beside it is honest; a fake chart is not.
		out := make([]string, len(values))
		for i, value := range values {
			out[i] = fmt.Sprint(value)
		}
		return strings.Join(out, " ")
	}

	var b strings.Builder
	for _, value := range values {
		level := 0
		// A flat series has no shape to show. Drawing it at the bottom would
		// read as zero, and at the top as a maximum, so it sits in the middle.
		if high > low {
			level = (value - low) * (len(sparkLevels) - 1) / (high - low)
		} else if value > 0 {
			level = len(sparkLevels) / 2
		}
		b.WriteRune(sparkLevels[level])
	}
	return b.String()
}

// Range describes what a sparkline was drawn against.
func Range(values []int) string {
	if len(values) == 0 {
		return ""
	}
	low, high := values[0], values[0]
	for _, value := range values {
		if value < low {
			low = value
		}
		if value > high {
			high = value
		}
	}
	if low == high {
		return fmt.Sprintf("flat at %d", low)
	}
	return fmt.Sprintf("%d to %d", low, high)
}
