package ui

import (
	"bytes"
	"strings"
	"testing"
)

// menuFor builds a Printer writing to a buffer and reading from a string.
//
// No *os.File, so this exercises the typed-number path -- which is the one
// that runs over a pipe and on platforms with no raw-mode support, and the
// only one testable without a real terminal.
func menuFor(input string) (*Printer, *bytes.Buffer) {
	var out bytes.Buffer
	return New(&out).WithInput(strings.NewReader(input)), &out
}

var threeChoices = []Choice{
	{Label: "Scan", Value: "scan"},
	{Label: "Status", Value: "status"},
	{Label: "Rules", Value: "rules"},
}

func TestTypingANumberChooses(t *testing.T) {
	printer, _ := menuFor("2\n")

	got, err := printer.Select("Pick", threeChoices)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "status" {
		t.Errorf("got %q, want status", got)
	}
}

func TestQCancels(t *testing.T) {
	printer, _ := menuFor("q\n")

	_, err := printer.Select("Pick", threeChoices)

	if err != ErrCancelled {
		t.Errorf("got %v, want ErrCancelled", err)
	}
}

func TestClosedInputCancelsRatherThanLooping(t *testing.T) {
	// The pipeline case. A menu that retried forever on a reader with nothing
	// in it would be a hung build with no output explaining why.
	printer, _ := menuFor("")

	_, err := printer.Select("Pick", threeChoices)

	if err != ErrCancelled {
		t.Errorf("got %v, want ErrCancelled", err)
	}
}

func TestAnOutOfRangeNumberIsRefusedAndRetried(t *testing.T) {
	printer, out := menuFor("9\n1\n")

	got, err := printer.Select("Pick", threeChoices)

	if err != nil || got != "scan" {
		t.Fatalf("got %q, %v; want scan", got, err)
	}
	if !strings.Contains(out.String(), "Not one of the options") {
		t.Errorf("the bad answer was not explained:\n%s", out.String())
	}
}

func TestRepeatedNonsenseGivesUpInsteadOfLoopingForever(t *testing.T) {
	printer, _ := menuFor("x\nx\nx\nx\nx\n")

	_, err := printer.Select("Pick", threeChoices)

	if err != ErrCancelled {
		t.Errorf("got %v, want ErrCancelled", err)
	}
}

func TestEveryChoiceIsListedWithItsNumber(t *testing.T) {
	printer, out := menuFor("1\n")
	printer.Select("Pick", threeChoices)

	text := out.String()
	for _, want := range []string{"1. Scan", "2. Status", "3. Rules"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}

func TestAnEmptyMenuIsAnErrorNotAPrompt(t *testing.T) {
	printer, _ := menuFor("1\n")

	_, err := printer.Select("Pick", nil)

	if err == nil {
		t.Error("expected an error for a menu with nothing in it")
	}
}

func TestConfirmDefaultsToNo(t *testing.T) {
	// Enter alone must not agree to anything. This guards the update path,
	// where the question precedes replacing the binary on disk.
	printer, _ := menuFor("\n")

	if printer.Confirm("Replace it?") {
		t.Error("a bare Enter agreed to something")
	}
}

func TestConfirmAcceptsYes(t *testing.T) {
	for _, answer := range []string{"y\n", "Y\n", "yes\n", "YES\n"} {
		printer, _ := menuFor(answer)
		if !printer.Confirm("Replace it?") {
			t.Errorf("%q was not accepted", answer)
		}
	}
}

func TestConfirmTreatsClosedInputAsNo(t *testing.T) {
	printer, _ := menuFor("")

	if printer.Confirm("Replace it?") {
		t.Error("EOF agreed to something")
	}
}

func TestTheSelectedRowIsMarkedWithoutRelyingOnColour(t *testing.T) {
	// NO_COLOR users and screen readers get nothing from a colour change, so
	// the marker and the number carry the selection.
	printer, _ := menuFor("1\n")
	row := printer.menuRow(0, threeChoices[0], true)
	unselected := printer.menuRow(1, threeChoices[1], false)

	if row == unselected {
		t.Error("selected and unselected rows are indistinguishable")
	}
	if !strings.Contains(row, "1.") {
		t.Errorf("the row lost its number: %q", row)
	}
}

func TestTheRepaintHeightMatchesWhatIsActuallyDrawn(t *testing.T) {
	// The menu repaints by moving the cursor up menuHeight lines. If that
	// number and drawMenu disagree, the menu crawls down the screen a row per
	// keypress -- a bug that only shows on a real terminal, which is exactly
	// the kind this test exists to catch first.
	for _, count := range []int{1, 3, 8} {
		choices := make([]Choice, count)
		for i := range choices {
			choices[i] = Choice{Label: "Option", Value: "x"}
		}

		var out bytes.Buffer
		printer := New(&out)
		printer.drawMenu("Pick", choices, 0, false)

		drawn := strings.Count(out.String(), "\n")
		if drawn != menuHeight(choices) {
			t.Errorf("%d choices: drew %d lines, repaint assumes %d",
				count, drawn, menuHeight(choices))
		}
	}
}

func TestTheFinishedMenuDropsTheInstructions(t *testing.T) {
	// Once a choice is made, "Enter to choose" is no longer true.
	var out bytes.Buffer
	printer := New(&out)
	printer.drawMenu("Pick", threeChoices, 1, true)

	if strings.Contains(out.String(), "Enter to choose") {
		t.Errorf("the hint survived the choice:\n%s", out.String())
	}
}
