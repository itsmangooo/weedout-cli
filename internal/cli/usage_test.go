package cli

import (
	"bytes"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every command the binary answers to has to be documented, in three places.
//
// The failure this guards against is the quiet one: a command is added, it
// works, its tests pass, and nobody outside the person who wrote it ever finds
// out it exists. `weedout --help` is where somebody looks first, the README is
// where they look second, and weedout.dev/docs/the-cli is where they look when
// the first two were not enough.
//
// The web docs live in the other repository and cannot be checked from here.
// What can be checked is that the binary describes itself completely, which is
// the thing those docs are written from.

// commandsInDispatch reads the switch in Run() and returns the primary name of
// every case.
//
// Parsed from the source rather than listed here, because a list maintained by
// hand is the same problem one level down.
func commandsInDispatch(t *testing.T) []string {
	t.Helper()

	source, err := os.ReadFile("cli.go")
	if err != nil {
		t.Fatalf("could not read cli.go: %v", err)
	}

	// `case "scan":` or `case "supply-chain", "signals":` — the first literal
	// is the primary name and the rest are aliases, which do not need their
	// own line in the usage text.
	caseLine := regexp.MustCompile(`(?m)^\tcase "([a-z-]+)"`)

	seen := map[string]bool{}
	names := []string{}
	for _, match := range caseLine.FindAllStringSubmatch(string(source), -1) {
		name := match[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}

	if len(names) < 10 {
		t.Fatalf("only found %d commands; the parser has probably stopped working", len(names))
	}
	sort.Strings(names)
	return names
}

// undocumented is the set of commands that never need a line of their own.
var undocumented = map[string]bool{
	// Prints the usage text. Listing it inside the usage text would be
	// circular and helps nobody.
	"help": true,
	// The flag form, `weedout --interactive`, is what the usage text lists.
	// The bare word is an alias nobody is told to type.
	"interactive": true,
}

func TestEveryCommandAppearsInTheUsageText(t *testing.T) {
	var out bytes.Buffer
	usage(&out)
	text := out.String()

	missing := []string{}
	for _, name := range commandsInDispatch(t) {
		if undocumented[name] {
			continue
		}
		if !strings.Contains(text, "weedout "+name) {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		t.Errorf(
			"these commands work but `weedout --help` does not mention them: %s\n\n"+
				"Add a line to usage(), and remember the web docs at "+
				"weedout.dev/docs/the-cli are written from it.",
			strings.Join(missing, ", "))
	}
}

func TestEveryCommandAppearsInTheReadme(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("could not read README.md: %v", err)
	}
	readme := string(raw)

	missing := []string{}
	for _, name := range commandsInDispatch(t) {
		if undocumented[name] {
			continue
		}
		if !strings.Contains(readme, "weedout "+name) {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		t.Errorf("the README does not mention: %s", strings.Join(missing, ", "))
	}
}

func TestTheUsageTextDoesNotPromiseCommandsThatDoNotExist(t *testing.T) {
	// The other direction, and the more embarrassing one. A command in the
	// help text that the dispatch does not handle is a documented feature that
	// answers "Unknown command".
	var out bytes.Buffer
	usage(&out)

	real := map[string]bool{}
	for _, name := range commandsInDispatch(t) {
		real[name] = true
	}

	// Not preceded by a dot, or `.weedout file` in the init line matches and
	// the test reports a phantom command called "file".
	mentioned := regexp.MustCompile(`(?:^|[^.\w])weedout ([a-z-]+)`)
	phantom := []string{}
	for _, match := range mentioned.FindAllStringSubmatch(out.String(), -1) {
		name := match[1]
		if !real[name] && !phantom_ok[name] {
			phantom = append(phantom, name)
		}
	}

	if len(phantom) > 0 {
		t.Errorf("the usage text promises commands that do not exist: %s", strings.Join(phantom, ", "))
	}
}

// Words that follow "weedout " in the usage text without naming a command.
// Empty, and the aim is to keep it that way: every entry here is a line of the
// help text that reads like a command and is not one.
var phantom_ok = map[string]bool{}
