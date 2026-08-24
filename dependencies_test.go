package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The CLI has no third-party dependencies, and weedout.dev says so in public.
//
// That claim is read live from this go.mod rather than written by hand, which
// keeps the page from going out of date — but it does not stop the claim
// becoming *false*. Adding one dependency would quietly turn a selling point
// into a table of modules, and the first anybody would know is a visitor
// reading the page.
//
// So the claim is a test. Not because a dependency is forbidden — sometimes
// one is the right call — but because taking one on should be a decision
// somebody makes on purpose, in a diff that says so, rather than something
// that arrives with a convenient import.
//
// The reasoning behind the claim, for whoever is deciding whether to break it:
// every dependency in a security tool is another thing its users have to
// trust, and this binary runs inside CI runners with credentials in the
// environment. A supply-chain compromise here is a compromise of the tool
// people installed to catch supply-chain compromises.

func TestTheBinaryHasNoThirdPartyDependencies(t *testing.T) {
	// `go list -m all` prints this module and every module it requires,
	// transitively. One line means one module: this one.
	output, err := exec.Command("go", "list", "-m", "all").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}

	modules := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			modules = append(modules, trimmed)
		}
	}

	if len(modules) != 1 {
		t.Errorf(
			"weedout.dev tells visitors this CLI has no dependencies, and it now has %d:\n  %s\n\n"+
				"If that is deliberate, delete this test in the same commit and say why. "+
				"The landing page reads go.mod live, so it will start showing the table.",
			len(modules)-1, strings.Join(modules[1:], "\n  "))
	}
}

func TestGoModDeclaresNoRequirements(t *testing.T) {
	// The same property from the other side, and the one that survives without
	// a Go toolchain on the machine running the tests.
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("could not read go.mod: %v", err)
	}

	if strings.Contains(string(raw), "require") {
		t.Errorf("go.mod has a require block:\n%s", raw)
	}
}
