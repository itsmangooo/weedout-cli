// Command weedout scans a project's dependencies for the CVEs that matter.
//
// Everything lives under internal/ so that `go install` produces one binary
// with no importable surface — this is a tool, not a library, and publishing
// an API would be promising to keep one stable.
package main

import (
	"fmt"
	"os"

	"github.com/itsmangooo/weedout-cli/internal/cli"
)

func main() {
	defer func() {
		// An unhandled panic must exit 2, never 1.
		//
		// Go exits 2 on panic by default, but only after printing a trace and
		// only if nothing recovers first. Being explicit here means a bug in
		// the client can never be mistaken for "critical vulnerabilities
		// found" — which would fail builds that are fine, and, once people
		// stopped trusting the signal, get worked around rather than reported.
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "weedout failed unexpectedly: %v\n", r)
			fmt.Fprintln(os.Stderr, "This is a bug. Nothing was checked.")
			os.Exit(cli.ExitError)
		}
	}()

	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
