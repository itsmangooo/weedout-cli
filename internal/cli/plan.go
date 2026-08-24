package cli

import (
	"github.com/itsmangooo/weedout-cli/internal/api"
	"github.com/itsmangooo/weedout-cli/internal/globalconfig"
)

// Noticing that the account's plan changed, and saying so once.
//
// A plan change is instant on the server: nothing caches the tier, so the very
// next request is served under the new plan. What is not instant is the person
// finding out. They upgrade in a browser, come back to a terminal, run a scan,
// and it silently reaches deeper than it did an hour ago with nothing to say
// why.
//
// A CLI cannot be subscribed to. It runs, prints, exits. So the honest version
// of "in real time" is: the next command reflects the change, and mentions it
// exactly once. This compares the plan the server just reported against the
// one recorded on this machine and prints a sentence when they differ.
//
// Three things it deliberately does not do:
//
//   - Decide anything. Every limit is enforced server-side; this is a message,
//     and a client that gated on a local file would be a client somebody could
//     edit.
//   - Speak on a first run. A machine with nothing recorded has nothing to
//     compare against, and greeting a new user with "your plan is now Free" is
//     news to nobody.
//   - Speak when the server said nothing. An older deployment sends no plan
//     block, and an absent field must read as "no information" rather than as
//     a downgrade.

// announcePlan prints a one-line notice when the plan differs from last time.
//
// Silent under --quiet and --json, which are the two modes whose whole promise
// is that the output is only what was asked for. A pipeline parsing JSON should
// not have to tolerate a sentence appearing in its stream, and the change is in
// the JSON anyway for anything that wants it.
func announcePlan(printer interface{ Line(...string) }, plan api.Plan, quiet, asJSON bool) {
	if !plan.Known() {
		return
	}

	changed, previous := globalconfig.NotePlan(plan.Tier)
	if !changed || quiet || asJSON {
		return
	}

	if message := plan.Describes(previous); message != "" {
		printer.Line()
		printer.Line(message)
	}
}
