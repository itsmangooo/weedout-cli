package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/itsmangooo/weedout-cli/internal/api"
	"github.com/itsmangooo/weedout-cli/internal/globalconfig"
)

// Noticing that the account's plan changed.
//
// The server applies a plan change instantly -- nothing caches the tier, so
// the next request is served under the new plan. What is not instant is the
// person finding out: they upgrade in a browser, come back to a terminal, and
// the next scan silently reaches deeper than it did an hour ago.
//
// A CLI cannot be subscribed to, so the honest version of "in real time" is
// that the next command reflects the change and mentions it once. Most of what
// follows is about the cases where it must stay quiet, because a tool that
// announces things that did not happen is one people learn to ignore.

func planServer(t *testing.T, plan map[string]any) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{
			"project": "demo", "dependencies_scanned": 3, "actionable": 0,
			"suppressed": 0, "counts": map[string]int{}, "findings": []any{},
		}
		if plan != nil {
			body["plan"] = plan
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func pro() map[string]any {
	return map[string]any{
		"tier": "pro", "name": "Pro", "scan_depth": nil,
		"custom_rules": true, "scan_interval_hours": 4, "max_projects": nil,
	}
}

func free() map[string]any {
	return map[string]any{
		"tier": "free", "name": "Free", "scan_depth": 1,
		"custom_rules": false, "scan_interval_hours": 24, "max_projects": 1,
	}
}

// seenPlan records what this machine last saw, as a previous command would.
func seenPlan(t *testing.T, tier string) {
	t.Helper()
	file, err := globalconfig.Load()
	if err != nil {
		t.Fatal(err)
	}
	file.LastSeenPlan = tier
	if err := globalconfig.Save(file); err != nil {
		t.Fatal(err)
	}
}

func TestAnUpgradeIsAnnouncedOnTheNextScan(t *testing.T) {
	isolateConfig(t)
	seenPlan(t, "free")
	server := planServer(t, pro())

	code, out := run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "Your plan is now Pro") {
		t.Errorf("the upgrade was not mentioned:\n%s", out)
	}
	// The capability, not just the label. "You are on Pro" tells somebody what
	// their receipt already told them.
	if !strings.Contains(out, "whole dependency tree") {
		t.Errorf("the message did not say what changed:\n%s", out)
	}
}

func TestADowngradeIsAnnouncedPlainly(t *testing.T) {
	// The direction that matters more. Somebody whose rules have stopped
	// applying needs to know before they read a result produced without them.
	isolateConfig(t)
	seenPlan(t, "pro")
	server := planServer(t, free())

	_, out := run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)

	if !strings.Contains(out, "Your plan is now Free") {
		t.Errorf("the downgrade was not mentioned:\n%s", out)
	}
	if !strings.Contains(out, "no longer apply") {
		t.Errorf("the consequence was not stated:\n%s", out)
	}
	// And that nothing was destroyed, because the obvious fear on reading that
	// sentence is that the rules are gone.
	if !strings.Contains(out, "kept, not deleted") {
		t.Errorf("the message implied the rules were lost:\n%s", out)
	}
}

func TestItIsSaidOnceAndNotAgain(t *testing.T) {
	isolateConfig(t)
	seenPlan(t, "free")
	server := planServer(t, pro())

	_, first := run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)
	_, second := run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)

	if !strings.Contains(first, "Your plan is now Pro") {
		t.Fatalf("the first run said nothing:\n%s", first)
	}
	if strings.Contains(second, "Your plan is now") {
		t.Errorf("it repeated itself on an unchanged plan:\n%s", second)
	}
}

func TestAFirstRunAnnouncesNothing(t *testing.T) {
	// A machine with nothing recorded has nothing to compare against, and
	// greeting a new user with "your plan is now Free" is news to nobody.
	isolateConfig(t)
	server := planServer(t, free())

	_, out := run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)

	if strings.Contains(out, "Your plan is now") {
		t.Errorf("a first run announced a change:\n%s", out)
	}
}

func TestTheFirstRunStillRecordsThePlan(t *testing.T) {
	// So the *second* change is noticed. Recording only on a change would mean
	// the first upgrade after installing is silent too.
	isolateConfig(t)
	server := planServer(t, free())

	run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)

	file, _ := globalconfig.Load()
	if file.LastSeenPlan != "free" {
		t.Errorf("nothing was recorded: %q", file.LastSeenPlan)
	}
}

func TestAServerThatSaysNothingIsNotADowngrade(t *testing.T) {
	// An older deployment sends no plan block. An absent field has to read as
	// "no information", never as a change -- announcing one that did not
	// happen is worse than announcing nothing.
	isolateConfig(t)
	seenPlan(t, "pro")
	server := planServer(t, nil)

	_, out := run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)

	if strings.Contains(out, "Your plan is now") {
		t.Errorf("silence was read as a change:\n%s", out)
	}
	file, _ := globalconfig.Load()
	if file.LastSeenPlan != "pro" {
		t.Errorf("silence overwrote what was known: %q", file.LastSeenPlan)
	}
}

func TestQuietStaysQuiet(t *testing.T) {
	// --quiet promises the exit code is the whole answer.
	isolateConfig(t)
	seenPlan(t, "free")
	server := planServer(t, pro())

	_, out := run(t, "scan", project(t), "--quiet", "--api-key", "k", "--url", server.URL)

	if strings.Contains(out, "Your plan is now") {
		t.Errorf("--quiet printed a notice:\n%s", out)
	}
}

func TestJSONStaysParseable(t *testing.T) {
	// A pipeline parsing the output must not have to tolerate a sentence
	// appearing in its stream. The change is in the JSON anyway.
	isolateConfig(t)
	seenPlan(t, "free")
	server := planServer(t, pro())

	_, out := run(t, "scan", project(t), "--json", "--api-key", "k", "--url", server.URL)

	if strings.Contains(out, "Your plan is now") {
		t.Errorf("--json printed prose:\n%s", out)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Errorf("the output was not JSON: %v\n%s", err, out)
	}
}

func TestTheNoticeIsRecordedEvenWhenSuppressed(t *testing.T) {
	// Otherwise --quiet in a cron job leaves the machine permanently primed to
	// announce the same change the next time somebody runs it by hand.
	isolateConfig(t)
	seenPlan(t, "free")
	server := planServer(t, pro())

	run(t, "scan", project(t), "--quiet", "--api-key", "k", "--url", server.URL)

	file, _ := globalconfig.Load()
	if file.LastSeenPlan != "pro" {
		t.Errorf("a suppressed notice did not record the plan: %q", file.LastSeenPlan)
	}
}

// ---------------------------------------------------------------------------
// The sentence itself
// ---------------------------------------------------------------------------

func TestDescribesSaysNothingWithoutAChange(t *testing.T) {
	depth := 1
	cases := []struct {
		name     string
		plan     api.Plan
		previous string
	}{
		{"same tier", api.Plan{Tier: "pro", Name: "Pro"}, "pro"},
		{"no previous", api.Plan{Tier: "pro", Name: "Pro"}, ""},
		{"server said nothing", api.Plan{}, "pro"},
		{"nothing at all", api.Plan{ScanDepth: &depth}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.plan.Describes(tc.previous); got != "" {
				t.Errorf("said %q", got)
			}
		})
	}
}

func TestKnownDistinguishesAbsentFromFree(t *testing.T) {
	// The distinction the whole thing rests on.
	if (api.Plan{}).Known() {
		t.Error("an empty plan claimed to be known")
	}
	if !(api.Plan{Tier: "free"}).Known() {
		t.Error("a free plan was treated as absent")
	}
}
