package cli

import (
	"strings"
	"testing"
)

// A Free account listing rules that are not in force.
//
// `weedout rules` prints a tidy list of severity floors and ignore entries.
// On a Free account none of them apply — custom rules are part of Pro — and
// without a word about that, the page is a list of configuration doing
// nothing. That is the exact shape of failure this product exists to avoid:
// something that looks configured and is not.
//
// The warning goes above the list rather than below it. Somebody scrolling
// twelve entries needs to know before they read them, and a footnote under
// twelve entries is a footnote nobody reaches.

func rulesPayloadWithPlan(tier string, custom bool, withRules bool) map[string]any {
	body := map[string]any{
		"plan": map[string]any{
			"tier": tier, "name": strings.ToUpper(tier[:1]) + tier[1:],
			"scan_depth": 1, "custom_rules": custom,
			"scan_interval_hours": 24, "max_projects": 1,
		},
		"thresholds":  map[string]any{},
		"ignores":     []map[string]any{},
		"policy_file": map[string]any{"present": false},
	}
	if withRules {
		body["thresholds"] = map[string]any{"direct": "high", "transitive": "critical"}
		body["ignores"] = []map[string]any{{
			"identifier": "CVE-2021-23337",
			"kind":       "advisory",
			"reason":     "not reachable from our code",
		}}
	}
	return body
}

func TestFreeIsToldItsRulesAreNotApplying(t *testing.T) {
	isolateConfig(t)
	seenPlan(t, "free")
	rec := serveJSON(t, "/api/v1/rules", 200, rulesPayloadWithPlan("free", false, true))

	code, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "None of these are applying") {
		t.Errorf("the rules were listed as if they were in force:\n%s", out)
	}
	// And that nothing was lost, because the obvious next worry is that
	// downgrading deleted them.
	if !strings.Contains(out, "kept exactly as it is") {
		t.Errorf("the message implied the rules were gone:\n%s", out)
	}
}

func TestTheWarningComesBeforeTheList(t *testing.T) {
	isolateConfig(t)
	seenPlan(t, "free")
	rec := serveJSON(t, "/api/v1/rules", 200, rulesPayloadWithPlan("free", false, true))

	_, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	warning := strings.Index(out, "None of these are applying")
	listed := strings.Index(out, "CVE-2021-23337")
	if warning < 0 || listed < 0 {
		t.Fatalf("expected both in:\n%s", out)
	}
	if warning > listed {
		t.Errorf("the warning was below the rules it is about:\n%s", out)
	}
}

func TestProIsNotWarned(t *testing.T) {
	isolateConfig(t)
	seenPlan(t, "pro")
	rec := serveJSON(t, "/api/v1/rules", 200, rulesPayloadWithPlan("pro", true, true))

	_, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	if strings.Contains(out, "None of these are applying") {
		t.Errorf("a Pro account was told its rules were inert:\n%s", out)
	}
}

func TestFreeWithNoRulesIsNotWarnedEither(t *testing.T) {
	// Telling somebody their nothing is not applying is noise, and noise on a
	// page about filtering noise is worse than most.
	isolateConfig(t)
	seenPlan(t, "free")
	rec := serveJSON(t, "/api/v1/rules", 200, rulesPayloadWithPlan("free", false, false))

	_, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	if strings.Contains(out, "None of these are applying") {
		t.Errorf("warned about an empty rule set:\n%s", out)
	}
}

func TestAServerWithNoPlanBlockDoesNotWarn(t *testing.T) {
	// An older deployment says nothing about the plan, and silence must not be
	// read as "no custom rules".
	isolateConfig(t)
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{
		"thresholds":  map[string]any{"direct": "high"},
		"ignores":     []map[string]any{},
		"policy_file": map[string]any{"present": false},
	})

	_, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	if strings.Contains(out, "None of these are applying") {
		t.Errorf("silence was read as a Free plan:\n%s", out)
	}
}

func TestRulesAlsoAnnouncesAPlanChange(t *testing.T) {
	isolateConfig(t)
	seenPlan(t, "free")
	rec := serveJSON(t, "/api/v1/rules", 200, rulesPayloadWithPlan("pro", true, true))

	_, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(out, "Your plan is now Pro") {
		t.Errorf("the change was not mentioned:\n%s", out)
	}
}
