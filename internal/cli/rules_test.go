package cli

import (
	"net/http"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// rules list
// ---------------------------------------------------------------------------

func rulesPayload() map[string]any {
	return map[string]any{
		"thresholds": map[string]any{"direct": "high", "transitive": "critical"},
		"ignores": []map[string]any{{
			"identifier": "CVE-2021-23337",
			"reason":     "not reachable from our code",
			"created_by": "you@example.com",
			"created_at": "2026-08-01T10:00:00+00:00",
		}},
		"policy_file": map[string]any{"present": false},
	}
}

func TestRulesListsThresholdsAndIgnores(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, rulesPayload())

	code, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	for _, want := range []string{"CVE-2021-23337", "not reachable", "you@example.com", "high"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRulesSaysWhenAnIgnoreStoppedApplying(t *testing.T) {
	payload := rulesPayload()
	payload["ignores"].([]map[string]any)[0]["overridden_at"] = "2026-08-10T10:00:00+00:00"

	rec := serveJSON(t, "/api/v1/rules", 200, payload)
	_, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	// Somebody wrote this rule expecting silence and is not getting it. A
	// listing that showed the rule as active would be lying by omission.
	if !strings.Contains(out, "Being reported anyway") {
		t.Errorf("an overridden rule was shown as if it still applied:\n%s", out)
	}
}

func TestRulesReportsABrokenPolicyFileAsFullyIgnored(t *testing.T) {
	payload := rulesPayload()
	payload["policy_file"] = map[string]any{
		"present": true,
		"error":   "line 4: could not parse",
	}

	rec := serveJSON(t, "/api/v1/rules", 200, payload)
	_, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	// The alternative reading is that half the file took effect and nobody can
	// tell which half. Saying it is discarded whole is what makes the failure
	// safe to reason about.
	if !strings.Contains(out, "ignored entirely") {
		t.Errorf("a broken policy file was not explained:\n%s", out)
	}
}

func TestRulesSeparatesRepoRulesFromServerRules(t *testing.T) {
	payload := rulesPayload()
	payload["policy_file"] = map[string]any{
		"present":    true,
		"updated_at": "2026-08-19T10:00:00+00:00",
		"ignores":    []string{"CVE-2020-1111"},
	}

	rec := serveJSON(t, "/api/v1/rules", 200, payload)
	_, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	repoAt := strings.Index(out, "From the repo")
	if repoAt < 0 {
		t.Fatalf("the repo section is missing:\n%s", out)
	}
	// One is reviewed like code and travels with the branch; the other was
	// typed once. Merging them into a single list would hide which is which.
	if !strings.Contains(out[repoAt:], "CVE-2020-1111") {
		t.Errorf("a repo rule was not listed under the repo:\n%s", out)
	}
	if strings.Contains(out[:repoAt], "CVE-2020-1111") {
		t.Errorf("a repo rule leaked into the server list:\n%s", out)
	}
}

func TestRulesSaysNothingIsIgnoredRatherThanPrintingNothing(t *testing.T) {
	payload := rulesPayload()
	payload["ignores"] = []map[string]any{}

	rec := serveJSON(t, "/api/v1/rules", 200, payload)
	_, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(out, "Every advisory that matches is reported") {
		t.Errorf("an empty ignore list was left blank:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// rules ignore
// ---------------------------------------------------------------------------

func TestIgnoreRequiresAReasonBeforeTouchingTheNetwork(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{})

	code, out := run(t, "rules", "ignore", "CVE-2021-23337",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if rec.called() {
		t.Error("a rule with no reason should never reach the server")
	}
	// A rule with no reason is indistinguishable from a mistake six months
	// later, so the message shows the shape of a good one.
	if !strings.Contains(out, "--reason") {
		t.Errorf("the message did not show how to supply one:\n%s", out)
	}
}

func TestIgnoreNeedsAnAdvisory(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{})

	code, out := run(t, "rules", "ignore", "--reason", "because",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if rec.called() {
		t.Error("no advisory was named, so there was nothing to send")
	}
	if !strings.Contains(out, "Which advisory") {
		t.Errorf("unhelpful message:\n%s", out)
	}
}

func TestIgnoreSendsTheIdentifierAndReason(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{
		"identifier": "CVE-2021-23337", "reason": "not reachable",
	})

	code, out := run(t, "rules", "ignore", "CVE-2021-23337",
		"--reason", "not reachable", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if rec.method != http.MethodPost {
		t.Errorf("expected POST, got %s", rec.method)
	}
	if !strings.Contains(rec.body, "CVE-2021-23337") || !strings.Contains(rec.body, "not reachable") {
		t.Errorf("the request body was missing something: %s", rec.body)
	}
}

func TestIgnoreSaysExploitationWillOverrideIt(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{"identifier": "CVE-2021-23337"})

	_, out := run(t, "rules", "ignore", "CVE-2021-23337",
		"--reason", "not reachable", "--api-key", "wo_x", "--url", rec.server.URL)

	// Setting an expectation at the moment the rule is written is worth more
	// than explaining the surprise later.
	if !strings.Contains(out, "known-exploited") {
		t.Errorf("the override was not mentioned:\n%s", out)
	}
}

func TestIgnoreFlagsWorkOnEitherSideOfTheIdentifier(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{"identifier": "CVE-1"})

	code, out := run(t, "rules", "ignore", "--reason", "why", "CVE-1",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(rec.body, "CVE-1") {
		t.Errorf("the identifier was not picked up: %s", rec.body)
	}
}

// ---------------------------------------------------------------------------
// rules unignore
// ---------------------------------------------------------------------------

func TestUnignoreDeletes(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{"removed": true})

	code, out := run(t, "rules", "unignore", "CVE-2021-23337",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if rec.method != http.MethodDelete {
		t.Errorf("expected DELETE, got %s", rec.method)
	}
	if !strings.Contains(out, "being reported again") {
		t.Errorf("the outcome was not stated:\n%s", out)
	}
}

func TestUnignoringSomethingThatWasNotIgnoredSaysSo(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", http.StatusNotFound, map[string]any{
		"error": "no_such_rule", "message": "CVE-2021-23337 is not ignored here.",
	})

	code, out := run(t, "rules", "unignore", "CVE-2021-23337",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if !strings.Contains(out, "not ignored here") {
		t.Errorf("the server's explanation was swallowed:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

func TestRulesWithNoSubcommandLists(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, rulesPayload())

	code, _ := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK || rec.method != http.MethodGet {
		t.Errorf("bare `rules` should list: exit %d, method %s", code, rec.method)
	}
}

func TestAnUnknownRulesSubcommandIsNotTreatedAsAnAdvisory(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, rulesPayload())

	code, out := run(t, "rules", "delete-everything",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if rec.called() {
		t.Error("an unrecognised subcommand should not reach the server")
	}
	if !strings.Contains(out, "Unknown rules command") {
		t.Errorf("unhelpful message:\n%s", out)
	}
}

func TestManageCommandsExplainAScopeRefusal(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", http.StatusForbidden, map[string]any{
		"error": "insufficient_scope",
		"message": "This key can push scans. That endpoint needs a key with " +
			"manage access. Create one in Settings.",
	})

	code, out := run(t, "rules", "ignore", "CVE-1", "--reason", "why",
		"--api-key", "wo_ci", "--url", rec.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if !strings.Contains(out, "manage access") {
		t.Errorf("the refusal did not say which key would work:\n%s", out)
	}
}
