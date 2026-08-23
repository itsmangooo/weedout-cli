package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two things this covers, and the first is a bug rather than a feature.
//
// `.weedout.yml` was documented, parsed by the server, gated as a Pro
// capability -- and never uploaded by anything. The server accepts it as a
// multipart field on /api/v1/scan and no client sent one, so every rule anybody
// wrote in a repository was dead text. These tests are what keeps it sent.
//
// The second is `--profile`, which is resolved server-side. The CLI's job is
// only to pass the name along and not to interpret it.

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("could not write %s: %v", name, err)
	}
	return path
}

const POLICY = "severity:\n  direct: high\n"

func TestAScanSendsThePolicyFileBesideTheManifest(t *testing.T) {
	rec := serveJSON(t, "/api/v1/scan", 200, map[string]any{"project": "demo"})
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.15"}}`)
	writeFile(t, dir, ".weedout.yml", POLICY)

	code, out := run(t, "scan", dir, "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(rec.body, "name=\"policy\"") {
		t.Errorf("the policy file was not uploaded:\n%s", rec.body)
	}
	if !strings.Contains(rec.body, "direct: high") {
		t.Errorf("the policy contents were not sent:\n%s", rec.body)
	}
}

func TestTheYamlSpellingIsAcceptedToo(t *testing.T) {
	// Insisting on one spelling of a YAML extension is a way to have people
	// write a config that silently does nothing.
	rec := serveJSON(t, "/api/v1/scan", 200, map[string]any{"project": "demo"})
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.15"}}`)
	writeFile(t, dir, ".weedout.yaml", POLICY)

	run(t, "scan", dir, "--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(rec.body, "direct: high") {
		t.Errorf(".weedout.yaml was not picked up:\n%s", rec.body)
	}
}

func TestThePolicyFileIsFoundAboveTheManifest(t *testing.T) {
	// A monorepo keeps its rules at the root and its lockfiles in packages.
	rec := serveJSON(t, "/api/v1/scan", 200, map[string]any{"project": "demo"})
	root := t.TempDir()
	writeFile(t, root, ".weedout.yml", POLICY)
	nested := filepath.Join(root, "services", "api")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, nested, "package.json", `{"dependencies":{"lodash":"4.17.15"}}`)

	run(t, "scan", nested, "--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(rec.body, "direct: high") {
		t.Errorf("the rules at the repository root were not found:\n%s", rec.body)
	}
}

func TestAScanWithoutAPolicyFileSendsNone(t *testing.T) {
	rec := serveJSON(t, "/api/v1/scan", 200, map[string]any{"project": "demo"})
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.15"}}`)

	code, out := run(t, "scan", dir, "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(rec.body, "name=\"policy\"") {
		t.Errorf("an empty policy part was sent:\n%s", rec.body)
	}
}

func TestVerboseSaysWhereTheRulesCameFrom(t *testing.T) {
	// "Why did this scan report that?" is answered by knowing which file
	// applied, and a file found three directories up is not obvious.
	rec := serveJSON(t, "/api/v1/scan", 200, map[string]any{"project": "demo"})
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.15"}}`)
	writeFile(t, dir, ".weedout.yml", POLICY)

	_, out := run(t, "scan", dir, "--verbose", "--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(out, "Rules from") {
		t.Errorf("verbose did not name the policy file:\n%s", out)
	}
}

func TestVerboseSaysWhenThereAreNoRules(t *testing.T) {
	rec := serveJSON(t, "/api/v1/scan", 200, map[string]any{"project": "demo"})
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.15"}}`)

	_, out := run(t, "scan", dir, "--verbose", "--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(out, "No .weedout.yml found") {
		t.Errorf("verbose was silent about the absent file:\n%s", out)
	}
}

func TestScanSendsTheProfileName(t *testing.T) {
	rec := serveJSON(t, "/api/v1/scan", 200, map[string]any{"project": "demo"})
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.15"}}`)

	run(t, "scan", dir, "--profile", "production", "--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(rec.body, "name=\"profile\"") || !strings.Contains(rec.body, "production") {
		t.Errorf("the profile was not sent:\n%s", rec.body)
	}
}

func TestAProfileTheServerRejectsFailsTheScan(t *testing.T) {
	// Resolved server-side, and a name that does not exist is a refusal rather
	// than a scan on the defaults. Exit 2, because the scan did not run --
	// which is the distinction a pipeline gates on.
	rec := serveJSON(t, "/api/v1/scan", 400, map[string]any{
		"error":   "no_such_profile",
		"message": "There is no rule profile called 'production' on this account.",
	})
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.15"}}`)

	code, out := run(t, "scan", dir, "--profile", "production",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d: %s", ExitError, code, out)
	}
	if !strings.Contains(out, "no rule profile") {
		t.Errorf("the reason was not shown:\n%s", out)
	}
}

func TestProfilesListsThemAndSaysWhichApplies(t *testing.T) {
	rec := serveJSON(t, "/api/v1/profiles", 200, map[string]any{
		"profiles": []map[string]any{
			{
				"name":        "Production",
				"slug":        "production",
				"description": "What everything customer-facing runs under.",
				"is_default":  true,
				"in_use_here": false,
			},
			{"name": "Internal tools", "slug": "internal-tools", "in_use_here": true},
		},
		"applies_here": "internal-tools",
	})

	code, out := run(t, "profiles", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	for _, want := range []string{"production", "internal-tools", "account default", "chosen here"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The question the listing is usually opened for.
	if !strings.Contains(out, "A scan here runs under internal-tools") {
		t.Errorf("the effective profile was not stated:\n%s", out)
	}
}

func TestProfilesSaysSoWhenThereAreNone(t *testing.T) {
	rec := serveJSON(t, "/api/v1/profiles", 200, map[string]any{
		"profiles": []map[string]any{}, "applies_here": "",
	})

	code, out := run(t, "profiles", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "None yet") {
		t.Errorf("an empty list was left blank:\n%s", out)
	}
}

func TestProfilesJSONIsTheWholeEnvelope(t *testing.T) {
	rec := serveJSON(t, "/api/v1/profiles", 200, map[string]any{
		"profiles":     []map[string]any{{"name": "Production", "slug": "production"}},
		"applies_here": "production",
	})

	code, out := run(t, "profiles", "--json", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, `"applies_here"`) {
		t.Errorf("the JSON dropped the effective profile:\n%s", out)
	}
}
