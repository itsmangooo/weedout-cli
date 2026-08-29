package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// TestPackagedCommands runs only when validation points it at the release-style
// artifact. The regular suite exercises source code; this closes the gap where
// a command works in tests but is absent or wired differently in the binary.
func TestPackagedCommands(t *testing.T) {
	binary := os.Getenv("WEEDOUT_PACKAGED_BINARY")
	if binary == "" {
		t.Skip("set WEEDOUT_PACKAGED_BINARY to validate a release-style artifact")
	}
	if absolute, err := filepath.Abs(binary); err == nil {
		binary = absolute
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("packaged binary is unavailable: %v", err)
	}

	configHome := t.TempDir()
	project := t.TempDir()
	writeFixture(t, project)

	var pollCount atomic.Int32
	var sawSourceContext atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/cli-auth/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_code": "ABCD-EFGH", "device_code": "device-secret",
				"verification_url":       serverURL(r) + "/cli-auth?code=ABCD-EFGH",
				"verification_url_plain": serverURL(r) + "/cli-auth",
				"expires_in":             5, "interval": 1,
			})
		case "/api/cli-auth/poll":
			pollCount.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"state": "approved", "token": "woa_machine_secret", "email": "cli@example.com",
			})
		case "/api/account/projects":
			if r.Header.Get("Authorization") != "Bearer woa_machine_secret" {
				writeError(w, http.StatusUnauthorized, "bad machine credential")
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project": map[string]any{"id": 7, "name": "packaged-project"},
				"key":     "wo_project_secret", "scope": "scan",
			})
		case "/api/v1/scan":
			if r.Header.Get("Authorization") == "Bearer bad" {
				writeError(w, http.StatusUnauthorized, "The API key was rejected.")
				return
			}
			if err := r.ParseMultipartForm(8 << 20); err != nil {
				writeError(w, http.StatusBadRequest, "bad multipart scan")
				return
			}
			if strings.Contains(r.FormValue("source_context"), "src/api.js") {
				sawSourceContext.Store(true)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project": "packaged-project", "dependencies_scanned": 1,
				"actionable": 0, "suppressed": 0, "counts": map[string]int{},
				"findings": []any{},
				"reachability": map[string]any{
					"analysis_complete": true, "source_files": 1,
					"counts": map[string]int{"reachable": 1},
				},
			})
		case "/api/v1/findings":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"show": "open", "count": 1,
				"findings": []any{map[string]any{
					"id": 11, "package": "axios", "version": "0.21.1",
					"cve": "CVE-2021-3749", "severity": "high", "status": "open",
					"reachability": "reachable",
					"reachability_evidence": []any{map[string]any{
						"source_file": "src/api.js", "line": 1,
						"explanation": "src/api.js:1 imports axios",
					}},
				}},
			})
		case "/api/v1/rules":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"plan":       map[string]any{"tier": "free", "name": "Free", "custom_rules": true},
				"thresholds": map[string]any{"direct": "high", "transitive": "critical"},
				"ignores":    []any{}, "policy_file": map[string]any{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	for _, command := range [][]string{
		{"--help"}, {"version", "--help"}, {"init", "--help"}, {"auth", "--help"},
		{"create", "--help"}, {"scan", "--help"}, {"findings", "--help"},
		{"rules", "--help"},
	} {
		code, output := runArtifact(t, binary, project, configHome, command...)
		if code != 0 || strings.TrimSpace(output) == "" {
			t.Fatalf("%v help failed with %d:\n%s", command, code, output)
		}
	}

	code, output := runArtifact(t, binary, project, configHome, "version")
	if code != 0 || !strings.Contains(output, "0.0.0-remediation") {
		t.Fatalf("packaged version failed with %d:\n%s", code, output)
	}

	code, output = runArtifact(
		t, binary, project, configHome, "auth", "--no-browser", "--url", server.URL,
	)
	if code != 0 || !strings.Contains(output, "Signed in as cli@example.com") {
		t.Fatalf("packaged auth failed with %d:\n%s", code, output)
	}
	assertNoSecret(t, output)
	if pollCount.Load() == 0 {
		t.Fatal("packaged auth never polled for approval")
	}

	code, output = runArtifact(t, binary, project, configHome, "create", "packaged-project")
	if code != 0 || !strings.Contains(output, "packaged-project") {
		t.Fatalf("packaged create failed with %d:\n%s", code, output)
	}
	assertNoSecret(t, output)

	code, output = runArtifact(t, binary, project, configHome, "scan")
	if code != 0 || !strings.Contains(output, "Reachability") || !sawSourceContext.Load() {
		t.Fatalf("packaged scan failed with %d:\n%s", code, output)
	}
	code, output = runArtifact(t, binary, project, configHome, "findings")
	if code != 0 || !strings.Contains(output, "src/api.js:1 imports axios") {
		t.Fatalf("packaged findings failed with %d:\n%s", code, output)
	}
	code, output = runArtifact(t, binary, project, configHome, "rules")
	if code != 0 || !strings.Contains(output, "Alert when") {
		t.Fatalf("packaged rules failed with %d:\n%s", code, output)
	}

	initDir := t.TempDir()
	code, output = runArtifactEnv(
		t, binary, initDir, configHome, []string{"WEEDOUT_API_KEY=wo_init_secret"}, "init",
	)
	if code != 0 || !strings.Contains(output, "Wrote") {
		t.Fatalf("packaged init failed with %d:\n%s", code, output)
	}
	assertNoSecret(t, output)

	for name, command := range map[string][]string{
		"auth":     {"auth", "--url", "://bad", "--no-browser", "--timeout", "1"},
		"create":   {"create", "another-project"},
		"scan":     {"scan", "--api-key", "bad", "--url", server.URL},
		"findings": {"findings", "--show", "banana"},
		"rules":    {"rules", "not-a-command"},
		"version":  {"version", "unexpected"},
	} {
		code, output = runArtifact(t, binary, project, configHome, command...)
		if code != 2 || strings.TrimSpace(output) == "" {
			t.Errorf("%s failure path returned %d:\n%s", name, code, output)
		}
	}
	emptyConfig := t.TempDir()
	code, output = runArtifact(t, binary, t.TempDir(), emptyConfig, "init")
	if code != 2 || !strings.Contains(output, "No API key") {
		t.Errorf("init failure path returned %d:\n%s", code, output)
	}
}

func writeFixture(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"axios":"0.21.1"}},"node_modules/axios":{"version":"0.21.1"}}}`,
		"src/api.js":        `import axios from "axios";`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func runArtifact(t *testing.T, binary, dir, configHome string, args ...string) (int, string) {
	t.Helper()
	return runArtifactEnv(t, binary, dir, configHome, nil, args...)
}

func runArtifactEnv(
	t *testing.T, binary, dir, configHome string, extraEnv []string, args ...string,
) (int, string) {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Dir = dir
	command.Env = cleanEnv(configHome, extraEnv)
	output, err := command.CombinedOutput()
	if err == nil {
		return 0, string(output)
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode(), string(output)
	}
	t.Fatalf("could not run packaged CLI: %v", err)
	return -1, string(output)
}

func cleanEnv(configHome string, extra []string) []string {
	blocked := []string{"WEEDOUT_API_KEY=", "WEEDOUT_URL=", "WEEDOUT_CONFIG_HOME="}
	environment := make([]string, 0, len(os.Environ())+4)
	for _, entry := range os.Environ() {
		skip := false
		for _, prefix := range blocked {
			if strings.HasPrefix(strings.ToUpper(entry), prefix) {
				skip = true
			}
		}
		if !skip {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "WEEDOUT_CONFIG_HOME="+configHome, "CI=true", "NO_COLOR=1")
	return append(environment, extra...)
}

func assertNoSecret(t *testing.T, output string) {
	t.Helper()
	for _, secret := range []string{"woa_machine_secret", "wo_project_secret", "wo_init_secret"} {
		if strings.Contains(output, secret) {
			t.Fatalf("credential leaked to output: %s", output)
		}
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, fmt.Sprintf(`{"error":{"code":"refused","message":%q}}`, message))
}

func serverURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func TestPackagedArtifactMatchesRuntimePlatform(t *testing.T) {
	binary := os.Getenv("WEEDOUT_PACKAGED_BINARY")
	if binary == "" {
		t.Skip("packaged validation is opt-in")
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(binary), ".exe") {
		t.Fatalf("Windows packaged artifact should be an .exe: %s", binary)
	}
}
