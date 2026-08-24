package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsmangooo/weedout-cli/internal/config"
	"github.com/itsmangooo/weedout-cli/internal/globalconfig"
)

// Connecting a checkout to a project.
//
// Both `link` and `create` end the same way: a project key arrives in the
// response to the request that asked for it, and goes to a 0600 file. Nobody
// copies a credential out of a browser, and nobody puts one inside a working
// tree.
//
// `TestResolutionOrder` at the bottom is the part with teeth. Four sources can
// supply a key, and the order between them decides whether a CI run
// authenticates as the account it was configured with.

type accountFake struct {
	server   *httptest.Server
	lastPath string
	lastBody string
	projects []map[string]any
	status   int
}

func accountServer(t *testing.T, fake *accountFake) *accountFake {
	t.Helper()
	if fake == nil {
		fake = &accountFake{}
	}
	if fake.status == 0 {
		fake.status = 200
	}

	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.lastPath = r.URL.Path
		if body, err := io.ReadAll(r.Body); err == nil {
			fake.lastBody = string(body)
		}
		w.Header().Set("Content-Type", "application/json")

		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer woa_") {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "unauthenticated", "message": "Run `weedout auth`.",
			})
			return
		}

		switch r.URL.Path {
		case "/api/account/projects":
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(map[string]any{"projects": fake.projects})
				return
			}
			w.WriteHeader(fake.status)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project": map[string]any{"id": 7, "name": "checkout-api"},
				"key":     "wo_new-key",
				"scope":   "scan",
			})
		case "/api/account/keys", "/api/account/keys/regenerate":
			w.WriteHeader(fake.status)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project": map[string]any{"id": 7, "name": "checkout-api"},
				"key":     "wo_new-key",
				"scope":   "scan",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// inDir runs the rest of the test with the working directory changed.
func inDir(t *testing.T, dir string) {
	t.Helper()
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
}

func machineSignedIn(t *testing.T) {
	t.Helper()
	isolateConfig(t)
	if err := globalconfig.Save(globalconfig.File{
		Token: "woa_test-token", Email: "dev@example.com",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLinkNeedsAMachineCredential(t *testing.T) {
	isolateConfig(t)
	inDir(t, t.TempDir())

	code, out := run(t, "link")

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if !strings.Contains(out, "weedout auth") {
		t.Errorf("no way forward was offered:\n%s", out)
	}
}

func TestLinkSavesTheKeyWithoutPrintingIt(t *testing.T) {
	machineSignedIn(t)
	dir := t.TempDir()
	inDir(t, dir)
	fake := accountServer(t, &accountFake{
		projects: []map[string]any{{"id": 7, "name": "checkout-api"}},
	})

	code, out := run(t, "link", "--project", "7", "--url", fake.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(out, "wo_new-key") {
		t.Errorf("the key was printed:\n%s", out)
	}

	file, _ := globalconfig.Load()
	project, _, found := file.ProjectFor(dir)
	if !found || project.Key != "wo_new-key" {
		t.Errorf("the key was not saved: %+v", file.Projects)
	}
}

func TestLinkRefusesAnIdThatIsNotOnTheAccount(t *testing.T) {
	machineSignedIn(t)
	inDir(t, t.TempDir())
	fake := accountServer(t, &accountFake{
		projects: []map[string]any{{"id": 7, "name": "checkout-api"}},
	})

	code, out := run(t, "link", "--project", "99", "--url", fake.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if !strings.Contains(out, "No project 99") {
		t.Errorf("unclear message:\n%s", out)
	}
}

func TestLinkMatchesTheDirectoryNameWhenItIsUnambiguous(t *testing.T) {
	machineSignedIn(t)
	root := t.TempDir()
	dir := filepath.Join(root, "checkout-api")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	inDir(t, dir)
	fake := accountServer(t, &accountFake{
		projects: []map[string]any{
			{"id": 7, "name": "checkout-api"},
			{"id": 8, "name": "billing"},
		},
	})

	code, out := run(t, "link", "--url", fake.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "checkout-api") {
		t.Errorf("the match was not explained:\n%s", out)
	}
}

func TestLinkAsksRatherThanGuessingBetweenProjects(t *testing.T) {
	// Guessing would be the worst outcome: results pushed to the wrong project
	// look correct until somebody notices the count is off.
	machineSignedIn(t)
	inDir(t, t.TempDir())
	fake := accountServer(t, &accountFake{
		projects: []map[string]any{
			{"id": 7, "name": "checkout-api"},
			{"id": 8, "name": "billing"},
		},
	})

	code, out := run(t, "link", "--url", fake.server.URL)

	if code != ExitError {
		t.Errorf("expected a refusal, got exit %d", code)
	}
	if !strings.Contains(out, "Which project?") {
		t.Errorf("the choice was not offered:\n%s", out)
	}
	if !strings.Contains(out, "--project ID") {
		t.Errorf("no way to answer was given:\n%s", out)
	}
}

func TestLinkWithNoProjectsAtAllPointsAtCreate(t *testing.T) {
	machineSignedIn(t)
	inDir(t, t.TempDir())
	fake := accountServer(t, &accountFake{projects: []map[string]any{}})

	code, out := run(t, "link", "--url", fake.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if !strings.Contains(out, "weedout create") {
		t.Errorf("no way forward was offered:\n%s", out)
	}
}

func TestLinkingAnAlreadyLinkedDirectoryIsRefusedGently(t *testing.T) {
	machineSignedIn(t)
	dir := t.TempDir()
	inDir(t, dir)
	file, _ := globalconfig.Load()
	if _, err := file.Link(dir, globalconfig.Project{ID: 3, Name: "already"}); err != nil {
		t.Fatal(err)
	}
	if err := globalconfig.Save(file); err != nil {
		t.Fatal(err)
	}
	fake := accountServer(t, nil)

	code, out := run(t, "link", "--url", fake.server.URL)

	if code != ExitOK {
		t.Errorf("this is not a failure: exit %d", code)
	}
	if !strings.Contains(out, "weedout unlink") {
		t.Errorf("no way forward was offered:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

func TestCreateSendsTheLockfileBesideIt(t *testing.T) {
	// So the project starts with real contents rather than as an empty shell
	// waiting for its first scan.
	machineSignedIn(t)
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.15"}}`)
	inDir(t, dir)
	fake := accountServer(t, nil)

	code, out := run(t, "create", "checkout-api", "--url", fake.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(fake.lastBody, "lodash") {
		t.Errorf("the lockfile was not sent:\n%s", fake.lastBody)
	}
}

func TestCreateWithNoLockfileNeedsAnEcosystem(t *testing.T) {
	// Never guessed: it decides which advisories the project is matched
	// against, and a project that silently changed would reinterpret every
	// finding recorded against it.
	machineSignedIn(t)
	inDir(t, t.TempDir())
	fake := accountServer(t, nil)

	code, out := run(t, "create", "empty", "--url", fake.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if !strings.Contains(out, "--ecosystem") {
		t.Errorf("no way forward was offered:\n%s", out)
	}
	if fake.lastPath != "" {
		t.Error("a request was made before the local check")
	}
}

func TestCreateWithAnEcosystemAndNoLockfileWorks(t *testing.T) {
	machineSignedIn(t)
	inDir(t, t.TempDir())
	fake := accountServer(t, nil)

	code, out := run(t, "create", "empty", "--ecosystem", "npm", "--url", fake.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(fake.lastBody, `"ecosystem":"npm"`) {
		t.Errorf("the ecosystem was not sent:\n%s", fake.lastBody)
	}
}

func TestCreateDefaultsTheNameToTheDirectory(t *testing.T) {
	machineSignedIn(t)
	root := t.TempDir()
	dir := filepath.Join(root, "my-service")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.15"}}`)
	inDir(t, dir)
	fake := accountServer(t, nil)

	run(t, "create", "--url", fake.server.URL)

	if !strings.Contains(fake.lastBody, "my-service") {
		t.Errorf("the directory name was not used:\n%s", fake.lastBody)
	}
}

// ---------------------------------------------------------------------------
// unlink and key regenerate
// ---------------------------------------------------------------------------

func TestUnlinkSaysTheKeyStillWorks(t *testing.T) {
	// Forgetting a key locally is not revoking it, and somebody who thinks it
	// is has a live credential they believe is dead.
	machineSignedIn(t)
	dir := t.TempDir()
	inDir(t, dir)
	file, _ := globalconfig.Load()
	if _, err := file.Link(dir, globalconfig.Project{ID: 3, Key: "wo_key"}); err != nil {
		t.Fatal(err)
	}
	if err := globalconfig.Save(file); err != nil {
		t.Fatal(err)
	}

	code, out := run(t, "unlink")

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "still valid") {
		t.Errorf("the key was implied to be revoked:\n%s", out)
	}
	reloaded, _ := globalconfig.Load()
	if _, _, found := reloaded.ProjectFor(dir); found {
		t.Error("it is still linked")
	}
}

func TestKeyRegenerateReplacesTheStoredKey(t *testing.T) {
	machineSignedIn(t)
	dir := t.TempDir()
	inDir(t, dir)
	file, _ := globalconfig.Load()
	if _, err := file.Link(dir, globalconfig.Project{
		ID: 7, Name: "checkout-api", Key: "wo_old",
	}); err != nil {
		t.Fatal(err)
	}
	if err := globalconfig.Save(file); err != nil {
		t.Fatal(err)
	}
	fake := accountServer(t, nil)

	code, out := run(t, "key", "regenerate", "--url", fake.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(out, "wo_new-key") {
		t.Errorf("the new key was printed:\n%s", out)
	}
	reloaded, _ := globalconfig.Load()
	project, _, _ := reloaded.ProjectFor(dir)
	if project.Key != "wo_new-key" {
		t.Errorf("the key was not replaced: %q", project.Key)
	}
}

func TestKeyRegenerateSaysTheOldOneIsStillLive(t *testing.T) {
	machineSignedIn(t)
	dir := t.TempDir()
	inDir(t, dir)
	file, _ := globalconfig.Load()
	if _, err := file.Link(dir, globalconfig.Project{ID: 7, Name: "x", Key: "wo_old"}); err != nil {
		t.Fatal(err)
	}
	if err := globalconfig.Save(file); err != nil {
		t.Fatal(err)
	}
	fake := accountServer(t, nil)

	_, out := run(t, "key", "regenerate", "--url", fake.server.URL)

	if !strings.Contains(out, "still valid") {
		t.Errorf("the old key was implied to be dead:\n%s", out)
	}
}

func TestKeyRegenerateNeedsALinkedDirectory(t *testing.T) {
	machineSignedIn(t)
	inDir(t, t.TempDir())
	fake := accountServer(t, nil)

	code, out := run(t, "key", "regenerate", "--url", fake.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if !strings.Contains(out, "weedout link") {
		t.Errorf("no way forward was offered:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Resolution order
// ---------------------------------------------------------------------------

func TestResolutionOrder(t *testing.T) {
	// Four sources can supply a key, and the order between them decides
	// whether a CI run authenticates as the account it was configured with.
	dir := t.TempDir()
	t.Setenv(globalconfig.EnvConfigHome, t.TempDir())

	global := globalconfig.File{Token: "woa_x"}
	if _, err := global.Link(dir, globalconfig.Project{ID: 1, Name: "linked", Key: "from-global"}); err != nil {
		t.Fatal(err)
	}
	if err := globalconfig.Save(global); err != nil {
		t.Fatal(err)
	}

	if err := config.Write(filepath.Join(dir, config.Filename), "from-dotfile", ""); err != nil {
		t.Fatal(err)
	}

	env := func(name string) string {
		if name == config.EnvAPIKey {
			return "from-env"
		}
		return ""
	}
	none := func(string) string { return "" }

	cases := []struct {
		name   string
		flag   string
		env    config.Lookup
		expect string
	}{
		{"the flag beats everything", "from-flag", env, "from-flag"},
		{"the environment beats both files", "", env, "from-env"},
		{"the repository file beats the global map", "", none, "from-dotfile"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := config.Resolve(dir, tc.flag, "", tc.env)
			if got.APIKey != tc.expect {
				t.Errorf("got %q from %s, want %q", got.APIKey, got.KeySource, tc.expect)
			}
		})
	}

	// And the fallback, with no dotfile in the way. This is the case the
	// global config exists for: a developer with eight checkouts and no
	// per-repository setup at all.
	t.Run("the global map is the fallback", func(t *testing.T) {
		if err := os.Remove(filepath.Join(dir, config.Filename)); err != nil {
			t.Fatal(err)
		}
		got := config.Resolve(dir, "", "", none)
		if got.APIKey != "from-global" {
			t.Errorf("got %q from %s, want the linked key", got.APIKey, got.KeySource)
		}
		if !strings.Contains(got.KeySource, "linked") {
			t.Errorf("the source did not say where it came from: %q", got.KeySource)
		}
	})
}

func TestAnUnlinkedDirectoryHasNoKeyAtAll(t *testing.T) {
	t.Setenv(globalconfig.EnvConfigHome, t.TempDir())

	got := config.Resolve(t.TempDir(), "", "", func(string) string { return "" })

	if got.APIKey != "" {
		t.Errorf("a key appeared from nowhere: %q via %s", got.APIKey, got.KeySource)
	}
	if got.KeySource != "nowhere" {
		t.Errorf("source %q, want \"nowhere\"", got.KeySource)
	}
}
