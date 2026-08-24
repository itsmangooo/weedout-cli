package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/itsmangooo/weedout-cli/internal/globalconfig"
)

// `weedout auth`, `link`, `create` and the resolution order they feed.
//
// The property asserted hardest is the one the whole flow exists for: a
// credential must never reach the terminal. Not on success, not with
// --verbose, not in an error message. A token in a scrollback is the problem
// this replaces, and a test that only checks the happy path would not notice
// it being reintroduced.

// authServer stands in for the device flow. It approves on the second poll,
// which is what a person clicking in a browser looks like from here.
func authServer(t *testing.T, opts ...func(*authFake)) *authFake {
	t.Helper()
	fake := &authFake{token: "woa_test-token", email: "dev@example.com", approveAfter: 1}
	for _, apply := range opts {
		apply(fake)
	}

	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/cli-auth/start":
			body, _ := io.ReadAll(r.Body)
			fake.startBody = string(body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_code":        "HXKR-2FQP",
				"verification_url": fake.server.URL + "/cli-auth?code=HXKR-2FQP",
				"device_code":      "device-secret",
				"expires_in":       600,
				// One second, so the test is not slow. Real installs get the
				// server's three.
				"interval": 1,
			})
		case "/api/cli-auth/poll":
			polls := atomic.AddInt32(&fake.polls, 1)
			if int(polls) <= fake.approveAfter {
				_ = json.NewEncoder(w).Encode(map[string]any{"state": "pending", "interval": 1})
				return
			}
			if fake.finalState != "" && fake.finalState != "approved" {
				_ = json.NewEncoder(w).Encode(map[string]any{"state": fake.finalState})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"state": "approved", "token": fake.token, "email": fake.email,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

type authFake struct {
	server       *httptest.Server
	token        string
	email        string
	approveAfter int
	finalState   string
	polls        int32
	startBody    string
}

func TestAuthSavesTheTokenWithoutPrintingIt(t *testing.T) {
	// The whole reason this command exists. A credential that reaches the
	// terminal reaches the scrollback, the shell history, and the screenshot
	// somebody pastes into a chat.
	dir := isolateConfig(t)
	fake := authServer(t)

	code, out := run(t, "auth", "--no-browser", "--url", fake.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(out, fake.token) {
		t.Errorf("the token was printed:\n%s", out)
	}

	raw, err := os.ReadFile(filepath.Join(dir, globalconfig.FileName))
	if err != nil {
		t.Fatalf("nothing was saved: %v", err)
	}
	if !strings.Contains(string(raw), fake.token) {
		t.Errorf("the token was not saved:\n%s", raw)
	}
}

func TestAuthShowsTheCodeAndTheURL(t *testing.T) {
	// The code is what somebody compares against the browser. Without both on
	// screen the flow has no security property at all.
	isolateConfig(t)
	fake := authServer(t)

	_, out := run(t, "auth", "--no-browser", "--url", fake.server.URL)

	if !strings.Contains(out, "HXKR-2FQP") {
		t.Errorf("the code was not shown:\n%s", out)
	}
	if !strings.Contains(out, "/cli-auth?code=HXKR-2FQP") {
		t.Errorf("the URL was not shown:\n%s", out)
	}
	if !strings.Contains(out, "same code") {
		t.Errorf("the page was not told what to check:\n%s", out)
	}
}

func TestAuthSaysWhoItSignedInAs(t *testing.T) {
	isolateConfig(t)
	fake := authServer(t)

	_, out := run(t, "auth", "--no-browser", "--url", fake.server.URL)

	if !strings.Contains(out, "dev@example.com") {
		t.Errorf("the account was not named:\n%s", out)
	}
}

func TestAuthSendsAMachineLabel(t *testing.T) {
	// Shown on the approval page, so somebody can tell their own laptop from a
	// request they did not make.
	isolateConfig(t)
	fake := authServer(t)

	run(t, "auth", "--no-browser", "--label", "work-laptop", "--url", fake.server.URL)

	if !strings.Contains(fake.startBody, "work-laptop") {
		t.Errorf("the label was not sent:\n%s", fake.startBody)
	}
}

func TestAuthWaitsThroughPendingPolls(t *testing.T) {
	isolateConfig(t)
	fake := authServer(t, func(f *authFake) { f.approveAfter = 2 })

	code, out := run(t, "auth", "--no-browser", "--url", fake.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if atomic.LoadInt32(&fake.polls) < 3 {
		t.Errorf("gave up after %d polls", fake.polls)
	}
}

func TestARefusedRequestFailsAndSavesNothing(t *testing.T) {
	dir := isolateConfig(t)
	fake := authServer(t, func(f *authFake) { f.finalState = "denied" })

	code, out := run(t, "auth", "--no-browser", "--url", fake.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if !strings.Contains(out, "refused") {
		t.Errorf("the outcome was not explained:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, globalconfig.FileName)); err == nil {
		t.Error("a refused login wrote a config file")
	}
}

func TestAnExpiredRequestSaysToTryAgain(t *testing.T) {
	isolateConfig(t)
	fake := authServer(t, func(f *authFake) { f.finalState = "expired" })

	code, out := run(t, "auth", "--no-browser", "--url", fake.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if !strings.Contains(out, "again") {
		t.Errorf("no way forward was offered:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// logout and whoami
// ---------------------------------------------------------------------------

func signedInConfig(t *testing.T, projects map[string]globalconfig.Project) string {
	t.Helper()
	dir := isolateConfig(t)
	file := globalconfig.File{Token: "woa_test-token", Email: "dev@example.com"}
	if projects != nil {
		file.Projects = projects
	}
	if err := globalconfig.Save(file); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLogoutForgetsTheTokenAndKeepsProjectKeys(t *testing.T) {
	// Somebody signing out because a laptop is being handed on needs to know
	// the project keys are still there, and that --all is how they go.
	signedInConfig(t, map[string]globalconfig.Project{
		normaliseForTest(t, "/repos/app"): {ID: 1, Name: "app", Key: "wo_key"},
	})

	code, out := run(t, "logout")

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	file, _ := globalconfig.Load()
	if file.SignedIn() {
		t.Error("the token survived")
	}
	if len(file.Projects) != 1 {
		t.Error("the project keys were removed without --all")
	}
	if !strings.Contains(out, "--all") {
		t.Errorf("the remaining keys were not mentioned:\n%s", out)
	}
}

func TestLogoutAllRemovesEverything(t *testing.T) {
	signedInConfig(t, map[string]globalconfig.Project{
		normaliseForTest(t, "/repos/app"): {ID: 1, Key: "wo_key"},
	})

	run(t, "logout", "--all")

	file, _ := globalconfig.Load()
	if file.SignedIn() || len(file.Projects) != 0 {
		t.Errorf("something survived: %+v", file)
	}
}

func TestLogoutSaysTheServerStillHasIt(t *testing.T) {
	// Forgetting a credential locally is not revoking it, and somebody
	// signing out of a stolen laptop needs to know the difference.
	signedInConfig(t, nil)

	_, out := run(t, "logout")

	if !strings.Contains(out, "Revoke") {
		t.Errorf("revocation was not mentioned:\n%s", out)
	}
}

func TestLogoutOnAMachineThatWasNeverSignedIn(t *testing.T) {
	isolateConfig(t)

	code, out := run(t, "logout")

	if code != ExitOK {
		t.Errorf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "not signed in") {
		t.Errorf("unclear message:\n%s", out)
	}
}

func TestWhoamiSaysWhoAndWhere(t *testing.T) {
	signedInConfig(t, nil)

	code, out := run(t, "whoami")

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "dev@example.com") {
		t.Errorf("the account was not named:\n%s", out)
	}
	if !strings.Contains(out, globalconfig.FileName) {
		t.Errorf("the config path was not shown:\n%s", out)
	}
}

func TestWhoamiOnAFreshMachinePointsAtAuth(t *testing.T) {
	isolateConfig(t)

	_, out := run(t, "whoami")

	if !strings.Contains(out, "weedout auth") {
		t.Errorf("no way forward was offered:\n%s", out)
	}
}

func TestWhoamiJSONNeverCarriesAKey(t *testing.T) {
	// `whoami --json` is the kind of thing that ends up piped into a log.
	dir := t.TempDir()
	t.Setenv(globalconfig.EnvConfigHome, dir)
	file := globalconfig.File{Token: "woa_test-token", Email: "dev@example.com"}
	cwd, _ := os.Getwd()
	if _, err := file.Link(cwd, globalconfig.Project{ID: 1, Name: "app", Key: "wo_secret"}); err != nil {
		t.Fatal(err)
	}
	if err := globalconfig.Save(file); err != nil {
		t.Fatal(err)
	}

	code, out := run(t, "whoami", "--json")

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(out, "wo_secret") {
		t.Errorf("a project key was printed:\n%s", out)
	}
	if strings.Contains(out, "woa_test-token") {
		t.Errorf("the machine credential was printed:\n%s", out)
	}
	if !strings.Contains(out, `"signed_in"`) {
		t.Errorf("the JSON was not the expected shape:\n%s", out)
	}
}

func normaliseForTest(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	file := globalconfig.File{Projects: map[string]globalconfig.Project{}}
	key, err := file.Link(absolute, globalconfig.Project{})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
