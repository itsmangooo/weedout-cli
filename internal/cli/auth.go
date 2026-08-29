package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/itsmangooo/weedout-cli/internal/api"
	"github.com/itsmangooo/weedout-cli/internal/config"
	"github.com/itsmangooo/weedout-cli/internal/globalconfig"
	"github.com/itsmangooo/weedout-cli/internal/ui"
)

// `weedout auth` — signing this machine in without pasting a credential.
//
// What it replaces is worse than it looks. "Create a key in Settings, copy it,
// paste it into your terminal" puts a live credential through a clipboard, a
// terminal scrollback, a shell history, and often a chat window where somebody
// asked a colleague for help. Every one of those outlives the moment.
//
// So: print a short code, open a browser, wait. The person compares the code
// against what the page shows and approves. The token arrives over the same
// TLS connection the poll went out on, and is written straight to a 0600 file.
// It is never printed — not even with --verbose, because a token in a
// scrollback is the problem this command exists to remove.

// pollDeadline bounds the wait regardless of what the server advertises, so a
// forgotten terminal does not sit polling until the process is killed.
const pollDeadline = 12 * time.Minute

func runAuth(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baseURL := fs.String("url", "", "API base URL")
	noBrowser := fs.Bool("no-browser", false, "print the URL instead of opening it")
	label := fs.String("label", "", "what to call this machine in your account settings")
	timeout := fs.Int("timeout", 30, "seconds to wait for each request")
	if err := fs.Parse(argv); err != nil {
		return flagErrorExit(err)
	}

	existing, _ := globalconfig.Load()
	endpoint := resolveAuthURL(*baseURL, existing)
	wait := time.Duration(*timeout) * time.Second

	started, err := api.StartAuth(endpoint, deviceLabel(*label), wait)
	if err != nil {
		return fail(printer, err)
	}

	printer.Line()
	printer.Line("  ", printer.Bold("Your code is"), "  ", printer.Bold(started.UserCode))
	printer.Line()
	printer.Line("  ", printer.Dim("Open this page and check that it shows the same code:"))
	printer.Line("  ", started.VerificationURL)
	printer.Line()

	if !*noBrowser {
		// A failure to open a browser is not a failure of the command. The URL
		// is already on screen, and plenty of machines that run this have no
		// browser at all.
		if err := openBrowser(started.VerificationURL); err != nil {
			printer.Line("  ", printer.Dim("Could not open a browser. Use the link above."))
			printer.Line()
		}
	}

	printer.Line("  ", printer.Dim("Waiting for you to approve it…"))

	outcome, err := waitForApproval(endpoint, started, wait)
	if err != nil {
		return fail(printer, err)
	}

	switch outcome.State {
	case "approved":
		// Nothing about the token reaches the terminal. It goes from the
		// response to a 0600 file and nowhere else.
		existing.Token = outcome.Token
		existing.Email = outcome.Email
		if endpoint != config.DefaultBaseURL {
			existing.BaseURL = endpoint
		}
		if err := globalconfig.Save(existing); err != nil {
			printer.Line(printer.Red("Signed in, but the credential could not be saved:"))
			printer.Line(printer.Red("  " + err.Error()))
			return ExitError
		}

		path, _ := globalconfig.Path()
		printer.Line()
		printer.Line(printer.Green("Signed in as " + outcome.Email + "."))
		printer.Line(printer.Dim("Saved to " + path))
		printer.Line(printer.Dim(
			"Run `weedout link` in a project directory to connect it, or `weedout logout` " +
				"to sign this machine out."))
		return ExitOK

	case "denied":
		printer.Line()
		printer.Line(printer.Red("That request was refused, so nothing was granted."))
		return ExitError

	default:
		printer.Line()
		printer.Line(printer.Red("That code expired before it was approved."))
		printer.Line(printer.Dim("Run `weedout auth` again for a new one."))
		return ExitError
	}
}

// waitForApproval polls until something conclusive happens or time runs out.
func waitForApproval(endpoint string, started api.AuthStart, wait time.Duration) (api.AuthPoll, error) {
	interval := time.Duration(started.Interval) * time.Second
	if interval < time.Second {
		interval = 3 * time.Second
	}

	deadline := time.Now().Add(pollDeadline)
	if started.ExpiresIn > 0 {
		// The server's window plus a little, so the last poll lands after the
		// request has actually expired and reports that rather than the client
		// giving up first and reporting something vaguer.
		deadline = time.Now().Add(time.Duration(started.ExpiresIn)*time.Second + 5*time.Second)
	}

	for time.Now().Before(deadline) {
		time.Sleep(interval)

		outcome, err := api.PollAuth(endpoint, started.DeviceCode, wait)
		if err != nil {
			// A poll that fails is not a login that failed. Networks blink,
			// and giving up on the first one would make this command flaky in
			// exactly the environments it is most useful in.
			continue
		}

		if outcome.State != "pending" {
			return outcome, nil
		}
		if outcome.Interval > 0 {
			// The server can slow us down without a client release.
			interval = time.Duration(outcome.Interval) * time.Second
		}
	}

	return api.AuthPoll{State: "expired"}, nil
}

// runLogout forgets the account token, and optionally everything else.
func runLogout(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.SetOutput(stderr)
	all := fs.Bool("all", false, "also forget every project key stored on this machine")
	if err := fs.Parse(argv); err != nil {
		return flagErrorExit(err)
	}

	file, err := globalconfig.Load()
	if err != nil {
		return fail(printer, err)
	}
	if !file.SignedIn() && len(file.Projects) == 0 {
		printer.Line(printer.Dim("This machine is not signed in."))
		return ExitOK
	}

	file.Token = ""
	file.Email = ""
	if *all {
		file.Projects = map[string]globalconfig.Project{}
	}

	if err := globalconfig.Save(file); err != nil {
		return fail(printer, err)
	}

	printer.Line(printer.Green("Signed out of this machine."))
	if *all {
		printer.Line(printer.Dim("Project keys on this machine were forgotten too."))
	} else if len(file.Projects) > 0 {
		// Said plainly rather than left implied. Somebody signing out because
		// a laptop is being handed on needs to know the project keys are still
		// there, and that `--all` is how they go.
		printer.Line(printer.Dim(fmt.Sprintf(
			"%d project key(s) are still stored here. Use `weedout logout --all` to remove them.",
			len(file.Projects))))
	}
	// The important half: the local file is only a copy.
	printer.Line(printer.Dim(
		"This only forgets the credential locally. Revoke it under Signed-in machines " +
			"in your account settings if the machine is out of your hands."))
	return ExitOK
}

// runWhoami answers "which account am I, and what is this directory linked to".
func runWhoami(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print the result as JSON instead of prose")
	if err := fs.Parse(argv); err != nil {
		return flagErrorExit(err)
	}

	file, _ := globalconfig.Load()
	path, _ := globalconfig.Path()
	cwd, _ := os.Getwd()
	project, linkedPath, linked := file.ProjectFor(cwd)

	if *asJSON {
		out := map[string]any{
			"signed_in":   file.SignedIn(),
			"email":       file.Email,
			"config_path": path,
			"linked":      linked,
		}
		if linked {
			// The key is deliberately absent. `whoami --json` is the kind of
			// thing that ends up piped into a log.
			out["project"] = map[string]any{
				"id":   project.ID,
				"name": project.Name,
				"path": linkedPath,
			}
		}
		if err := emit(printer.Writer(), out); err != nil {
			fmt.Fprintf(stderr, "Could not encode the result: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	printer.Line()
	if file.SignedIn() {
		printer.Line("  ", printer.Bold("Signed in as"), "  ", file.Email)
	} else {
		printer.Line("  ", printer.Dim("Not signed in. Run `weedout auth`."))
	}
	printer.Line("  ", printer.Dim("Config "+path))
	printer.Line()

	if linked {
		printer.Line("  ", printer.Bold("This directory"), "  ", project.Name)
		printer.Line("    ", printer.Dim(fmt.Sprintf("project %d, linked at %s",
			project.ID, linkedPath)))
	} else {
		printer.Line("  ", printer.Dim("This directory is not linked to a project."))
		printer.Line("  ", printer.Dim("Run `weedout link` to connect it."))
	}
	printer.Line()
	return ExitOK
}

// deviceLabel is what the approval page shows next to "called itself".
//
// The hostname, because that is what somebody recognises. Untrusted on the
// server and displayed as such, so there is nothing to be careful about beyond
// not sending something absurd.
func deviceLabel(override string) string {
	if trimmed := strings.TrimSpace(override); trimmed != "" {
		return truncate(trimmed, 120)
	}
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "an unnamed machine"
	}
	return truncate(strings.TrimSpace(name), 120)
}

func resolveAuthURL(flagValue string, file globalconfig.File) string {
	for _, candidate := range []string{flagValue, os.Getenv(config.EnvBaseURL), file.BaseURL} {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			return strings.TrimRight(trimmed, "/")
		}
	}
	return config.DefaultBaseURL
}

// openBrowser is best-effort by design. The URL is already on screen.
func openBrowser(url string) error {
	var command string
	var args []string

	switch runtime.GOOS {
	case "windows":
		// Through cmd's start, whose first quoted argument is the window
		// title -- hence the empty one, or a URL in quotes is taken as the
		// title and nothing opens.
		command, args = "cmd", []string{"/c", "start", "", url}
	case "darwin":
		command, args = "open", []string{url}
	default:
		command, args = "xdg-open", []string{url}
	}

	return exec.Command(command, args...).Start() //nolint:gosec // fixed command, URL from our own API
}
