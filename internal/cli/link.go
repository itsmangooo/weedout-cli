package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/itsmangooo/weedout-cli/internal/api"
	"github.com/itsmangooo/weedout-cli/internal/detect"
	"github.com/itsmangooo/weedout-cli/internal/globalconfig"
	"github.com/itsmangooo/weedout-cli/internal/ui"
)

// `weedout link` and `weedout create` — connecting a checkout to a project.
//
// Both end the same way: a project key arrives in the response to the request
// that asked for it, and is written to the global config against this
// directory's absolute path. Nobody copies a credential out of a browser, and
// nobody puts one inside a working tree.
//
// The distinction between them is only what happens on the server. `create`
// makes a new project; `link` attaches to one that exists. Running `link` in a
// directory with a lockfile and no matching project offers to create one,
// because "no such project" is not an answer anybody wants.

func runLink(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("link", flag.ContinueOnError)
	fs.SetOutput(stderr)
	projectID := fs.Int("project", 0, "the project to link to, by id")
	scope := fs.String("scope", "scan", "what the key may do: scan, read or manage")
	baseURL := fs.String("url", "", "API base URL")
	timeout := fs.Int("timeout", 30, "seconds to wait")

	path, err := parseWithPath(fs, argv)
	if err != nil {
		return ExitError
	}
	dir := resolveDir(path)

	file, token, endpoint, ok := signedIn(printer, *baseURL)
	if !ok {
		return ExitError
	}
	wait := time.Duration(*timeout) * time.Second

	if existing, at, found := file.ProjectFor(dir); found {
		printer.Line(printer.Dim(fmt.Sprintf(
			"%s is already linked to %s (project %d).", at, existing.Name, existing.ID)))
		printer.Line(printer.Dim("Run `weedout unlink` first to point it somewhere else."))
		return ExitOK
	}

	projects, err := api.ListAccountProjects(endpoint, token, wait)
	if err != nil {
		return fail(printer, err)
	}

	chosen, ok := chooseProject(printer, projects.Projects, *projectID, dir)
	if !ok {
		return ExitError
	}

	issued, err := api.MintKey(endpoint, token, chosen.ID, *scope, wait)
	if err != nil {
		return fail(printer, err)
	}

	return storeLink(printer, file, dir, issued)
}

func runCreate(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ecosystem := fs.String("ecosystem", "", "npm, PyPI, Go, crates.io or Maven — only needed with no lockfile")
	scope := fs.String("scope", "scan", "what the key may do: scan, read or manage")
	baseURL := fs.String("url", "", "API base URL")
	timeout := fs.Int("timeout", 30, "seconds to wait")

	name, err := parseWithPath(fs, argv)
	if err != nil {
		return ExitError
	}

	dir, err := os.Getwd()
	if err != nil {
		printer.Line(printer.Red("Could not read the working directory."))
		return ExitError
	}
	if strings.TrimSpace(name) == "" {
		// The directory name, which is what somebody would have typed anyway.
		name = filepath.Base(dir)
	}

	file, token, endpoint, ok := signedIn(printer, *baseURL)
	if !ok {
		return ExitError
	}

	if _, at, found := file.ProjectFor(dir); found {
		printer.Line(printer.Red(fmt.Sprintf("%s is already linked to a project.", at)))
		printer.Line(printer.Dim("Run `weedout unlink` first, or `weedout create` elsewhere."))
		return ExitError
	}

	// A lockfile if there is one. Sent so the project starts with real
	// contents rather than as an empty shell waiting for its first scan.
	filename, content := manifestBeside(dir)
	if content == "" && strings.TrimSpace(*ecosystem) == "" {
		printer.Line(printer.Red("No lockfile here, so I need to know which ecosystem."))
		printer.Line(printer.Dim(
			"  weedout create --ecosystem npm       (or PyPI, Go, crates.io, Maven)"))
		printer.Line(printer.Dim(
			"It is never guessed: it decides which advisories this project is matched against."))
		return ExitError
	}

	issued, err := api.CreateProject(
		endpoint, token, name, filename, content, *ecosystem, *scope,
		time.Duration(*timeout)*time.Second,
	)
	if err != nil {
		return fail(printer, err)
	}

	return storeLink(printer, file, dir, issued)
}

func runUnlink(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("unlink", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path, err := parseWithPath(fs, argv)
	if err != nil {
		return ExitError
	}
	dir := resolveDir(path)

	file, err := globalconfig.Load()
	if err != nil {
		return fail(printer, err)
	}
	if !file.Unlink(dir) {
		printer.Line(printer.Dim("That directory is not linked to a project."))
		return ExitOK
	}
	if err := globalconfig.Save(file); err != nil {
		return fail(printer, err)
	}

	printer.Line(printer.Green("Unlinked."))
	// The key still exists on the server. Saying so is the difference between
	// somebody thinking they revoked something and actually having done it.
	printer.Line(printer.Dim(
		"The key is forgotten locally but still valid. Revoke it in the project's " +
			"settings if it should stop working."))
	return ExitOK
}

// runKeyRegenerate replaces the key for the linked project.
func runKey(argv []string, printer *ui.Printer, stderr io.Writer) int {
	if len(argv) == 0 || argv[0] != "regenerate" && argv[0] != "rotate" {
		fmt.Fprint(stderr, `weedout key — the credential this directory scans with.

  weedout key regenerate    replace it with a fresh one

The old key keeps working until the new one is saved, so a failure part-way
leaves you with something that works rather than nothing.
`)
		return ExitError
	}

	fs := flag.NewFlagSet("key regenerate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	scope := fs.String("scope", "scan", "what the new key may do: scan, read or manage")
	baseURL := fs.String("url", "", "API base URL")
	timeout := fs.Int("timeout", 30, "seconds to wait")
	if err := fs.Parse(argv[1:]); err != nil {
		return ExitError
	}

	dir, err := os.Getwd()
	if err != nil {
		printer.Line(printer.Red("Could not read the working directory."))
		return ExitError
	}

	file, token, endpoint, ok := signedIn(printer, *baseURL)
	if !ok {
		return ExitError
	}

	project, _, found := file.ProjectFor(dir)
	if !found {
		printer.Line(printer.Red("This directory is not linked to a project."))
		printer.Line(printer.Dim("Run `weedout link` first."))
		return ExitError
	}

	// The server mints before it revokes, and the id of the key being replaced
	// is not something the CLI knows -- it holds the token, not the row. So
	// the old one is left for the dashboard to clean up rather than guessed
	// at, which is the safe direction: an extra live key somebody can see and
	// revoke beats revoking the wrong one.
	issued, err := api.RegenerateKey(
		endpoint, token, project.ID, 0, *scope, time.Duration(*timeout)*time.Second,
	)
	if err != nil {
		return fail(printer, err)
	}

	project.Key = issued.Key
	if _, err := file.Link(dir, project); err != nil {
		return fail(printer, err)
	}
	if err := globalconfig.Save(file); err != nil {
		return fail(printer, err)
	}

	printer.Line(printer.Green("A new key is in place for " + project.Name + "."))
	printer.Line(printer.Dim(
		"The previous one is still valid. Revoke it under API keys in the project's " +
			"settings once nothing is using it."))
	return ExitOK
}

// signedIn resolves the machine credential, or explains how to get one.
func signedIn(printer *ui.Printer, urlFlag string) (globalconfig.File, string, string, bool) {
	file, err := globalconfig.Load()
	if err != nil {
		printer.Line(printer.Red(err.Error()))
		return file, "", "", false
	}
	if !file.SignedIn() {
		printer.Line(printer.Red("This machine is not signed in."))
		printer.Line(printer.Dim("  weedout auth"))
		return file, "", "", false
	}
	return file, file.Token, resolveAuthURL(urlFlag, file), true
}

// storeLink writes the issued key against this directory and says what happened.
func storeLink(
	printer *ui.Printer, file globalconfig.File, dir string, issued api.IssuedKey,
) int {
	at, err := file.Link(dir, globalconfig.Project{
		ID:   issued.Project.ID,
		Name: issued.Project.Name,
		Key:  issued.Key,
	})
	if err != nil {
		return fail(printer, err)
	}
	if err := globalconfig.Save(file); err != nil {
		return fail(printer, err)
	}

	path, _ := globalconfig.Path()
	printer.Line()
	printer.Line(printer.Green(fmt.Sprintf(
		"%s is linked to %s (project %d).", at, issued.Project.Name, issued.Project.ID)))
	// The key is not printed. It went straight from the response to a 0600
	// file, which is the whole point of doing it this way.
	printer.Line(printer.Dim(fmt.Sprintf("A %s key was saved to %s", issued.Scope, path)))
	printer.Line(printer.Dim("Run `weedout scan` here."))
	return ExitOK
}

// chooseProject picks the project to link to.
//
// By id when one was given, by an exact name match against the directory when
// that is unambiguous, and otherwise by asking. Guessing between two similarly
// named projects would be the worst outcome: results pushed to the wrong one
// look correct until somebody notices the count is off.
func chooseProject(
	printer *ui.Printer, projects []api.AccountProject, wanted int, dir string,
) (api.AccountProject, bool) {
	if wanted > 0 {
		for _, project := range projects {
			if project.ID == wanted {
				return project, true
			}
		}
		printer.Line(printer.Red(fmt.Sprintf("No project %d on this account.", wanted)))
		return api.AccountProject{}, false
	}

	if len(projects) == 0 {
		printer.Line(printer.Red("There are no projects on this account yet."))
		printer.Line(printer.Dim("  weedout create"))
		return api.AccountProject{}, false
	}

	base := strings.ToLower(filepath.Base(dir))
	matches := make([]api.AccountProject, 0, 1)
	for _, project := range projects {
		if strings.ToLower(project.Name) == base {
			matches = append(matches, project)
		}
	}
	if len(matches) == 1 {
		printer.Line(printer.Dim("Matching this directory to " + matches[0].Name + "."))
		return matches[0], true
	}

	printer.Line()
	printer.Line("  ", printer.Bold("Which project?"))
	for _, project := range projects {
		printer.Line("    ", printer.Bold(strconv.Itoa(project.ID)), "  ", project.Name)
	}
	printer.Line()
	printer.Line("  ", printer.Dim("weedout link --project ID"))
	return api.AccountProject{}, false
}

// manifestBeside finds a lockfile to seed a new project with, if there is one.
func manifestBeside(dir string) (string, string) {
	match, found, err := detect.Find(dir)
	if err != nil || !found {
		return "", ""
	}
	content, err := os.ReadFile(match.Path) //nolint:gosec // a path this user just pointed at
	if err != nil {
		return "", ""
	}
	if len(content) > api.MaxManifestBytes {
		// Too large to send here. The project is created empty and the first
		// scan, which has its own handling for this, reports it properly.
		return "", ""
	}
	return filepath.Base(match.Path), string(content)
}

func resolveDir(path string) string {
	if strings.TrimSpace(path) == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "."
		}
		return cwd
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absolute
}
