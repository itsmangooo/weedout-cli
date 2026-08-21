// Package settings stores preferences that belong to this installation.
//
// Distinct from the config package, which answers "which project and which
// key" and is per-repository. This answers "how does this copy of the tool
// behave", which follows the binary rather than the checkout: whether the
// interactive menu is on, and when the last update check happened.
//
// The file lives beside the executable, so a copy of weedout carries its own
// settings and two copies on one machine do not fight. That location is often
// read-only once installed -- /usr/local/bin, Program Files, a container layer
// -- so a fallback into the user's config directory exists and Path() reports
// which one is in use. Failing to save a preference silently would be worse
// than not offering it.
//
// Same flat key = value format as .weedout, for the same reason: it holds a
// handful of values, and parsing YAML to read them would put a dependency in a
// CI runner for no benefit.
package settings

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Filename is the settings file, kept beside the executable.
const Filename = "weedout.settings"

// Settings is one installation's preferences.
type Settings struct {
	// Interactive turns on the menu when weedout is run with no command.
	Interactive bool
	// UpdateChecks controls the passive "a new version exists" notice.
	UpdateChecks bool
	// LastUpdateCheck is when the release list was last fetched, so a check
	// happens about once a day rather than on every invocation.
	LastUpdateCheck time.Time
	// LatestSeen is the newest version the last check found. Cached so the
	// notice can be printed without going to the network.
	LatestSeen string

	// path is where this was loaded from, and where Save will write.
	path string
	// beside records whether that is next to the executable or the fallback.
	beside bool
}

// Defaults are what an installation does before anyone changes anything.
//
// Interactive is off: the first thing many people do with this tool is put it
// in a pipeline, and a binary that waits for a keypress there would hang a
// build. It is opt-in, once, per installation.
//
// Update checks are on, because a security scanner running months behind its
// advisory handling is a real cost and a dim one-line notice is a small one.
// The check never blocks, never installs anything, and never runs in CI.
func Defaults() Settings {
	return Settings{Interactive: false, UpdateChecks: true}
}

// Path is the file these settings came from, for messages.
func (s Settings) Path() string { return s.path }

// BesideExecutable reports whether settings live next to the binary, as
// intended, or in the fallback location because that directory is read-only.
func (s Settings) BesideExecutable() bool { return s.beside }

// Load reads the settings for this installation.
//
// A missing file is not an error -- it is the normal state of a fresh install,
// and returns the defaults. A malformed one is also not an error: unreadable
// lines are skipped, so a settings file somebody hand-edited badly degrades to
// "the defaults" rather than stopping a scan. Nothing in here is worth
// refusing to work over.
func Load() Settings {
	path, beside := resolvePath()

	loaded := loadFrom(path)
	loaded.beside = beside
	return loaded
}

// loadFrom reads settings from an explicit path.
//
// Split from Load so the parsing can be tested without depending on where the
// test binary happens to live, which is the one thing resolvePath is about.
func loadFrom(path string) Settings {
	loaded := Defaults()
	loaded.path = path
	if path == "" {
		return loaded
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return loaded
	}

	for _, line := range strings.Split(string(content), "\n") {
		key, value, ok := parse(line)
		if !ok {
			continue
		}
		switch key {
		case "interactive":
			loaded.Interactive = truthy(value)
		case "update_checks":
			loaded.UpdateChecks = truthy(value)
		case "last_update_check":
			if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
				loaded.LastUpdateCheck = time.Unix(seconds, 0)
			}
		case "latest_seen":
			loaded.LatestSeen = value
		}
	}
	return loaded
}

// Save writes the settings back.
//
// Written to a temporary file in the same directory and renamed over the
// target, so an interrupted write leaves the previous settings rather than a
// truncated file. The same-directory part matters: a rename across filesystems
// is not atomic, and /tmp is frequently a different one.
func (s Settings) Save() error {
	if s.path == "" {
		return fmt.Errorf("nowhere to save settings: could not find the executable or a config directory")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("could not create %s: %w", filepath.Dir(s.path), err)
	}

	values := map[string]string{
		"interactive":   strconv.FormatBool(s.Interactive),
		"update_checks": strconv.FormatBool(s.UpdateChecks),
	}
	if !s.LastUpdateCheck.IsZero() {
		values["last_update_check"] = strconv.FormatInt(s.LastUpdateCheck.Unix(), 10)
	}
	if s.LatestSeen != "" {
		values["latest_seen"] = s.LatestSeen
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	// Sorted so the file does not reorder itself between writes. It is a file
	// people will open, and a diff should show what changed.
	sort.Strings(keys)

	var body strings.Builder
	body.WriteString("# weedout settings for this installation.\n")
	body.WriteString("# Written by `weedout --interactive` and the update check.\n\n")
	for _, key := range keys {
		body.WriteString(key + " = " + values[key] + "\n")
	}

	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".weedout-settings-*")
	if err != nil {
		return fmt.Errorf("could not write to %s: %w", filepath.Dir(s.path), err)
	}
	name := temporary.Name()

	if _, err := temporary.WriteString(body.String()); err != nil {
		temporary.Close()
		os.Remove(name)
		return err
	}
	if err := temporary.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, s.path); err != nil {
		os.Remove(name)
		return fmt.Errorf("could not replace %s: %w", s.path, err)
	}
	return nil
}

// WithPath returns a copy that will save to an explicit path. For tests.
func (s Settings) WithPath(path string) Settings {
	s.path = path
	s.beside = true
	return s
}

// resolvePath picks where settings live, preferring beside the executable.
//
// Writability is tested by actually creating a file rather than by reading
// permission bits, because the bits lie often enough to matter: a read-only
// mount, a container layer, and Windows ACLs all present as writable-looking
// directories that refuse the write. Finding out at save time -- after
// somebody has answered a prompt -- would be too late to say anything useful.
func resolvePath() (path string, beside bool) {
	if executable, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(executable); err == nil {
			executable = resolved
		}
		directory := filepath.Dir(executable)
		candidate := filepath.Join(directory, Filename)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
		if writable(directory) {
			return candidate, true
		}
	}

	if configDir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(configDir, "weedout", Filename), false
	}
	return "", false
}

func writable(directory string) bool {
	probe, err := os.CreateTemp(directory, ".weedout-probe-*")
	if err != nil {
		return false
	}
	name := probe.Name()
	probe.Close()
	os.Remove(name)
	return true
}

func parse(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	key, value, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value), true
}

func truthy(value string) bool {
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
