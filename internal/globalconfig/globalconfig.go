// Package globalconfig holds what `weedout auth` puts on a machine.
//
// One file, in the place the operating system says configuration goes:
// ~/.config/weedout/config.json on Linux, ~/Library/Application
// Support/weedout/ on macOS, %AppData%\weedout\ on Windows. Go's
// os.UserConfigDir gives the right answer on each.
//
// It holds three things:
//
//   - The account token from `weedout auth`. Not a project key: it can create
//     projects and mint keys for them, and cannot push a scan or read
//     findings.
//   - A map from absolute repository path to the project key for that
//     repository, so a developer with eight checkouts runs `weedout scan` in
//     any of them without eight dotfiles.
//   - Nothing else. Rules live on the server, in a profile, or in the
//     repository's own .weedout.yml, where they are reviewed.
//
// # Why a global file and not a dotfile per repository
//
// The dotfile is still there and still works, because CI needs it — or rather,
// CI needs WEEDOUT_API_KEY, and the dotfile is the local equivalent. What the
// dotfile is bad at is being a *developer's* configuration: it puts a
// credential inside a working tree, one .gitignore mistake from being
// published, and it has to be recreated in every checkout of every project.
//
// So the two are for different jobs, and the resolution order says which wins
// where. A key named on the command line beats everything; the environment
// beats every file, because that is what a CI runner sets and a stray file in
// a checkout must never override it; the repository dotfile beats the global
// map, because somebody who put a key next to their code meant that key; and
// the global map is the fallback that makes the common case need no setup.
//
// # What is written to disk
//
// Credentials, so: 0600 on the file and 0700 on the directory, written through
// a temporary file and renamed, so a crash halfway cannot leave a truncated
// config that loses every key on the machine.
package globalconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	// DirName is the subdirectory under the OS config directory.
	DirName = "weedout"
	// FileName is the config file itself.
	FileName = "config.json"

	// EnvConfigHome overrides where the file lives. Present for tests and for
	// anybody running several accounts side by side; not documented as a
	// feature, because "which account am I?" being ambiguous is how people
	// push results to the wrong project.
	EnvConfigHome = "WEEDOUT_CONFIG_HOME"

	// currentVersion is stamped into the file so a future format change can
	// recognise what it is reading rather than guessing.
	currentVersion = 1
)

// Project is what the CLI knows about one checkout on this machine.
type Project struct {
	// ID is the project on the server. Kept alongside the key so the CLI can
	// name the project in a message without a round trip.
	ID int `json:"id"`
	// Name is display only, and may be out of date if it was renamed on the
	// server. Never used to identify anything.
	Name string `json:"name"`
	// Key is a project-scoped API key. This is the credential a scan uses.
	Key string `json:"key"`
	// LinkedAt is when this checkout was associated, for `weedout whoami`.
	LinkedAt time.Time `json:"linked_at"`
}

// File is the whole document.
type File struct {
	Version int `json:"version"`
	// Token is the account credential from `weedout auth`.
	Token string `json:"token,omitempty"`
	// Email is who that token belongs to, so `weedout whoami` can answer
	// without a request. Display only.
	Email string `json:"email,omitempty"`
	// BaseURL is set only when it is not the default, so a config file copied
	// between machines does not silently pin an old endpoint.
	BaseURL string `json:"base_url,omitempty"`
	// Projects maps an absolute repository path to what is known about it.
	Projects map[string]Project `json:"projects,omitempty"`
}

// Path returns where the config file lives on this machine.
func Path() (string, error) {
	if override := strings.TrimSpace(os.Getenv(EnvConfigHome)); override != "" {
		return filepath.Join(override, FileName), nil
	}

	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("could not find a configuration directory: %w", err)
	}
	return filepath.Join(dir, DirName, FileName), nil
}

// Load reads the config, or returns an empty one.
//
// A missing file is not an error: it is what every machine looks like before
// `weedout auth` runs, and treating it as a failure would make every command
// print something alarming on a fresh install.
//
// A *corrupt* file is also not an error, and that is the more debatable call.
// The alternative is refusing to run until somebody deletes it by hand, which
// turns a bad write into a broken installation. Returning empty means the next
// `weedout auth` fixes it by overwriting, and in the meantime the command says
// "not signed in" rather than something about JSON.
func Load() (File, error) {
	path, err := Path()
	if err != nil {
		return File{Version: currentVersion}, err
	}
	return LoadFrom(path)
}

// LoadFrom reads a specific path. Exported for tests and for `weedout whoami`,
// which reports where it read from.
func LoadFrom(path string) (File, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is ours, from os.UserConfigDir
	if errors.Is(err, os.ErrNotExist) {
		return File{Version: currentVersion, Projects: map[string]Project{}}, nil
	}
	if err != nil {
		return File{Version: currentVersion, Projects: map[string]Project{}}, err
	}

	var file File
	if err := json.Unmarshal(raw, &file); err != nil {
		return File{Version: currentVersion, Projects: map[string]Project{}}, nil
	}
	if file.Projects == nil {
		file.Projects = map[string]Project{}
	}
	if file.Version == 0 {
		file.Version = currentVersion
	}
	return file, nil
}

// Save writes the config atomically, with permissions fit for a credential.
func Save(file File) error {
	path, err := Path()
	if err != nil {
		return err
	}
	return SaveTo(path, file)
}

// SaveTo writes to a specific path.
func SaveTo(path string, file File) error {
	if file.Version == 0 {
		file.Version = currentVersion
	}

	dir := filepath.Dir(path)
	// 0700: the directory holds credentials, and the default 0755 would let
	// every other account on a shared machine list it.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("could not create %s: %w", dir, err)
	}
	// MkdirAll applies the mode only when it creates the final directory. An
	// existing WEEDOUT_CONFIG_HOME (or a permissive umask-created directory)
	// could otherwise remain world-readable while holding credential files.
	if err := os.Chmod(dir, 0o700); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("could not secure %s: %w", dir, err)
	}

	body, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("could not encode the configuration: %w", err)
	}
	body = append(body, '\n')

	// Temporary file then rename, so a crash or a full disk halfway through
	// cannot leave a truncated config -- which would lose every project key on
	// the machine, and look like being signed out for no reason.
	temp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("could not write to %s: %w", dir, err)
	}
	tempName := temp.Name()

	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}

	// Before anything is written, so the contents are never briefly readable
	// by anyone else. CreateTemp already makes it 0600, but saying so here
	// means the guarantee does not depend on that staying true.
	if err := temp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		cleanup()
		return fmt.Errorf("could not secure %s: %w", tempName, err)
	}
	if _, err := temp.Write(body); err != nil {
		cleanup()
		return fmt.Errorf("could not write %s: %w", tempName, err)
	}
	// Flushed before the rename. Renaming an unsynced file can leave a
	// zero-length config after a power loss on some filesystems, which is the
	// exact failure the rename was meant to prevent.
	if err := temp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("could not flush %s: %w", tempName, err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("could not close %s: %w", tempName, err)
	}

	if err := os.Rename(tempName, path); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("could not save %s: %w", path, err)
	}
	return nil
}

// ProjectFor returns what is known about the checkout containing dir.
//
// Walks upward, so running the command in a subdirectory of a linked
// repository finds it. The deepest match wins: a monorepo whose root is linked
// to one project and whose service directory is linked to another should get
// the more specific answer, because that is the one somebody set deliberately.
func (f File) ProjectFor(dir string) (Project, string, bool) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return Project{}, "", false
	}
	absolute = normalise(absolute)

	// Longest first, so the deepest link is found before its parent.
	keys := make([]string, 0, len(f.Projects))
	for key := range f.Projects {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })

	for _, key := range keys {
		if absolute == key || strings.HasPrefix(absolute, key+string(filepath.Separator)) {
			return f.Projects[key], key, true
		}
	}
	return Project{}, "", false
}

// Link records a project against a repository path.
func (f *File) Link(dir string, project Project) (string, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if f.Projects == nil {
		f.Projects = map[string]Project{}
	}
	key := normalise(absolute)
	project.LinkedAt = time.Now().UTC()
	f.Projects[key] = project
	return key, nil
}

// Unlink forgets a repository. Returns whether there was one.
func (f *File) Unlink(dir string) bool {
	_, key, found := f.ProjectFor(dir)
	if !found {
		return false
	}
	delete(f.Projects, key)
	return true
}

// SignedIn reports whether this machine holds an account token.
func (f File) SignedIn() bool {
	return strings.TrimSpace(f.Token) != ""
}

// normalise makes two spellings of the same directory compare equal.
//
// Case-insensitive on Windows and macOS, where the filesystem is: C:\Repos\App
// and c:\repos\app are one directory, and storing them as two entries would
// hand the same checkout two different keys.
func normalise(path string) string {
	cleaned := filepath.Clean(path)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(cleaned)
	}
	return cleaned
}
