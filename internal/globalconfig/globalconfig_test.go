package globalconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The file `weedout auth` writes.
//
// It holds credentials, so the tests that matter most are about permissions,
// atomicity, and never losing what is already there. A config that loses every
// project key on a machine because one write went wrong is worse than one that
// never existed.

func tempConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(EnvConfigHome, dir)
	return filepath.Join(dir, FileName)
}

func TestAMissingFileIsNotAnError(t *testing.T) {
	// It is what every machine looks like before `weedout auth` runs.
	tempConfig(t)

	file, err := Load()

	if err != nil {
		t.Fatalf("a fresh machine reported an error: %v", err)
	}
	if file.SignedIn() {
		t.Error("a fresh machine claimed to be signed in")
	}
	if file.Projects == nil {
		t.Error("Projects should be usable without a nil check")
	}
}

func TestACorruptFileReadsAsEmptyRatherThanBroken(t *testing.T) {
	// The alternative is refusing to run until somebody deletes it by hand,
	// which turns a bad write into a broken installation. Empty means the next
	// `weedout auth` fixes it.
	path := tempConfig(t)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	file, err := Load()

	if err != nil {
		t.Fatalf("a corrupt file should not be an error: %v", err)
	}
	if file.SignedIn() {
		t.Error("a corrupt file produced a signed-in state")
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	tempConfig(t)
	original := File{Token: "woa_secret", Email: "dev@example.com"}
	if _, err := original.Link("/repos/app", Project{ID: 7, Name: "app", Key: "wo_key"}); err != nil {
		t.Fatal(err)
	}

	if err := Save(original); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.Token != "woa_secret" || loaded.Email != "dev@example.com" {
		t.Errorf("the credential did not survive: %+v", loaded)
	}
	project, _, found := loaded.ProjectFor("/repos/app")
	if !found || project.ID != 7 || project.Key != "wo_key" {
		t.Errorf("the project link did not survive: %+v", loaded.Projects)
	}
}

func TestTheFileIsNotReadableByOtherAccounts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply")
	}
	path := tempConfig(t)

	if err := Save(File{Token: "woa_secret"}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the config holds credentials and is %o, want 600", mode)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Errorf("the config directory is %o, want 700", mode)
	}
}

func TestNoTemporaryFilesAreLeftBehind(t *testing.T) {
	// The write goes through a temp file and a rename. One left lying around
	// would be a credential at a path nobody is thinking about.
	path := tempConfig(t)

	for i := 0; i < 3; i++ {
		if err := Save(File{Token: "woa_secret"}); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("a temporary file survived: %s", entry.Name())
		}
	}
}

func TestSavingDoesNotLoseWhatIsAlreadyThere(t *testing.T) {
	tempConfig(t)
	file := File{Token: "woa_one"}
	if _, err := file.Link("/repos/app", Project{ID: 1, Key: "wo_a"}); err != nil {
		t.Fatal(err)
	}
	if err := Save(file); err != nil {
		t.Fatal(err)
	}

	// A second sign-in, as `weedout auth` does it: load, change the token,
	// save. The project keys must survive.
	again, _ := Load()
	again.Token = "woa_two"
	if err := Save(again); err != nil {
		t.Fatal(err)
	}

	loaded, _ := Load()
	if loaded.Token != "woa_two" {
		t.Error("the new token was not saved")
	}
	if _, _, found := loaded.ProjectFor("/repos/app"); !found {
		t.Error("signing in again lost the project keys")
	}
}

func TestTheVersionIsStamped(t *testing.T) {
	path := tempConfig(t)
	if err := Save(File{Token: "woa_x"}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["version"] == nil {
		t.Error("a future format change would have nothing to recognise")
	}
}

// ---------------------------------------------------------------------------
// Finding the project for a directory
// ---------------------------------------------------------------------------

func TestASubdirectoryFindsItsProject(t *testing.T) {
	// Somebody runs the command from wherever they happen to be standing.
	file := File{Projects: map[string]Project{}}
	root := filepath.Join(t.TempDir(), "app")
	if _, err := file.Link(root, Project{ID: 1, Name: "app"}); err != nil {
		t.Fatal(err)
	}

	project, _, found := file.ProjectFor(filepath.Join(root, "src", "handlers"))

	if !found || project.ID != 1 {
		t.Errorf("a subdirectory did not find its project: %+v", file.Projects)
	}
}

func TestTheDeepestLinkWins(t *testing.T) {
	// A monorepo root linked to one project and a service directory linked to
	// another should get the more specific answer: that is the one somebody
	// set deliberately.
	file := File{Projects: map[string]Project{}}
	root := t.TempDir()
	service := filepath.Join(root, "services", "api")
	if _, err := file.Link(root, Project{ID: 1, Name: "monorepo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Link(service, Project{ID: 2, Name: "api"}); err != nil {
		t.Fatal(err)
	}

	project, _, _ := file.ProjectFor(filepath.Join(service, "internal"))

	if project.ID != 2 {
		t.Errorf("got project %d, want the deeper link (2)", project.ID)
	}
}

func TestASiblingDirectoryIsNotAMatch(t *testing.T) {
	// /repos/app must not match /repos/app-staging. A prefix comparison
	// without the separator would, and it would push results to the wrong
	// project while looking entirely correct.
	file := File{Projects: map[string]Project{}}
	root := t.TempDir()
	if _, err := file.Link(filepath.Join(root, "app"), Project{ID: 1}); err != nil {
		t.Fatal(err)
	}

	if _, _, found := file.ProjectFor(filepath.Join(root, "app-staging")); found {
		t.Error("a sibling directory matched")
	}
}

func TestAnUnrelatedDirectoryFindsNothing(t *testing.T) {
	file := File{Projects: map[string]Project{}}
	if _, err := file.Link(filepath.Join(t.TempDir(), "app"), Project{ID: 1}); err != nil {
		t.Fatal(err)
	}

	if _, _, found := file.ProjectFor(t.TempDir()); found {
		t.Error("an unrelated directory matched")
	}
}

func TestCaseIsIgnoredWhereTheFilesystemIgnoresIt(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("the filesystem here is case-sensitive, so these are two directories")
	}
	file := File{Projects: map[string]Project{}}
	root := t.TempDir()
	if _, err := file.Link(filepath.Join(root, "App"), Project{ID: 1}); err != nil {
		t.Fatal(err)
	}

	if _, _, found := file.ProjectFor(filepath.Join(root, "app")); !found {
		t.Error("one directory was stored under two keys")
	}
}

func TestUnlinkForgetsIt(t *testing.T) {
	file := File{Projects: map[string]Project{}}
	root := t.TempDir()
	if _, err := file.Link(root, Project{ID: 1}); err != nil {
		t.Fatal(err)
	}

	if !file.Unlink(root) {
		t.Fatal("unlink reported nothing to remove")
	}
	if _, _, found := file.ProjectFor(root); found {
		t.Error("it is still linked")
	}
}

func TestUnlinkFromASubdirectoryRemovesTheLink(t *testing.T) {
	file := File{Projects: map[string]Project{}}
	root := t.TempDir()
	if _, err := file.Link(root, Project{ID: 1}); err != nil {
		t.Fatal(err)
	}

	if !file.Unlink(filepath.Join(root, "src")) {
		t.Fatal("unlink from a subdirectory found nothing")
	}
	if len(file.Projects) != 0 {
		t.Errorf("the entry survived: %+v", file.Projects)
	}
}

func TestUnlinkingNothingIsNotAnError(t *testing.T) {
	file := File{Projects: map[string]Project{}}

	if file.Unlink(t.TempDir()) {
		t.Error("unlink claimed to remove something that was not there")
	}
}

func TestTheConfigHomeOverrideIsHonoured(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigHome, dir)

	path, err := Path()

	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("got %s, want a file inside %s", path, dir)
	}
}
