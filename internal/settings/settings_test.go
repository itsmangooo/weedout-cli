package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func at(t *testing.T) Settings {
	t.Helper()
	return Defaults().WithPath(filepath.Join(t.TempDir(), Filename))
}

func TestTheDefaultsAreTheSafeOnes(t *testing.T) {
	defaults := Defaults()

	// Interactive off matters most: the first thing many people do with this
	// tool is put it in a pipeline, and a binary that waits for a keypress
	// there is a hung build.
	if defaults.Interactive {
		t.Error("interactive mode is on by default")
	}
	if !defaults.UpdateChecks {
		t.Error("update checks should be on by default")
	}
}

func TestASettingSurvivesARoundTrip(t *testing.T) {
	original := at(t)
	original.Interactive = true
	original.LatestSeen = "v1.4.2"
	original.LastUpdateCheck = time.Now().Truncate(time.Second)

	if err := original.Save(); err != nil {
		t.Fatal(err)
	}

	reloaded := loadFrom(original.Path())

	if !reloaded.Interactive {
		t.Error("interactive was not persisted")
	}
	if reloaded.LatestSeen != "v1.4.2" {
		t.Errorf("latest_seen: got %q", reloaded.LatestSeen)
	}
	if !reloaded.LastUpdateCheck.Equal(original.LastUpdateCheck) {
		t.Errorf("last check: got %v, want %v",
			reloaded.LastUpdateCheck, original.LastUpdateCheck)
	}
}

func TestAMissingFileIsTheDefaultsNotAnError(t *testing.T) {
	// The normal state of a fresh install. Treating it as a failure would make
	// the first run of the tool report a problem that is not one.
	loaded := loadFrom(filepath.Join(t.TempDir(), "nothing-here"))

	if loaded.Interactive || !loaded.UpdateChecks {
		t.Error("a missing file did not produce the defaults")
	}
}

func TestAMangledFileDegradesToDefaultsRatherThanFailing(t *testing.T) {
	// Nothing in this file is worth refusing to run a scan over.
	path := filepath.Join(t.TempDir(), Filename)
	os.WriteFile(path, []byte("this is not\nkey = value\x00 nonsense\n[section]\n"), 0o644)

	loaded := loadFrom(path)

	if loaded.Interactive {
		t.Error("nonsense turned interactive mode on")
	}
	if !loaded.UpdateChecks {
		t.Error("nonsense turned update checks off")
	}
}

func TestOffIsPersistedAndNotConfusedWithUnset(t *testing.T) {
	// update_checks defaults to true, so writing false has to be distinguishable
	// from the key being absent, or turning it off would never stick.
	original := at(t)
	original.UpdateChecks = false
	if err := original.Save(); err != nil {
		t.Fatal(err)
	}

	if loadFrom(original.Path()).UpdateChecks {
		t.Error("update checks came back on after being turned off")
	}
}

func TestTheFileIsReadableByAPerson(t *testing.T) {
	original := at(t)
	original.Interactive = true
	original.Save()

	content, err := os.ReadFile(original.Path())
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)

	if !strings.Contains(text, "interactive = true") {
		t.Errorf("not in the documented format:\n%s", text)
	}
	if !strings.HasPrefix(text, "#") {
		t.Errorf("no explanation at the top of the file:\n%s", text)
	}
}

func TestWritingTwiceDoesNotReorderTheFile(t *testing.T) {
	// It is a file people open. A diff should show what changed rather than
	// every line moving.
	first := at(t)
	first.Interactive = true
	first.Save()
	before, _ := os.ReadFile(first.Path())

	second := loadFrom(first.Path())
	second.Save()
	after, _ := os.ReadFile(first.Path())

	if string(before) != string(after) {
		t.Errorf("re-saving unchanged settings rewrote the file:\n%s\n---\n%s", before, after)
	}
}

func TestSavingWithNowhereToWriteReportsIt(t *testing.T) {
	// The read-only install case. It has to say so rather than appear to work,
	// or somebody turns on interactive mode and it silently forgets.
	nowhere := Defaults()
	nowhere.path = ""

	if err := nowhere.Save(); err == nil {
		t.Error("saving with no path succeeded")
	}
}

func TestSavingIntoAMissingDirectoryCreatesIt(t *testing.T) {
	// The fallback location is under the user's config directory, which will
	// not exist the first time.
	deep := Defaults().WithPath(
		filepath.Join(t.TempDir(), "weedout", Filename))

	if err := deep.Save(); err != nil {
		t.Fatalf("could not create the config directory: %v", err)
	}
	if _, err := os.Stat(deep.Path()); err != nil {
		t.Error("the file was not created")
	}
}

func TestValuesAreParsedForgivingly(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	os.WriteFile(path, []byte("  INTERACTIVE  =  YES  \n"), 0o644)

	if !loadFrom(path).Interactive {
		t.Error("a differently cased and spaced value was not understood")
	}
}
