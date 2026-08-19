package detect

import (
	"os"
	"path/filepath"
	"testing"
)

// write creates a file, making any parent directories it needs.
func write(t *testing.T, root, rel string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLockfileBeatsTheManifestItCameFrom(t *testing.T) {
	// package.json records the ranges a resolver was asked to satisfy;
	// package-lock.json records what it actually resolved. Scanning the range
	// means guessing at the floor it permits, so when both exist the lockfile
	// has to win or every result carries an avoidable assumption.
	root := t.TempDir()
	write(t, root, "package.json")
	lock := write(t, root, "package-lock.json")

	match, found, err := Find(root)
	if err != nil || !found {
		t.Fatalf("expected a match, got found=%v err=%v", found, err)
	}
	if match.Path != lock {
		t.Errorf("picked %s, want the lockfile %s", match.Path, lock)
	}
	if !match.Candidate.Locked {
		t.Error("the chosen candidate should be marked as locked")
	}
}

func TestEachSupportedFilenameIsFound(t *testing.T) {
	for _, c := range Candidates {
		t.Run(c.Filename, func(t *testing.T) {
			root := t.TempDir()
			want := write(t, root, c.Filename)

			match, found, err := Find(root)
			if err != nil || !found {
				t.Fatalf("expected to find %s, got found=%v err=%v", c.Filename, found, err)
			}
			if match.Path != want {
				t.Errorf("found %s, want %s", match.Path, want)
			}
			if match.Candidate.Ecosystem != c.Ecosystem {
				t.Errorf("ecosystem %s, want %s", match.Candidate.Ecosystem, c.Ecosystem)
			}
		})
	}
}

func TestNodeModulesIsNeverWalked(t *testing.T) {
	// node_modules holds a package.json for every installed package —
	// thousands of files, none of which describes the project being built.
	root := t.TempDir()
	write(t, root, "node_modules/left-pad/package.json")

	_, found, err := Find(root)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("found a manifest inside node_modules; it must be skipped")
	}
}

func TestSkippedDirectoriesAreNotSearched(t *testing.T) {
	for _, dir := range []string{".git", "vendor", "dist", ".venv"} {
		t.Run(dir, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, dir+"/package.json")
			if _, found, _ := Find(root); found {
				t.Errorf("searched %s, which should be skipped", dir)
			}
		})
	}
}

func TestSearchStopsAtMaxDepth(t *testing.T) {
	// A repository root is where a manifest lives. Walking a whole monorepo
	// would make the CLI pick an arbitrary sub-package and report on the wrong
	// thing, which is worse than reporting nothing.
	root := t.TempDir()
	write(t, root, "a/b/c/package.json")

	if _, found, _ := Find(root); found {
		t.Error("found a manifest below MaxDepth")
	}
}

func TestShallowerManifestWinsAtEqualRank(t *testing.T) {
	root := t.TempDir()
	shallow := write(t, root, "go.mod")
	write(t, root, "sub/go.mod")

	match, found, err := Find(root)
	if err != nil || !found {
		t.Fatalf("expected a match: found=%v err=%v", found, err)
	}
	if match.Path != shallow {
		t.Errorf("picked %s, want the shallower %s", match.Path, shallow)
	}
}

func TestOrderingIsStable(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json")
	write(t, root, "package-lock.json")
	write(t, root, "requirements.txt")

	first, err := FindAll(root, MaxDepth)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := FindAll(root, MaxDepth)
		if err != nil {
			t.Fatal(err)
		}
		if len(again) != len(first) {
			t.Fatalf("length changed between runs: %d then %d", len(first), len(again))
		}
		for j := range first {
			if first[j].Path != again[j].Path {
				t.Fatalf("order changed at %d: %s then %s", j, first[j].Path, again[j].Path)
			}
		}
	}
}

func TestNothingFoundInAnEmptyDirectory(t *testing.T) {
	if _, found, err := Find(t.TempDir()); found || err != nil {
		t.Errorf("found=%v err=%v, want no match and no error", found, err)
	}
}

func TestUnsupportedLockfilesAreNamedNotScanned(t *testing.T) {
	// The API cannot parse yarn.lock. Detecting it as scannable would upload a
	// file the server rejects, leaving the user reading a parse error instead
	// of a sentence telling them which file to point at.
	root := t.TempDir()
	write(t, root, "yarn.lock")

	if _, found, _ := Find(root); found {
		t.Error("yarn.lock was treated as scannable; the API cannot read it")
	}

	present := FindUnsupported(root)
	instead, ok := present["yarn.lock"]
	if !ok {
		t.Fatal("yarn.lock was not reported as a recognised-but-unsupported file")
	}
	if instead != "package.json" {
		t.Errorf("suggested %q, want package.json", instead)
	}
}

func TestUnsupportedIsSilentWhenASupportedFileExists(t *testing.T) {
	root := t.TempDir()
	write(t, root, "yarn.lock")
	want := write(t, root, "package.json")

	match, found, _ := Find(root)
	if !found || match.Path != want {
		t.Errorf("found=%v path=%s, want %s", found, match.Path, want)
	}
}

func TestSupportedNamesListsEveryCandidate(t *testing.T) {
	names := SupportedNames()
	for _, c := range Candidates {
		if !contains(names, c.Filename) {
			t.Errorf("%s missing from the supported list shown to users", c.Filename)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
