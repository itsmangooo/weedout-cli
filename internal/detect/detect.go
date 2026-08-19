// Package detect finds the file to scan.
//
// The rule is "prefer the file that says what is actually installed". A
// package-lock.json records resolved versions; a package.json records the
// ranges a resolver was asked to satisfy. Scanning the range means guessing at
// the floor it permits, and the guess is labelled as one in the dashboard —
// but a lockfile removes the guess entirely, so when both are present the
// lockfile wins.
//
// Detection is by filename, matching exactly what the server accepts. The
// server does the parsing; duplicating that here would mean two
// implementations of "is this a valid manifest" that have to agree forever,
// and the one in the CI runner would be the one nobody notices has drifted.
package detect

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Candidate is one recognised manifest filename.
type Candidate struct {
	Filename  string
	Ecosystem string
	// Rank sorts ascending. A lockfile outranks the manifest it came from.
	Rank   int
	Locked bool
}

// Candidates lists what the API can parse, in preference order. Kept in one
// place so the scan and the "nothing found" message can never disagree.
var Candidates = []Candidate{
	{Filename: "package-lock.json", Ecosystem: "npm", Rank: 0, Locked: true},
	{Filename: "package.json", Ecosystem: "npm", Rank: 1, Locked: false},
	{Filename: "requirements.txt", Ecosystem: "PyPI", Rank: 0, Locked: false},
	{Filename: "go.mod", Ecosystem: "Go", Rank: 0, Locked: false},
}

// Unsupported are lockfiles people reasonably expect to work but the API
// cannot read yet. They are recognised only so the CLI can say so by name.
//
// Detecting them as scannable would be worse than not detecting them: the
// upload would reach the server and come back a 400, and the user would be
// left reading a parse error instead of a sentence telling them which file to
// point at instead.
var Unsupported = map[string]string{
	"yarn.lock":      "package.json",
	"pnpm-lock.yaml": "package.json",
	"poetry.lock":    "requirements.txt",
	"Pipfile.lock":   "requirements.txt",
	"go.sum":         "go.mod",
}

// SkipDirs are never worth walking into. node_modules in particular holds a
// package.json for every installed package — thousands of files, none of which
// describes the project being built.
var SkipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".tox": true,
	".venv": true, ".mypy_cache": true, ".pytest_cache": true,
	"__pycache__": true, "node_modules": true, "vendor": true,
	"venv": true, "env": true, "dist": true, "build": true,
	"target": true, "site-packages": true,
}

// MaxDepth is how far below the starting directory the search goes.
//
// Deliberately shallow. A repository root is where a manifest lives; walking
// a whole monorepo would make `weedout scan` pick an arbitrary sub-package and
// report on the wrong thing, which is worse than reporting nothing.
const MaxDepth = 2

// Match is a found manifest and what it was recognised as.
type Match struct {
	Path      string
	Candidate Candidate
	// Depth below the search root, used for ordering.
	Depth int
}

func candidateFor(name string) (Candidate, bool) {
	for _, c := range Candidates {
		if name == c.Filename {
			return c, true
		}
	}
	return Candidate{}, false
}

// FindAll returns every recognised manifest under root, best first.
//
// Ordered by rank, then depth, then path — so a lockfile at the root beats a
// lockfile in a subdirectory, and the result is stable rather than dependent
// on filesystem ordering.
func FindAll(root string, maxDepth int) ([]Match, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	var found []Match
	err = filepath.WalkDir(abs, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory is not a reason to abandon the search.
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		rel, relErr := filepath.Rel(abs, path)
		if relErr != nil {
			return nil
		}
		depth := 0
		if rel != "." {
			depth = len(strings.Split(rel, string(filepath.Separator))) - 1
		}

		if entry.IsDir() {
			if path == abs {
				return nil
			}
			name := entry.Name()
			if SkipDirs[name] || strings.HasPrefix(name, ".") || depth >= maxDepth {
				return fs.SkipDir
			}
			return nil
		}

		if c, ok := candidateFor(entry.Name()); ok {
			found = append(found, Match{Path: path, Candidate: c, Depth: depth})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.SliceStable(found, func(i, j int) bool {
		if found[i].Candidate.Rank != found[j].Candidate.Rank {
			return found[i].Candidate.Rank < found[j].Candidate.Rank
		}
		if found[i].Depth != found[j].Depth {
			return found[i].Depth < found[j].Depth
		}
		return found[i].Path < found[j].Path
	})
	return found, nil
}

// Find returns the single best manifest to scan.
func Find(root string) (Match, bool, error) {
	matches, err := FindAll(root, MaxDepth)
	if err != nil {
		return Match{}, false, err
	}
	if len(matches) == 0 {
		return Match{}, false, nil
	}
	return matches[0], true, nil
}

// FindUnsupported reports lockfiles present at the root that the API cannot
// read, so the CLI can name them instead of just saying it found nothing.
func FindUnsupported(root string) map[string]string {
	present := map[string]string{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return present
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if instead, ok := Unsupported[e.Name()]; ok {
			present[e.Name()] = instead
		}
	}
	return present
}

// SupportedNames is the list for the "nothing found" message.
func SupportedNames() string {
	names := make([]string, 0, len(Candidates))
	for _, c := range Candidates {
		names = append(names, c.Filename)
	}
	return strings.Join(names, ", ")
}
