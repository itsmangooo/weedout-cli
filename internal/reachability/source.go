// Package reachability collects bounded JavaScript/TypeScript source for the
// server-side reachability analyser. It does not decide reachability itself;
// the API combines this source with its parsed dependency graph and records
// the evidence-backed result.
package reachability

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	MaxFiles     = 512
	MaxFileBytes = 512 << 10
	MaxBytes     = 4 << 20
)

var suffixes = map[string]bool{
	".js": true, ".jsx": true, ".mjs": true, ".cjs": true,
	".ts": true, ".tsx": true, ".mts": true, ".cts": true,
}

var skippedDirectories = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	"dist": true, "build": true, "coverage": true, "out": true,
	".next": true, ".nuxt": true, ".cache": true, ".turbo": true,
}

type File struct {
	Path    string
	Content []byte
}

type Bundle struct {
	Files    []File
	Complete bool
	Notes    []string
}

// Collect discovers every supported source file below root without following
// symlinks. A limit/read failure makes the inventory incomplete; it never
// turns missing analysis into a negative reachability conclusion.
func Collect(root string) Bundle {
	bundle := Bundle{Complete: true}
	var paths []string

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			bundle.Complete = false
			bundle.Notes = append(bundle.Notes, "Could not inspect "+path+".")
			return nil
		}
		if entry.IsDir() {
			if path != root && (skippedDirectories[entry.Name()] || strings.HasPrefix(entry.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !suffixes[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		bundle.Complete = false
		bundle.Notes = append(bundle.Notes, "Source discovery did not complete.")
	}

	sort.Strings(paths)
	if len(paths) > MaxFiles {
		bundle.Complete = false
		bundle.Notes = append(bundle.Notes, "Source file limit reached; unobserved dependencies remain unknown.")
		paths = paths[:MaxFiles]
	}

	total := 0
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			bundle.Complete = false
			bundle.Notes = append(bundle.Notes, "Could not inspect "+path+".")
			continue
		}
		if info.Size() > MaxFileBytes {
			bundle.Complete = false
			bundle.Notes = append(bundle.Notes, "Skipped oversized source file "+path+".")
			continue
		}
		if total+int(info.Size()) > MaxBytes {
			bundle.Complete = false
			bundle.Notes = append(bundle.Notes, "Source byte limit reached; unobserved dependencies remain unknown.")
			break
		}
		content, err := os.ReadFile(path)
		if err != nil {
			bundle.Complete = false
			bundle.Notes = append(bundle.Notes, "Could not read "+path+".")
			continue
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(relative, "..") {
			bundle.Complete = false
			bundle.Notes = append(bundle.Notes, "Could not label source file "+path+" safely.")
			continue
		}
		bundle.Files = append(bundle.Files, File{
			Path:    filepath.ToSlash(relative),
			Content: content,
		})
		total += len(content)
	}
	return bundle
}
