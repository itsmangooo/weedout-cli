// Package config resolves the API key and endpoint for an invocation.
//
// Resolution order, highest first:
//
//  1. --api-key on the command line
//  2. WEEDOUT_API_KEY in the environment
//  3. api_key in a .weedout file, searched from the working directory upward
//
// The environment beating the file is the important one. CI systems inject
// secrets as environment variables, and a .weedout accidentally committed to
// the repository must never quietly override the key the pipeline was
// configured with — a build that authenticates as the wrong account is far
// worse than one that fails to authenticate at all.
//
// .weedout is a flat key = value file rather than TOML or YAML: it holds two
// settings, and depending on a parser to read them would put a dependency in a
// CI runner for no benefit.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// Filename is the per-project config file. It holds a credential and must
	// stay out of the repository.
	Filename = ".weedout"

	// PolicyFilename is the scan-rules file, which is the opposite: it belongs
	// in the repository, where it is reviewed like code and travels with a
	// branch. Two files with confusingly similar names, doing opposite things,
	// so the distinction is stated wherever either one is mentioned.
	PolicyFilename = ".weedout.yml"
	// DefaultBaseURL is the hosted service.
	DefaultBaseURL = "https://weedout.dev"

	// EnvAPIKey is the variable CI pipelines set.
	EnvAPIKey = "WEEDOUT_API_KEY"
	// EnvBaseURL points the CLI at a self-hosted instance.
	EnvBaseURL = "WEEDOUT_URL"

	// maxParents bounds the upward search, so running the CLI in a temporary
	// directory cannot pick up a stray config from near the filesystem root.
	maxParents = 6
)

// Config is the resolved settings for one run.
type Config struct {
	APIKey  string
	BaseURL string
	// KeySource names where the key came from. Someone debugging "why did this
	// report the wrong project" needs to know which of three places won.
	KeySource string
}

// FindFile returns the nearest .weedout at or above start.
func FindFile(start string) (string, bool) {
	current, err := filepath.Abs(start)
	if err != nil {
		return "", false
	}
	for i := 0; i <= maxParents; i++ {
		candidate := filepath.Join(current, Filename)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", false
}

// FindPolicyFile returns the nearest .weedout.yml at or above start.
//
// The same upward walk as FindFile, and bounded the same way, because the two
// files live in the same place for the same reason: the repository root, found
// from wherever the command happened to be run.
//
// .weedout.yaml is accepted as well. Insisting on one spelling of a YAML
// extension is a way to have people write a config that silently does nothing.
func FindPolicyFile(start string) (string, bool) {
	current, err := filepath.Abs(start)
	if err != nil {
		return "", false
	}
	for i := 0; i <= maxParents; i++ {
		for _, name := range []string{PolicyFilename, ".weedout.yaml"} {
			candidate := filepath.Join(current, name)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, true
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", false
}

// ReadFile parses a .weedout. Unreadable or malformed lines are skipped: a
// broken config degrades to "no key found there" and the caller reports that
// in terms the user can act on, rather than crashing mid-pipeline.
func ReadFile(path string) map[string]string {
	values := map[string]string{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return values
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		values[strings.ToLower(strings.TrimSpace(name))] = strings.Trim(
			strings.TrimSpace(value), `"'`)
	}
	return values
}

// Lookup is an environment reader, so tests do not have to mutate the process.
type Lookup func(string) string

// Resolve works out the key and endpoint for this invocation.
func Resolve(start, cliKey, cliURL string, env Lookup) Config {
	if env == nil {
		env = os.Getenv
	}

	fileValues := map[string]string{}
	configPath, ok := FindFile(start)
	if ok {
		fileValues = ReadFile(configPath)
	}

	var apiKey, source string
	switch {
	case cliKey != "":
		apiKey, source = cliKey, "--api-key"
	case env(EnvAPIKey) != "":
		apiKey, source = env(EnvAPIKey), EnvAPIKey
	case fileValues["api_key"] != "":
		apiKey, source = fileValues["api_key"], configPath
	default:
		apiKey, source = "", "nowhere"
	}

	baseURL := firstNonEmpty(
		cliURL,
		env(EnvBaseURL),
		fileValues["url"],
		fileValues["base_url"],
		DefaultBaseURL,
	)

	return Config{
		APIKey:    strings.TrimSpace(apiKey),
		BaseURL:   strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		KeySource: source,
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Write creates a .weedout, with a warning about what it now contains.
func Write(path, apiKey, baseURL string) error {
	lines := []string{
		"# Weedout project configuration.",
		"#",
		"# This file holds a credential. Add it to .gitignore: a key committed",
		"# to a repository is a key anyone who can read the repository has.",
		"# In CI, prefer the WEEDOUT_API_KEY environment variable, which takes",
		"# precedence over this file.",
		"",
		fmt.Sprintf("api_key = %s", apiKey),
	}
	if baseURL != "" && baseURL != DefaultBaseURL {
		lines = append(lines, fmt.Sprintf("url = %s", baseURL))
	}
	// 0600: it is a credential, and the default 0644 would make it readable by
	// every other account on a shared build machine.
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}
