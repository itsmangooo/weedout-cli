package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeConfig(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, Filename), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentBeatsTheConfigFile(t *testing.T) {
	// The one that matters. CI injects secrets as environment variables, and a
	// .weedout accidentally committed to the repository must never quietly
	// override the key the pipeline was configured with — authenticating as
	// the wrong account is far worse than failing to authenticate.
	dir := t.TempDir()
	writeConfig(t, dir, "api_key = from_file\n")

	env := func(k string) string {
		if k == EnvAPIKey {
			return "from_env"
		}
		return ""
	}
	got := Resolve(dir, "", "", env)
	if got.APIKey != "from_env" {
		t.Errorf("key %q, want from_env", got.APIKey)
	}
	if got.KeySource != EnvAPIKey {
		t.Errorf("source %q, want %s", got.KeySource, EnvAPIKey)
	}
}

func TestFlagBeatsEverything(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "api_key = from_file\n")
	env := func(k string) string {
		if k == EnvAPIKey {
			return "from_env"
		}
		return ""
	}
	if got := Resolve(dir, "from_flag", "", env); got.APIKey != "from_flag" {
		t.Errorf("key %q, want from_flag", got.APIKey)
	}
}

func TestConfigFileIsUsedWhenNothingElseIsSet(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "api_key = from_file\n")
	got := Resolve(dir, "", "", func(string) string { return "" })
	if got.APIKey != "from_file" {
		t.Errorf("key %q, want from_file", got.APIKey)
	}
}

func TestConfigIsFoundInAParentDirectory(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, "api_key = parent\n")
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := Resolve(nested, "", "", func(string) string { return "" }); got.APIKey != "parent" {
		t.Errorf("key %q, want parent", got.APIKey)
	}
}

func TestMalformedConfigDegradesRatherThanCrashing(t *testing.T) {
	// A broken config must not take the pipeline down; it becomes "no key
	// found there" and the caller says so in terms the user can act on.
	dir := t.TempDir()
	writeConfig(t, dir, "this is not = = valid\n\n# comment\nnokeyhere\n")
	got := Resolve(dir, "", "", func(string) string { return "" })
	if got.APIKey != "" {
		t.Errorf("key %q, want empty", got.APIKey)
	}
	if got.KeySource != "nowhere" {
		t.Errorf("source %q, want nowhere", got.KeySource)
	}
}

func TestCommentsAndQuotesAreHandled(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "# a comment\napi_key = \"quoted_key\"\nurl = 'https://example.test/'\n")
	got := Resolve(dir, "", "", func(string) string { return "" })
	if got.APIKey != "quoted_key" {
		t.Errorf("key %q, want quoted_key", got.APIKey)
	}
	if got.BaseURL != "https://example.test" {
		t.Errorf("url %q, want the trailing slash trimmed", got.BaseURL)
	}
}

func TestDefaultBaseURLWhenNothingSaysOtherwise(t *testing.T) {
	got := Resolve(t.TempDir(), "", "", func(string) string { return "" })
	if got.BaseURL != DefaultBaseURL {
		t.Errorf("url %q, want %s", got.BaseURL, DefaultBaseURL)
	}
}

func TestWriteProducesAReadableConfigWithAWarning(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, Filename)
	if err := Write(target, "wo_key", ""); err != nil {
		t.Fatal(err)
	}
	got := Resolve(dir, "", "", func(string) string { return "" })
	if got.APIKey != "wo_key" {
		t.Errorf("round trip gave %q", got.APIKey)
	}

	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(raw), ".gitignore") {
		t.Error("the file should warn that it holds a credential")
	}
}

func TestWrittenConfigIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows has no POSIX mode bits; Go reports 0666 whatever is asked
		// for. The 0600 still applies on the platforms where CI actually runs.
		t.Skip("POSIX permissions do not apply on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, Filename)
	if err := Write(target, "wo_key", ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	// It is a credential. The default 0644 would make it readable by every
	// other account on a shared build machine.
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("mode %o allows group or other access", mode)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
