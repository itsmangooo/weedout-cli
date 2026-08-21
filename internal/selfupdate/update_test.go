package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Integrity — the control the whole package exists to uphold
// ---------------------------------------------------------------------------

func digestOf(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func TestAMatchingDigestPasses(t *testing.T) {
	payload := []byte("a binary, pretend")

	if err := verify(payload, digestOf(payload)); err != nil {
		t.Fatalf("a correct checksum was rejected: %v", err)
	}
}

func TestASingleAlteredByteIsRefused(t *testing.T) {
	original := []byte("a binary, pretend")
	expected := digestOf(original)

	tampered := append([]byte{}, original...)
	tampered[0] ^= 0x01

	err := verify(tampered, expected)
	if err == nil {
		t.Fatal("a modified payload passed verification")
	}
	// The message has to say nothing was installed. Someone who sees this is
	// entitled to know their working binary was left alone.
	if !strings.Contains(err.Error(), "Nothing was installed") {
		t.Errorf("the message does not say the binary is untouched: %v", err)
	}
}

func TestAnEmptyPayloadDoesNotAccidentallyMatch(t *testing.T) {
	// Guards the shape of failure where a download silently yields nothing and
	// the digest of empty happens to be compared against itself.
	if err := verify(nil, digestOf([]byte("real content"))); err == nil {
		t.Error("an empty download passed verification")
	}
}

// ---------------------------------------------------------------------------
// Reading the published checksums
// ---------------------------------------------------------------------------

const checksumsFile = `d2c5a4a7f4e5d0b1c3a9e8f7d6c5b4a3928170695a4b3c2d1e0f9a8b7c6d5e4f  weedout-linux-amd64
1111111111111111111111111111111111111111111111111111111111111111  weedout-darwin-arm64
2222222222222222222222222222222222222222222222222222222222222222  weedout-windows-amd64.exe
`

func TestTheRightLineIsPickedOut(t *testing.T) {
	got, err := parseChecksums([]byte(checksumsFile), "weedout-darwin-arm64")

	if err != nil {
		t.Fatal(err)
	}
	if got != strings.Repeat("1", 64) {
		t.Errorf("got %s", got)
	}
}

func TestAnAssetWithNoChecksumIsRefused(t *testing.T) {
	// Refusing is the point. Treating a missing entry as "no verification
	// needed" would mean an attacker who can drop one line from a file also
	// turns the integrity check off.
	_, err := parseChecksums([]byte(checksumsFile), "weedout-freebsd-amd64")

	if err == nil {
		t.Fatal("a file with no published checksum was accepted")
	}
	if !strings.Contains(err.Error(), "cannot be verified") {
		t.Errorf("unclear message: %v", err)
	}
}

func TestABinaryModeStarIsTolerated(t *testing.T) {
	// sha256sum writes "*name" in binary mode on some platforms.
	body := strings.Repeat("3", 64) + "  *weedout-linux-amd64\n"

	got, err := parseChecksums([]byte(body), "weedout-linux-amd64")

	if err != nil || got != strings.Repeat("3", 64) {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestAMalformedDigestIsRefusedRatherThanUsed(t *testing.T) {
	for _, body := range []string{
		"nothexnothexnothexnothexnothexnothexnothexnothexnothexnothexnotg  weedout-linux-amd64\n",
		"abc  weedout-linux-amd64\n",
	} {
		if _, err := parseChecksums([]byte(body), "weedout-linux-amd64"); err == nil {
			t.Errorf("accepted a bad digest: %q", body)
		}
	}
}

func TestBlankLinesAndHeadersAreSkipped(t *testing.T) {
	body := "# generated\n\n" + checksumsFile

	if _, err := parseChecksums([]byte(body), "weedout-linux-amd64"); err != nil {
		t.Errorf("a comment or blank line broke parsing: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Where an update is allowed to come from
// ---------------------------------------------------------------------------

func TestPlainHTTPIsRefused(t *testing.T) {
	err := checkURL("http://github.com/itsmangooo/weedout-cli/releases/download/v1/x")

	if err == nil {
		t.Fatal("an update over http was allowed")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("unclear message: %v", err)
	}
}

func TestGitHubHostsAreAllowed(t *testing.T) {
	for _, raw := range []string{
		"https://api.github.com/repos/x/y/releases/latest",
		"https://github.com/x/y/releases/download/v1/z",
		"https://objects.githubusercontent.com/thing",
		"https://release-assets.githubusercontent.com/thing",
	} {
		if err := checkURL(raw); err != nil {
			t.Errorf("%s was refused: %v", raw, err)
		}
	}
}

func TestOtherHostsAreRefused(t *testing.T) {
	for _, raw := range []string{
		"https://example.com/weedout",
		"https://githubusercontent.com.evil.example/weedout",
		"https://notgithub.com/weedout",
		"https://api.github.com.evil.example/repos",
	} {
		if err := checkURL(raw); err == nil {
			t.Errorf("%s was allowed", raw)
		}
	}
}

func TestFileURLsAreRefused(t *testing.T) {
	// Worth its own case: a file:// redirect would make the updater read a
	// local path instead of the network, which is a different attack from a
	// hostile server but lands in the same place.
	if err := checkURL("file:///etc/passwd"); err == nil {
		t.Error("a file:// URL was allowed")
	}
}

// ---------------------------------------------------------------------------
// Swapping the binary
// ---------------------------------------------------------------------------

func TestTheBinaryIsReplacedAndTheOldOneMovedAside(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "weedout")
	if err := os.WriteFile(target, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := replaceExecutable(target, []byte("new binary")); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new binary" {
		t.Errorf("the binary was not replaced: %q", content)
	}
}

func TestNoTemporaryFilesAreLeftBehind(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "weedout")
	os.WriteFile(target, []byte("old"), 0o755)

	if err := replaceExecutable(target, []byte("new")); err != nil {
		t.Fatal(err)
	}

	entries, _ := os.ReadDir(directory)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".weedout-update-") {
			t.Errorf("a staging file survived: %s", entry.Name())
		}
	}
}

func TestAnUnwritableDirectoryFailsBeforeTouchingTheBinary(t *testing.T) {
	// The case where somebody installed to a system directory and is not root.
	// It has to fail with the original still in place and still working, not
	// half-replaced.
	directory := t.TempDir()
	target := filepath.Join(directory, "weedout")
	os.WriteFile(target, []byte("original"), 0o755)

	missing := filepath.Join(directory, "no-such-dir", "weedout")

	if err := replaceExecutable(missing, []byte("new")); err == nil {
		t.Fatal("expected a failure writing into a directory that does not exist")
	}

	content, _ := os.ReadFile(target)
	if string(content) != "original" {
		t.Errorf("the existing binary was disturbed: %q", content)
	}
}

func TestAStaleOldFileFromAPreviousUpdateIsReplaced(t *testing.T) {
	// On Windows the .old file survives the update that created it, so the
	// next update has to cope with one already being there.
	directory := t.TempDir()
	target := filepath.Join(directory, "weedout")
	os.WriteFile(target, []byte("current"), 0o755)
	os.WriteFile(target+".old", []byte("ancient"), 0o755)

	if err := replaceExecutable(target, []byte("newest")); err != nil {
		t.Fatalf("a leftover .old blocked the update: %v", err)
	}

	content, _ := os.ReadFile(target)
	if string(content) != "newest" {
		t.Errorf("got %q", content)
	}
}

// ---------------------------------------------------------------------------
// Which asset this platform wants
// ---------------------------------------------------------------------------

func TestTheAssetNameMatchesWhatTheReleaseWorkflowBuilds(t *testing.T) {
	// If these drift apart, every update fails with "no build for your
	// platform" and the cause is in a YAML file nobody would think to open.
	name := assetName()

	if !strings.HasPrefix(name, "weedout-") {
		t.Errorf("unexpected asset name: %s", name)
	}
	if strings.Contains(name, "windows") && !strings.HasSuffix(name, ".exe") {
		t.Errorf("the Windows asset needs its extension: %s", name)
	}
}
