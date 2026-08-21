// Package selfupdate replaces this binary with a newer release.
//
// A tool that downloads code and puts it where the operating system will run
// it is, structurally, a supply-chain attack in waiting. This one is a security
// scanner, which makes it a more attractive thing to hijack than most. So the
// rules it follows are worth stating in one place:
//
//   - Nothing is installed without a SHA-256 that matches the checksums file
//     published with the release. Not "if a checksum is available" -- if the
//     checksum cannot be fetched or does not match, the update fails and the
//     binary on disk is untouched.
//   - HTTPS only, on every hop. Redirects are followed, because GitHub serves
//     release assets from a CDN, but a redirect to plain HTTP ends the attempt.
//   - Nothing is executed. The downloaded file is verified, put in place, and
//     that is all; it runs when the user next runs it.
//   - Never in CI. A pipeline whose scanner silently changes version between
//     runs is no longer reproducible, and a build is exactly where a swapped
//     binary would go unnoticed.
//   - Never automatically. The check is passive and prints a line; installing
//     is something a person asks for.
//
// The replacement itself is done by renaming rather than writing over the
// running file, because Windows will not allow the latter and because a rename
// is atomic: an interrupted update leaves either the old binary or the new one,
// never half of either.
package selfupdate

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// Repository is where releases come from.
	Repository = "itsmangooo/weedout-cli"

	// apiHost and downloadHosts are checked on every request, including after
	// a redirect. The checksum is the real control, but refusing to even talk
	// to an unexpected host means a hijacked redirect cannot serve a payload
	// to be checksummed in the first place.
	apiHost = "api.github.com"

	// maxDownload bounds what will be read from the network. Comfortably above
	// a real binary and far below anything that would fill a disk.
	maxDownload = 64 << 20

	// maxChecksums bounds the checksums file, which is a few hundred bytes.
	maxChecksums = 1 << 20

	// userAgent is required: the GitHub API rejects requests without one.
	userAgent = "weedout-cli-selfupdate"
)

// downloadHosts are where GitHub serves release assets from.
var downloadHosts = []string{
	"github.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
	"github-releases.githubusercontent.com",
}

// Release is the part of a GitHub release this needs.
type Release struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

// Available describes an update that could be installed.
type Available struct {
	Current Version
	Latest  Version
	// AssetName is the file that would be downloaded.
	AssetName string
	// Compressed reports whether that asset is gzipped.
	Compressed bool
	assetURL   string
	checksums  string
	notesURL   string
}

// NotesURL links to the release notes, so somebody deciding whether to update
// can read what changed first.
func (a Available) NotesURL() string { return a.notesURL }

// Check asks GitHub what the newest release is.
//
// Returns ok=false when there is nothing newer, which includes the case where
// the running binary is a development build: those are deliberately never
// offered an update.
func Check(current string, timeout time.Duration) (Available, bool, error) {
	running, parsed := ParseVersion(current)
	if !parsed {
		// Not a release build. Nothing to compare against, and replacing a
		// binary somebody compiled themselves is not this function's business.
		return Available{Current: running}, false, nil
	}

	release, err := latestRelease(timeout)
	if err != nil {
		return Available{Current: running}, false, err
	}

	latest, ok := ParseVersion(release.TagName)
	if !ok {
		return Available{Current: running}, false, fmt.Errorf(
			"the latest release is tagged %q, which is not a version this understands",
			release.TagName)
	}
	if !latest.NewerThan(running) {
		return Available{Current: running, Latest: latest}, false, nil
	}

	update := Available{
		Current:  running,
		Latest:   latest,
		notesURL: release.HTMLURL,
	}

	// The gzipped asset is preferred: it is roughly 40% of the size of the raw
	// binary, and compress/gzip is already linked in through net/http, so
	// decompressing costs nothing that has not already been paid for.
	//
	// Both are collected before choosing, rather than taking whichever is seen
	// first, because the order GitHub lists assets in is not something to
	// depend on.
	plain := assetName()
	var plainURL, compressedURL string
	for _, asset := range release.Assets {
		switch asset.Name {
		case plain:
			plainURL = asset.URL
		case plain + ".gz":
			compressedURL = asset.URL
		case "checksums.txt":
			update.checksums = asset.URL
		}
	}

	switch {
	case compressedURL != "":
		update.AssetName, update.assetURL, update.Compressed = plain+".gz", compressedURL, true
	case plainURL != "":
		update.AssetName, update.assetURL = plain, plainURL
	}

	if update.assetURL == "" {
		return update, false, fmt.Errorf(
			"release %s has no build for %s/%s", release.TagName, runtime.GOOS, runtime.GOARCH)
	}
	if update.checksums == "" {
		// Refused rather than downgraded to an unverified download. An update
		// path that silently drops its integrity check the one time the file
		// is missing is an update path with no integrity check.
		return update, false, fmt.Errorf(
			"release %s publishes no checksums.txt, so the download cannot be verified",
			release.TagName)
	}
	return update, true, nil
}

// assetName is what the release workflow calls the build for this platform.
func assetName() string {
	name := fmt.Sprintf("weedout-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// Install downloads, verifies and swaps in the update.
//
// The binary on disk is only touched after the download has been checksummed,
// so a failure at any earlier point leaves a working tool.
func (a Available) Install(timeout time.Duration) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not find the running binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		// Follow the symlink and replace what it points at. Replacing the link
		// itself would leave the real binary stale and break the link's
		// purpose, which is usually a version manager's layout.
		executable = resolved
	}

	expected, err := fetchChecksum(a.checksums, a.AssetName, timeout)
	if err != nil {
		return err
	}

	payload, err := download(a.assetURL, timeout)
	if err != nil {
		return err
	}

	if err := verify(payload, expected); err != nil {
		return err
	}

	binary := payload
	if a.Compressed {
		if binary, err = gunzip(payload); err != nil {
			return fmt.Errorf("the download could not be decompressed: %w", err)
		}
	}
	if len(binary) == 0 {
		return fmt.Errorf("the download was empty")
	}

	return replaceExecutable(executable, binary)
}

// replaceExecutable puts the new binary where the old one is.
//
// Written to the same directory as the target, never to a temporary directory:
// a rename across filesystems is not atomic and silently degrades to a copy,
// which is exactly the non-atomic replacement this is avoiding.
func replaceExecutable(path string, binary []byte) error {
	directory := filepath.Dir(path)

	staged, err := os.CreateTemp(directory, ".weedout-update-*")
	if err != nil {
		return fmt.Errorf(
			"cannot write to %s: %w\nThe binary lives somewhere this user cannot modify; "+
				"re-run with the rights to write there, or reinstall.", directory, err)
	}
	stagedName := staged.Name()

	cleanup := func() { os.Remove(stagedName) }

	if _, err := staged.Write(binary); err != nil {
		staged.Close()
		cleanup()
		return err
	}
	if err := staged.Close(); err != nil {
		cleanup()
		return err
	}
	// Before it is in place, so the file is never briefly present-but-not-
	// executable at the path people run.
	if err := os.Chmod(stagedName, 0o755); err != nil {
		cleanup()
		return err
	}

	// Windows will not overwrite or delete a running executable, but it will
	// rename one. Moving the current binary aside first therefore works on
	// every platform, and gives a rollback target if the second rename fails.
	retired := path + ".old"
	os.Remove(retired) // A leftover from a previous update on Windows.

	if err := os.Rename(path, retired); err != nil {
		cleanup()
		return fmt.Errorf("could not move the current binary aside: %w", err)
	}

	if err := os.Rename(stagedName, path); err != nil {
		// Put it back. Leaving the user with no binary at all would be far
		// worse than failing to update.
		if rollback := os.Rename(retired, path); rollback != nil {
			return fmt.Errorf(
				"the update failed and the original could not be restored: %w\n"+
					"The previous binary is at %s -- rename it back to %s.",
				err, retired, path)
		}
		cleanup()
		return fmt.Errorf("could not put the new binary in place: %w", err)
	}

	// Best effort. On Windows this fails while the old binary is still running,
	// which is why CleanUp exists and runs at startup.
	os.Remove(retired)
	return nil
}

// CleanUp removes the previous binary left behind by an update.
//
// Called at startup because Windows cannot delete a running executable: the
// update renames it to .old, fails to remove it, and the next run -- which is
// a different process, with the old file no longer open -- clears it.
//
// Silent and best-effort. A leftover file is untidy, not broken, and a warning
// about it on every invocation would be worse than the file.
func CleanUp() {
	executable, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	os.Remove(executable + ".old")
}

// latestRelease fetches the newest release from the GitHub API.
func latestRelease(timeout time.Duration) (Release, error) {
	endpoint := fmt.Sprintf("https://%s/repos/%s/releases/latest", apiHost, Repository)

	body, err := get(endpoint, timeout, maxChecksums, "application/vnd.github+json")
	if err != nil {
		return Release{}, err
	}

	var release Release
	if err := json.Unmarshal(body, &release); err != nil {
		return Release{}, fmt.Errorf("GitHub sent a response that was not a release: %w", err)
	}
	if release.TagName == "" {
		return Release{}, fmt.Errorf("no published releases yet")
	}
	return release, nil
}

// verify checks a download against its published digest.
//
// Split out from the download so it can be tested directly. This is the single
// control standing between a compromised network path and an attacker-supplied
// binary sitting at the path the user runs, and a control no test ever
// exercises is a control nobody knows works.
func verify(payload []byte, expected string) error {
	sum := sha256.Sum256(payload)
	got := hex.EncodeToString(sum[:])
	if got == expected {
		return nil
	}
	// The one failure worth being loud about. Everything else in this package
	// is a network problem; this is either corruption or somebody serving a
	// binary that is not the released one.
	return fmt.Errorf(
		"the download does not match its published checksum.\n"+
			"  expected %s\n  received %s\n"+
			"Nothing was installed. Report this if it repeats.",
		expected, got)
}

// fetchChecksum finds one file's expected SHA-256 in the release checksums.
func fetchChecksum(checksumsURL, name string, timeout time.Duration) (string, error) {
	body, err := get(checksumsURL, timeout, maxChecksums, "")
	if err != nil {
		return "", fmt.Errorf("could not fetch the checksums: %w", err)
	}
	return parseChecksums(body, name)
}

// parseChecksums finds one entry in a sha256sum-format file.
//
// The format is the digest, whitespace, then the filename. A line that is not
// exactly two fields is skipped rather than treated as an error: the file is
// generated, but a blank line or some future header should not be the reason
// an update refuses to install.
func parseChecksums(body []byte, name string) (string, error) {
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		// sha256sum writes a leading * for binary mode on some platforms.
		if strings.TrimPrefix(fields[1], "*") == name {
			digest := strings.ToLower(fields[0])
			if len(digest) != 64 {
				return "", fmt.Errorf("the checksum for %s is malformed", name)
			}
			if _, err := hex.DecodeString(digest); err != nil {
				return "", fmt.Errorf("the checksum for %s is not hexadecimal", name)
			}
			return digest, nil
		}
	}
	return "", fmt.Errorf("the release checksums do not cover %s, so it cannot be verified", name)
}

func download(assetURL string, timeout time.Duration) ([]byte, error) {
	return get(assetURL, timeout, maxDownload, "application/octet-stream")
}

// get performs one bounded HTTPS request, refusing anything off-host.
func get(rawURL string, timeout time.Duration, limit int64, accept string) ([]byte, error) {
	if err := checkURL(rawURL); err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", userAgent)
	if accept != "" {
		request.Header.Set("Accept", accept)
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			// Re-checked on every hop. A redirect is how the CDN is reached,
			// and it is also how an attacker with control of one response
			// would move the download somewhere else.
			return checkURL(req.URL.String())
		},
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("could not reach GitHub: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found (%s)", rawURL)
	}
	if response.StatusCode == http.StatusForbidden {
		// Unauthenticated GitHub API calls are limited by IP, and a shared
		// office address hits it. Worth naming, since the obvious reading of a
		// 403 is that something is wrong with the tool.
		return nil, fmt.Errorf(
			"GitHub refused the request (403). This is usually its rate limit for " +
				"unauthenticated callers; try again in a little while")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("the download was interrupted: %w", err)
	}
	if int64(len(body)) >= limit {
		return nil, fmt.Errorf("the download exceeded %d bytes and was abandoned", limit)
	}
	return body, nil
}

// checkURL enforces HTTPS and a known host.
func checkURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("unusable URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf(
			"refusing to fetch an update over %s: only https is allowed", parsed.Scheme)
	}

	host := parsed.Hostname()
	if host == apiHost {
		return nil
	}
	for _, allowed := range downloadHosts {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return nil
		}
	}
	return fmt.Errorf("refusing to fetch an update from %s", host)
}

func gunzip(payload []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, maxDownload))
}
