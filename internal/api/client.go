// Package api talks to the scan endpoint using only the standard library.
//
// net/http rather than a client library on purpose: this is one POST request
// wide, and a CI runner is the last place that benefits from a dependency tree.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// UserAgent identifies the CLI to the server.
const UserAgent = "weedout-cli"

// DefaultTimeout is generous, because the caller is a pipeline that would
// rather wait than retry. The server does no outbound HTTP during a scan, so a
// slow response means a large lockfile, not a stalled upstream.
const DefaultTimeout = 120 * time.Second

// Error is a refused or unreachable request.
//
// It carries the server's machine-readable code when there was one, so callers
// can tell "your key is wrong" from "the service is down" without matching on
// prose.
type Error struct {
	Message string
	Code    string
	Status  int
}

func (e *Error) Error() string { return e.Message }

// Finding is one reported vulnerability.
type Finding struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	CVE       string `json:"cve"`
	Severity  string `json:"severity"`
	Exploited bool   `json:"exploited"`
	// Malicious is its own field rather than a severity value: a malicious
	// package carries no CVSS score, so anything that ranks severities would
	// sort the worst finding here below a medium.
	Malicious bool   `json:"malicious"`
	FixedIn   string `json:"fixed_in"`
	Summary   string `json:"summary"`
}

// Result is the parsed scan response.
type Result struct {
	Project             string         `json:"project"`
	DependenciesScanned int            `json:"dependencies_scanned"`
	Actionable          int            `json:"actionable"`
	Suppressed          int            `json:"suppressed"`
	New                 int            `json:"new"`
	Resolved            int            `json:"resolved"`
	Counts              map[string]int `json:"counts"`
	Findings            []Finding      `json:"findings"`
	Warnings            []string       `json:"warnings"`
	DashboardURL        string         `json:"dashboard_url"`
}

// Critical is the count of critical-severity findings.
func (r Result) Critical() int { return r.Counts["critical"] }

// Malicious is the count of dependencies that are malware rather than
// packages with a vulnerability in them.
func (r Result) Malicious() int { return r.Counts["malicious"] }

// Exploited is the count of findings confirmed exploited in the wild.
func (r Result) Exploited() int { return r.Counts["exploited"] }

// Threshold is the severity floor --ci fails on.
type Threshold string

// The two that exist. Not every severity is offered: "fail on low" is a
// setting nobody leaves switched on, and offering it invites a pipeline
// configuration that gets disabled a week later rather than tuned.
const (
	// ThresholdCritical fails on critical severity or confirmed exploitation.
	ThresholdCritical Threshold = "critical"
	// ThresholdHigh additionally fails on high severity.
	ThresholdHigh Threshold = "high"
)

// ParseThreshold maps a --fail-on value. The empty string means the default.
func ParseThreshold(value string) (Threshold, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "critical":
		return ThresholdCritical, nil
	case "high":
		return ThresholdHigh, nil
	default:
		return "", fmt.Errorf("unknown --fail-on value %q: use \"critical\" or \"high\"", value)
	}
}

// Blocks reports whether one finding clears the threshold.
//
// Confirmed exploitation and outright malware block at every threshold,
// whatever the CVSS score says. A vulnerability with working public
// exploitation is not a medium problem because a scoring rubric said so, and a
// package that is malware is not a low one because nobody scored it at all.
func (f Finding) Blocks(t Threshold) bool {
	// Malware first, and at every threshold. A malicious package has no CVSS
	// score, so a check that only reads severity lets the single worst thing
	// this scanner can find straight through the gate.
	if f.Malicious {
		return true
	}
	if f.Exploited || f.Severity == "critical" {
		return true
	}
	return t == ThresholdHigh && f.Severity == "high"
}

// Blocking is what --ci fails on at the default threshold.
func (r Result) Blocking() int { return r.BlockingAt(ThresholdCritical) }

// BlockingAt counts the findings that clear a threshold.
//
// Counted from the findings list rather than by adding the severity counters —
// a finding that is both critical and exploited is one problem, and summing
// would report it twice.
func (r Result) BlockingAt(t Threshold) int {
	n := 0
	for _, f := range r.Findings {
		if f.Blocks(t) {
			n++
		}
	}
	return n
}

// MaxManifestBytes matches what the server accepts.
//
// Checked here as well, so a mistake -- a lockfile with a megabyte of vendored
// data, or a path pointing at something that is not a manifest at all -- fails
// in a sentence instead of by reading the file into memory and uploading it to
// be refused.
const MaxManifestBytes = 5 << 20

// PostScan uploads a manifest and returns the parsed result.
// ScanRequest is everything one scan sends beyond the key.
//
// A struct rather than four positional arguments: the last two are both
// optional strings, and a call site that swapped them would compile.
type ScanRequest struct {
	// ManifestPath is the lockfile to scan. Required.
	ManifestPath string
	// PolicyPath is a .weedout.yml found beside it, or "" if there is none.
	//
	// The server never sees the repository, only what is uploaded, so the
	// rules have to travel with the scan. That is also what makes CI the
	// source of truth: the file that ran in the pipeline is the file that
	// applied.
	PolicyPath string
	// Profile names one of the account's rule profiles, or "" to let the
	// server decide from the project and the account default. Resolved
	// server-side -- a name that does not exist fails the scan rather than
	// quietly running on the defaults.
	Profile string
}

func PostScan(baseURL, apiKey, path string, timeout time.Duration) (Result, error) {
	return PostScanRequest(baseURL, apiKey, ScanRequest{ManifestPath: path}, timeout)
}

func PostScanRequest(
	baseURL, apiKey string, req ScanRequest, timeout time.Duration,
) (Result, error) {
	path := req.ManifestPath
	info, err := os.Stat(path)
	if err != nil {
		return Result{}, &Error{
			Message: fmt.Sprintf("Could not read %s: %v", path, err),
			Code:    "unreadable_file",
		}
	}
	if info.Size() > MaxManifestBytes {
		return Result{}, &Error{
			Message: fmt.Sprintf(
				"%s is %d MB, and the limit is %d MB. Point at a lockfile rather than a bundle.",
				filepath.Base(path), info.Size()>>20, MaxManifestBytes>>20),
			Code: "file_too_large",
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return Result{}, &Error{
			Message: fmt.Sprintf("Could not read %s: %v", path, err),
			Code:    "unreadable_file",
		}
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("manifest", filepath.Base(path))
	if err != nil {
		return Result{}, &Error{Message: err.Error(), Code: "encode_failed"}
	}
	if _, err := part.Write(content); err != nil {
		return Result{}, &Error{Message: err.Error(), Code: "encode_failed"}
	}
	if req.PolicyPath != "" {
		// Read failures are not fatal here. A .weedout.yml that cannot be read
		// means the scan runs on the defaults, which can only produce more
		// alerts than intended -- and failing the pipeline over a file the
		// caller may not know exists would be the worse trade.
		if policy, err := os.ReadFile(req.PolicyPath); err == nil {
			if part, err := writer.CreateFormFile("policy", filepath.Base(req.PolicyPath)); err == nil {
				_, _ = part.Write(policy)
			}
		}
	}

	if req.Profile != "" {
		_ = writer.WriteField("profile", req.Profile)
	}

	if err := writer.Close(); err != nil {
		return Result{}, &Error{Message: err.Error(), Code: "encode_failed"}
	}

	endpoint := strings.TrimRight(baseURL, "/") + "/api/v1/scan"
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return Result{}, &Error{
			Message: fmt.Sprintf("Unsupported URL: %s", endpoint),
			Code:    "bad_url",
		}
	}

	request, err := http.NewRequest(http.MethodPost, endpoint, body)
	if err != nil {
		return Result{}, &Error{Message: err.Error(), Code: "bad_request"}
	}
	request.Header.Set("Authorization", "Bearer "+apiKey)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", UserAgent)

	client := &http.Client{Timeout: timeout}

	payload, status, err := doWithRetry(client, request, body.Bytes(), baseURL)
	if err != nil {
		return Result{}, err
	}

	if status != http.StatusOK {
		return Result{}, errorFromResponse(status, payload)
	}

	var result Result
	if err := json.Unmarshal(payload, &result); err != nil {
		return Result{}, &Error{
			Message: "The server sent a response that was not JSON.",
			Code:    "bad_response",
			Status:  status,
		}
	}
	if result.Counts == nil {
		result.Counts = map[string]int{}
	}
	return result, nil
}

// Attempts is how many times a transient failure is retried before giving up.
//
// Small on purpose. This runs inside somebody's build, and a step that spends
// two minutes retrying is worse than one that fails in ten seconds with a
// message saying what went wrong.
const Attempts = 3

// RetryDelay is the wait before attempt n (1-indexed), so 0s, 1s, 3s.
//
// A variable rather than a constant so tests can flatten it. Without that the
// suite pays four real seconds for every retry case, which is a cost that only
// grows and eventually gets paid by deleting the tests.
var RetryDelay = func(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 0
	case 2:
		return time.Second
	default:
		return 3 * time.Second
	}
}

// retryable reports whether a status is worth a second attempt.
//
// Only the ones where trying again can plausibly work: a gateway that was
// restarting, a rate limit that has since expired, a request that timed out in
// transit. A 401 will be a 401 next time too, and retrying it would turn one
// clear "your key is wrong" into three.
func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// doWithRetry sends the request, retrying transient failures.
//
// The body is passed separately and rebuilt for each attempt: an
// http.Request's body is a reader that is consumed by the first send, so
// retrying without rebuilding it uploads zero bytes and gets a confusing 400.
func doWithRetry(
	client *http.Client, request *http.Request, body []byte, baseURL string,
) ([]byte, int, error) {
	var lastErr error
	var lastStatus int
	var lastPayload []byte

	for attempt := 1; attempt <= Attempts; attempt++ {
		if wait := RetryDelay(attempt); wait > 0 {
			time.Sleep(wait)
		}

		attemptReq := request.Clone(request.Context())
		attemptReq.Body = io.NopCloser(bytes.NewReader(body))
		attemptReq.ContentLength = int64(len(body))

		response, err := client.Do(attemptReq)
		if err != nil {
			// A timeout or a refused connection. Both are worth another go:
			// CI networks are not reliable, and a runner that just came up may
			// beat its own DNS.
			lastErr = &Error{
				Message: fmt.Sprintf("Could not reach %s: %v", baseURL, unwrapNetError(err)),
				Code:    "unreachable",
			}
			continue
		}

		// Bounded read. A misconfigured URL can point at something that
		// streams indefinitely, and a CI step should fail rather than fill the
		// disk.
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		response.Body.Close()
		if readErr != nil {
			lastErr = &Error{
				Message: "Truncated response from the server.",
				Code:    "bad_response",
			}
			continue
		}

		if retryable(response.StatusCode) && attempt < Attempts {
			lastStatus, lastPayload, lastErr = response.StatusCode, payload, nil
			continue
		}

		return payload, response.StatusCode, nil
	}

	if lastErr != nil {
		return nil, 0, lastErr
	}
	// Ran out of attempts on a retryable status; report the server's own words.
	return lastPayload, lastStatus, nil
}

func unwrapNetError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

func errorFromResponse(status int, payload []byte) *Error {
	// Prefer the server's own words.
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	_ = json.Unmarshal(payload, &body)

	// `error` is a machine-readable code, not prose. Showing "invalid_key" to
	// somebody whose build just failed tells them nothing they can act on, so
	// it is only used as the message when it actually reads like a sentence.
	message := firstNonEmpty(body.Message, body.Detail)
	if message == "" && strings.Contains(body.Error, " ") {
		message = body.Error
	}
	if message == "" {
		// A proxy or load balancer between here and the API returns HTML. That
		// is still a real error the caller must hear about, so it falls back to
		// a sentence rather than surfacing markup.
		if fallback, ok := fallbackMessages[status]; ok {
			message = fallback
		} else {
			message = fmt.Sprintf("The server returned HTTP %d.", status)
		}
	}
	return &Error{Message: message, Code: body.Error, Status: status}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

var fallbackMessages = map[int]string{
	401: "That API key was not accepted. Check WEEDOUT_API_KEY, or create a new key in Settings.",
	403: "That key is not allowed to do this.",
	404: "No scan endpoint at that URL. Check the configured address.",
	413: "That file is too large to scan.",
	429: "Too many scans for this project right now. Try again shortly.",
	503: "The scan could not be completed. Nothing was checked; this is not a clean result.",
}
