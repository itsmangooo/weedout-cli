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
// Confirmed exploitation blocks at every threshold, whatever the CVSS score
// says. A vulnerability with working public exploitation is not a medium
// problem because a scoring rubric said so.
func (f Finding) Blocks(t Threshold) bool {
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

// PostScan uploads a manifest and returns the parsed result.
func PostScan(baseURL, apiKey, path string, timeout time.Duration) (Result, error) {
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
	response, err := client.Do(request)
	if err != nil {
		return Result{}, &Error{
			Message: fmt.Sprintf("Could not reach %s: %v", baseURL, unwrapNetError(err)),
			Code:    "unreachable",
		}
	}
	defer response.Body.Close()

	// Bounded read. A misconfigured URL can point at something that streams
	// indefinitely, and a CI step should fail rather than fill the disk.
	payload, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return Result{}, &Error{Message: "Truncated response from the server.", Code: "bad_response"}
	}

	if response.StatusCode != http.StatusOK {
		return Result{}, errorFromResponse(response.StatusCode, payload)
	}

	var result Result
	if err := json.Unmarshal(payload, &result); err != nil {
		return Result{}, &Error{
			Message: "The server sent a response that was not JSON.",
			Code:    "bad_response",
			Status:  response.StatusCode,
		}
	}
	if result.Counts == nil {
		result.Counts = map[string]int{}
	}
	return result, nil
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
