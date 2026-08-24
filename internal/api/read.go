package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The read and manage side of the API.
//
// `scan` is the only call a pipeline makes, and it lives in client.go with the
// multipart handling it needs. Everything here is what a person runs at a
// terminal instead of opening the dashboard, so it shares one small JSON
// helper rather than repeating the request plumbing five times.
//
// These need a key with a wider scope than a CI key has. That is deliberate on
// the server, and the message it returns for the wrong scope is specific
// enough to print as-is.

// Status is a project at a glance -- what the dashboard leads with.
type Status struct {
	// Plan is what the account can do right now. See plan.go.
	Plan         Plan           `json:"plan"`
	Project      string         `json:"project"`
	Ecosystem    string         `json:"ecosystem"`
	Dependencies int            `json:"dependencies"`
	LastScanned  string         `json:"last_scanned_at"`
	NextScan     string         `json:"next_scan_at"`
	LastError    string         `json:"last_error"`
	Counts       map[string]int `json:"counts"`
	Open         int            `json:"open"`
	Filtered     int            `json:"filtered"`
	Dismissed    int            `json:"dismissed"`
	Resolved     int            `json:"resolved"`
	// Packages the plan did not reach. Reported rather than left to be
	// inferred from a smaller number: nothing was found there because nothing
	// was looked at.
	UnreachedByDepth int    `json:"unreached_by_depth"`
	DashboardURL     string `json:"dashboard_url"`
}

// Detail is one finding, carrying more than the scan response does.
type Detail struct {
	ID        int      `json:"id"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	CVE       string   `json:"cve"`
	Advisory  string   `json:"advisory"`
	Severity  string   `json:"severity"`
	Exploited bool     `json:"exploited"`
	Malicious bool     `json:"malicious"`
	EPSS      *float64 `json:"epss"`
	FixedIn   string   `json:"fixed_in"`
	Summary   string   `json:"summary"`
	Via       []string `json:"via"`
	Depth     int      `json:"depth"`
	Reason    string   `json:"reason"`
	FirstSeen string   `json:"first_seen_at"`
}

// Chain renders how a package got into the tree, which is usually the
// difference between upgrading this package and upgrading whatever wants it.
func (d Detail) Chain() string {
	if len(d.Via) == 0 {
		return "direct dependency"
	}
	return strings.Join(append(append([]string{}, d.Via...), d.Package), " > ")
}

// Findings is one page of findings.
type Findings struct {
	Plan     Plan     `json:"plan"`
	Show     string   `json:"show"`
	Count    int      `json:"count"`
	Findings []Detail `json:"findings"`
}

// Run is one scan in the history.
type Run struct {
	StartedAt    string  `json:"started_at"`
	Status       string  `json:"status"`
	Dependencies int     `json:"dependencies_scanned"`
	Actionable   int     `json:"actionable"`
	Suppressed   int     `json:"suppressed"`
	New          int     `json:"new"`
	Resolved     int     `json:"resolved"`
	Duration     float64 `json:"duration_seconds"`
	Error        string  `json:"error"`
}

// History is the recent-checks panel.
type History struct {
	Runs []Run `json:"runs"`
}

// Signal is something about a package itself rather than a version of it.
type Signal struct {
	Package string `json:"package"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Level   string `json:"level"`
	Detail  string `json:"detail"`
}

// SupplyChain is the set of open package signals.
type SupplyChain struct {
	Signals []Signal `json:"signals"`
}

// Ignore is one advisory this project has been told to skip.
type Ignore struct {
	Identifier string `json:"identifier"`
	// "advisory" or "package". Absent on a server that predates package
	// rules, which means advisory — the same default the server applies.
	Kind      string `json:"kind"`
	Reason    string `json:"reason"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
	// Set when a KEV listing set the rule aside. A rule that stopped applying
	// is worth saying out loud, because somebody wrote it expecting silence.
	OverriddenAt string `json:"overridden_at"`
}

// PolicyFile is the state of the checked-in config as the server saw it.
type PolicyFile struct {
	Present   bool     `json:"present"`
	UpdatedAt string   `json:"updated_at"`
	Error     string   `json:"error"`
	Ignores   []string `json:"ignores"`
	// Package globs from the same file. Listed separately because they read
	// differently: an id names one advisory, a glob names a family of packages
	// and every advisory that will ever be written about them.
	IgnoredPackages []string `json:"ignored_packages"`
}

// Thresholds are the per-project severity floors.
type Thresholds struct {
	Direct     string   `json:"direct"`
	Transitive string   `json:"transitive"`
	EPSS       *float64 `json:"epss"`
}

// Rules is everything that shapes what this project reports.
type Rules struct {
	// Plan matters here more than anywhere else: a Free account sees a tidy
	// list of rules that are not doing anything, and nothing else on the page
	// would say so.
	Plan       Plan       `json:"plan"`
	Thresholds Thresholds `json:"thresholds"`
	Ignores    []Ignore   `json:"ignores"`
	PolicyFile PolicyFile `json:"policy_file"`
}

// Profile is one named rule set on the account.
type Profile struct {
	Name string `json:"name"`
	// Slug is what --profile matches. Given by the server so nobody has to
	// reproduce the normalisation by guesswork.
	Slug        string `json:"slug"`
	Description string `json:"description"`
	IsDefault   bool   `json:"is_default"`
	// InUseHere is set when this project chose the profile explicitly, which
	// is a different thing from inheriting the account default.
	InUseHere bool   `json:"in_use_here"`
	Document  string `json:"document"`
}

// Profiles is the account's rule profiles and which one applies here.
type Profiles struct {
	Profiles []Profile `json:"profiles"`
	// AppliesHere is what a scan with no --profile would run under. Empty when
	// the account has neither a choice on this project nor a default.
	AppliesHere string `json:"applies_here"`
}

// GetProfiles fetches the account's rule profiles.
func GetProfiles(baseURL, apiKey string, timeout time.Duration) (Profiles, error) {
	var out Profiles
	err := call(baseURL, apiKey, http.MethodGet, "/api/v1/profiles", nil, timeout, &out)
	return out, err
}

// HasAny reports whether this project has configured anything at all.
//
// Used to decide whether a "none of these are applying" warning has a subject.
// Telling a Free account with no rules that its rules are not applying would be
// noise, and noise on a page about filtering noise is worse than most.
func (r Rules) HasAny() bool {
	return len(r.Ignores) > 0 ||
		r.Thresholds.Direct != "" ||
		r.Thresholds.Transitive != "" ||
		r.Thresholds.EPSS != nil ||
		len(r.PolicyFile.Ignores) > 0 ||
		len(r.PolicyFile.IgnoredPackages) > 0
}

// GetStatus fetches the project overview.
func GetStatus(baseURL, apiKey string, timeout time.Duration) (Status, error) {
	var out Status
	err := call(baseURL, apiKey, http.MethodGet, "/api/v1/project", nil, timeout, &out)
	return out, err
}

// GetFindings fetches one page of findings. `show` mirrors the dashboard tabs.
func GetFindings(baseURL, apiKey, show string, limit int, timeout time.Duration) (Findings, error) {
	var out Findings
	path := fmt.Sprintf("/api/v1/findings?show=%s&limit=%d", url.QueryEscape(show), limit)
	err := call(baseURL, apiKey, http.MethodGet, path, nil, timeout, &out)
	return out, err
}

// GetHistory fetches recent scans, newest first.
func GetHistory(baseURL, apiKey string, limit int, timeout time.Duration) (History, error) {
	var out History
	path := fmt.Sprintf("/api/v1/history?limit=%d", limit)
	err := call(baseURL, apiKey, http.MethodGet, path, nil, timeout, &out)
	return out, err
}

// GetSupplyChain fetches the open package signals.
func GetSupplyChain(baseURL, apiKey string, timeout time.Duration) (SupplyChain, error) {
	var out SupplyChain
	err := call(baseURL, apiKey, http.MethodGet, "/api/v1/supply-chain", nil, timeout, &out)
	return out, err
}

// GetRules fetches the project's scan rules.
func GetRules(baseURL, apiKey string, timeout time.Duration) (Rules, error) {
	var out Rules
	err := call(baseURL, apiKey, http.MethodGet, "/api/v1/rules", nil, timeout, &out)
	return out, err
}

// AddIgnore tells the project to stop reporting one advisory.
//
// The reason is required by the server, and that is worth keeping: an ignore
// rule with no reason is indistinguishable from a mistake six months later.
// kind is "advisory" or "package". It is always sent, so the server never has
// to infer which was meant from the shape of the identifier.
func AddIgnore(baseURL, apiKey, identifier, kind, reason string, timeout time.Duration) error {
	if kind == "" {
		kind = "advisory"
	}
	body, err := json.Marshal(map[string]string{
		"identifier": identifier,
		"kind":       kind,
		"reason":     reason,
	})
	if err != nil {
		return &Error{Message: err.Error(), Code: "encode_failed"}
	}
	return call(baseURL, apiKey, http.MethodPost, "/api/v1/rules", body, timeout, nil)
}

// RemoveIgnore deletes an ignore rule, so the advisory is reported again.
func RemoveIgnore(baseURL, apiKey, identifier string, timeout time.Duration) error {
	path := "/api/v1/rules/" + url.PathEscape(identifier)
	return call(baseURL, apiKey, http.MethodDelete, path, nil, timeout, nil)
}

// call performs one JSON request and decodes the response into out.
//
// Shares doWithRetry with the scan path, so a flaky network behaves the same
// way whichever command hit it. out may be nil for calls whose body is not
// worth decoding.
func call(
	baseURL, apiKey, method, path string, body []byte, timeout time.Duration, out any,
) error {
	endpoint := strings.TrimRight(baseURL, "/") + path
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return &Error{Message: fmt.Sprintf("Unsupported URL: %s", endpoint), Code: "bad_url"}
	}

	request, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		return &Error{Message: err.Error(), Code: "bad_request"}
	}
	request.Header.Set("Authorization", "Bearer "+apiKey)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", UserAgent)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: timeout}
	payload, status, err := doWithRetry(client, request, body, baseURL)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return errorFromResponse(status, payload)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return &Error{
			Message: "The server sent a response that was not JSON.",
			Code:    "bad_response",
			Status:  status,
		}
	}
	return nil
}
