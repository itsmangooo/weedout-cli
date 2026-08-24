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

// The two calls behind `weedout auth`.
//
// Neither carries a credential: the whole point of the flow is that this
// machine does not have one yet. What makes it safe is on the other side --
// the start writes one short-lived row and is rate limited, and the poll needs
// the 256-bit device code that only this process has ever held.
//
// Deliberately not under /api/v1: that namespace is bearer-key authenticated
// and asserted to be so, and these two would be a hole in that assertion.

// AuthStart is what the server says when a login begins.
type AuthStart struct {
	// UserCode is short, and the person compares it against the browser. It is
	// printed, not sent anywhere.
	UserCode string `json:"user_code"`
	// VerificationURL already carries the code, so the page can pre-fill it.
	VerificationURL string `json:"verification_url"`
	// VerificationURLPlain is for anybody who would rather type it.
	VerificationURLPlain string `json:"verification_url_plain"`
	// DeviceCode is the secret this process polls with. Never printed, never
	// logged, never written to disk.
	DeviceCode string `json:"device_code"`
	ExpiresIn  int    `json:"expires_in"`
	Interval   int    `json:"interval"`
}

// AuthPoll is one answer to "has somebody approved it yet".
type AuthPoll struct {
	// State is "pending", "approved", "denied" or "expired". Four values
	// because all four mean different things to the person watching a
	// terminal.
	State string `json:"state"`
	Token string `json:"token"`
	Email string `json:"email"`
	// Interval is the server's advice on how long to wait, echoed on every
	// pending response so it can change without a client release.
	Interval int `json:"interval"`
}

// StartAuth begins a login and returns what to show and what to poll with.
func StartAuth(baseURL, deviceLabel string, timeout time.Duration) (AuthStart, error) {
	body, err := json.Marshal(map[string]string{"device_label": deviceLabel})
	if err != nil {
		return AuthStart{}, &Error{Message: err.Error(), Code: "encode_failed"}
	}

	var out AuthStart
	err = callUnauthenticated(baseURL, http.MethodPost, "/api/cli-auth/start", body, timeout, &out)
	return out, err
}

// PollAuth asks whether the login has been approved.
func PollAuth(baseURL, deviceCode string, timeout time.Duration) (AuthPoll, error) {
	body, err := json.Marshal(map[string]string{"device_code": deviceCode})
	if err != nil {
		return AuthPoll{}, &Error{Message: err.Error(), Code: "encode_failed"}
	}

	var out AuthPoll
	err = callUnauthenticated(baseURL, http.MethodPost, "/api/cli-auth/poll", body, timeout, &out)
	return out, err
}

// callUnauthenticated is `call` without the Authorization header.
//
// A separate function rather than a nil key passed to `call`, so no
// authenticated path can ever reach here by accident and send a request with
// no credential that quietly succeeds against something that should have
// refused it.
func callUnauthenticated(
	baseURL, method, path string, body []byte, timeout time.Duration, out any,
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
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", UserAgent)
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: timeout}
	payload, status, err := doWithRetry(client, request, body, baseURL)
	if err != nil {
		return err
	}
	if status >= 400 {
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
