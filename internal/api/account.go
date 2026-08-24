package api

import (
	"encoding/json"
	"net/http"
	"time"
)

// Account-level calls, made with the credential `weedout auth` puts on a
// machine.
//
// A separate file from read.go because it is a separate credential. A project
// key cannot reach these, and this token cannot reach a finding — the server
// enforces both, and keeping the two client surfaces apart makes it hard to
// call one with the other by accident.

// AccountProject is one project as the account API describes it.
//
// No findings and no counts: this credential is not for reading results, and a
// client struct with fields the server never fills is a client struct somebody
// will try to use.
type AccountProject struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Ecosystem   string `json:"ecosystem"`
	HasManifest bool   `json:"has_manifest"`
}

// AccountProjects is the listing.
type AccountProjects struct {
	Projects []AccountProject `json:"projects"`
}

// IssuedKey is a project key the server just minted. Once.
type IssuedKey struct {
	Project  AccountProject `json:"project"`
	Key      string         `json:"key"`
	Scope    string         `json:"scope"`
	Replaced bool           `json:"replaced"`
}

// Identity is who this machine is signed in as.
type Identity struct {
	Email       string `json:"email"`
	Tier        string `json:"tier"`
	DeviceLabel string `json:"device_label"`
	ExpiresAt   string `json:"expires_at"`
}

// Whoami asks the server who this credential belongs to.
//
// Worth a request rather than reading the local file: a token revoked from the
// dashboard still sits on disk, and the only way to find out is to use it.
func Whoami(baseURL, token string, timeout time.Duration) (Identity, error) {
	var out Identity
	err := call(baseURL, token, http.MethodGet, "/api/account/whoami", nil, timeout, &out)
	return out, err
}

// ListAccountProjects fetches every project on the account.
func ListAccountProjects(baseURL, token string, timeout time.Duration) (AccountProjects, error) {
	var out AccountProjects
	err := call(baseURL, token, http.MethodGet, "/api/account/projects", nil, timeout, &out)
	return out, err
}

// CreateProject makes a project and returns a key for it, in one call.
//
// manifest may be empty, in which case ecosystem must not be: a project with
// no file has nothing to say which advisories it should be matched against,
// and the server refuses to guess.
func CreateProject(
	baseURL, token, name, filename, manifest, ecosystem, scope string, timeout time.Duration,
) (IssuedKey, error) {
	body, err := json.Marshal(map[string]string{
		"name":      name,
		"filename":  filename,
		"content":   manifest,
		"ecosystem": ecosystem,
		"scope":     scope,
	})
	if err != nil {
		return IssuedKey{}, &Error{Message: err.Error(), Code: "encode_failed"}
	}

	var out IssuedKey
	err = call(baseURL, token, http.MethodPost, "/api/account/projects", body, timeout, &out)
	return out, err
}

// MintKey issues a key for a project that already exists.
func MintKey(
	baseURL, token string, projectID int, scope string, timeout time.Duration,
) (IssuedKey, error) {
	body, err := json.Marshal(map[string]any{"project_id": projectID, "scope": scope})
	if err != nil {
		return IssuedKey{}, &Error{Message: err.Error(), Code: "encode_failed"}
	}

	var out IssuedKey
	err = call(baseURL, token, http.MethodPost, "/api/account/keys", body, timeout, &out)
	return out, err
}

// RegenerateKey replaces a project key.
//
// replaceKeyID may be 0, meaning "give me another one" rather than "throw the
// current one away". The server mints before it revokes either way, so a
// failure part-way leaves the caller with a working credential.
func RegenerateKey(
	baseURL, token string, projectID, replaceKeyID int, scope string, timeout time.Duration,
) (IssuedKey, error) {
	payload := map[string]any{"project_id": projectID, "scope": scope}
	if replaceKeyID > 0 {
		payload["replace_key_id"] = replaceKeyID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return IssuedKey{}, &Error{Message: err.Error(), Code: "encode_failed"}
	}

	var out IssuedKey
	err = call(baseURL, token, http.MethodPost, "/api/account/keys/regenerate", body, timeout, &out)
	return out, err
}
