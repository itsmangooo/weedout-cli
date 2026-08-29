package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPostScanUploadsBoundedSourceContext(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "package-lock.json")
	if err := os.WriteFile(manifest, []byte(`{"lockfileVersion":3}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var gotContext struct {
		Complete bool     `json:"complete"`
		Files    []string `json:"files"`
		Notes    []string `json:"notes"`
	}
	var gotSources = map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/scan" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer wo_test" {
			t.Errorf("credential was not sent in the authorization header")
		}
		if err := r.ParseMultipartForm(MaxManifestBytes); err != nil {
			t.Errorf("multipart parse failed: %v", err)
		}
		for _, header := range r.MultipartForm.File["sources"] {
			file, err := header.Open()
			if err != nil {
				t.Fatal(err)
			}
			content, _ := io.ReadAll(file)
			_ = file.Close()
			gotSources[header.Filename] = string(content)
		}
		if err := json.Unmarshal([]byte(r.FormValue("source_context")), &gotContext); err != nil {
			t.Errorf("source context was not JSON: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"project":"demo","counts":{},"findings":[]}`)
	}))
	t.Cleanup(server.Close)

	_, err := PostScanRequest(
		server.URL,
		"wo_test",
		ScanRequest{
			ManifestPath: manifest,
			Sources: []SourceFile{
				{Path: "src/api.js", Content: []byte(`import axios from "axios"`)},
				{Path: "test/config.js", Content: []byte(`require("express")`)},
			},
			SourceComplete: false,
			SourceNotes:    []string{"Skipped oversized source file src/generated.js."},
		},
		2*time.Second,
	)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if !reflect.DeepEqual(gotContext.Files, []string{"src/api.js", "test/config.js"}) {
		t.Fatalf("source paths lost their repository context: %#v", gotContext.Files)
	}
	if gotContext.Complete {
		t.Fatal("incomplete collection was reported complete")
	}
	if len(gotContext.Notes) != 1 {
		t.Fatalf("collection notes were lost: %#v", gotContext.Notes)
	}
	if gotSources["api.js"] == "" || gotSources["config.js"] == "" {
		t.Fatalf("source bodies were not uploaded: %#v", gotSources)
	}
}
