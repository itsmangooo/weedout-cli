package reachability

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectIncludesSourceAndSkipsDependencies(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "axios"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "api.js"), []byte("import axios from 'axios'"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "axios", "index.js"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}

	bundle := Collect(root)
	if !bundle.Complete {
		t.Fatalf("complete source tree was marked incomplete: %v", bundle.Notes)
	}
	if len(bundle.Files) != 1 || bundle.Files[0].Path != "src/api.js" {
		t.Fatalf("unexpected source inventory: %#v", bundle.Files)
	}
}

func TestCollectMarksOversizedSourceIncomplete(t *testing.T) {
	root := t.TempDir()
	large := make([]byte, MaxFileBytes+1)
	if err := os.WriteFile(filepath.Join(root, "generated.js"), large, 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := Collect(root)
	if bundle.Complete {
		t.Fatal("an omitted source file must make negative reachability unsafe")
	}
	if len(bundle.Files) != 0 {
		t.Fatal("oversized source was uploaded")
	}
}
