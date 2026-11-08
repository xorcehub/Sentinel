package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadLiveWithoutLocalIsShippedOnly(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.yml"), "title: a")
	write(t, filepath.Join(dir, ExampleDir, "x.yml"), "title: example")
	data, n, err := ReadLive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || strings.Contains(string(data), "example") {
		t.Fatalf("fresh layout must load no overlays (and never local.example); n=%d data=%q", n, data)
	}
}

func TestReadLivePicksUpLocal(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.yml"), "title: a")
	write(t, filepath.Join(dir, LocalDir, "t.yml"), "title: local")
	write(t, filepath.Join(dir, LocalDir, "notes.txt"), "ignored")
	data, n, err := ReadLive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || !strings.Contains(string(data), "title: local") {
		t.Fatalf("n=%d data=%q", n, data)
	}
	if !strings.HasPrefix(string(data), "title: a\n---\n") {
		t.Fatalf("shipped files must come first, separated: %q", data)
	}
}

func TestReadNeedsShippedRules(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, LocalDir, "t.yml"), "title: local")
	if _, _, err := ReadLive(dir); err == nil {
		t.Fatal("overlays alone (no shipped rules) must be an error")
	}
}
