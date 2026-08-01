//go:build windows

package ingest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinel/internal/event"
	"sentinel/internal/pathnorm"
)

// newSelfParentsForTest builds a selfParents from real temp files (with their
// current on-disk hash), so matches() exercises the actual sha256 verify path.
func newSelfParentsForTest(t *testing.T, paths ...string) *selfParents {
	t.Helper()
	sp := &selfParents{want: map[string]string{}, ok: map[string]time.Time{}}
	for _, p := range paths {
		h, err := sha256of(p)
		if err != nil {
			t.Fatalf("sha256of %s: %v", p, err)
		}
		sp.want[pathnorm.NormalizePath(p)] = h
	}
	return sp
}

// TestIsSelfChild verifies the hash-gated self-ingestion filter: events whose
// parent is a sentinel binary (verified on disk) are skipped, while third-party
// processes pass through. Unlike a pure path match, the hash gate means a
// swapped imposter at the same path is detected (see TestIsSelfChildImposter).
func TestIsSelfChild(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel.exe")
	if err := os.WriteFile(sentinel, []byte("legit sentinel binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &sysmonRT{parents: newSelfParentsForTest(t, sentinel)}

	cases := []struct {
		name string
		ev   event.Event
		want bool
	}{
		{
			name: "powershell child of sentinel (the poller) - filtered",
			ev: event.Event{
				EID:         1,
				Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				ParentImage: sentinel,
			},
			want: true,
		},
		{
			name: "third-party process (attacker) - kept",
			ev: event.Event{
				EID:         1,
				Image:       filepath.Join(dir, "evil.exe"),
				ParentImage: `C:\Windows\explorer.exe`,
			},
			want: false,
		},
		{
			name: "powershell NOT spawned by sentinel - kept",
			ev: event.Event{
				EID:         1,
				Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				ParentImage: filepath.Join(dir, "dropper.exe"),
			},
			want: false,
		},
		{
			name: "network event from sentinel's child - kept (gate is EID 1 only)",
			ev:   event.Event{EID: 3, ParentImage: sentinel},
			want: false,
		},
		{
			name: "parent path in mixed case / forward-slash form - still matched",
			ev: event.Event{
				EID:         1,
				Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				ParentImage: filepath.ToSlash(uppercaseFirst(sentinel)),
			},
			want: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.isSelfChild(c.ev); got != c.want {
				t.Errorf("isSelfChild = %v, want %v", got, c.want)
			}
		})
	}
}

// uppercaseFirst returns s with its first byte ASCII-uppercased, for the
// mixed-case path-matching case.
func uppercaseFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 32
	}
	return string(b)
}

// TestIsSelfChildImposter: after the startup hash is recorded, overwriting the
// binary at the same path with different content MUST make matches() return
// false (detected), not silenced. This is the whole point of hash-gating over a
// pure path match — our install dir is user-writable.
func TestIsSelfChildImposter(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sentinel-tray.exe")
	if err := os.WriteFile(target, []byte("legit tray binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	sp := newSelfParentsForTest(t, target)
	base := time.Now()

	// Legit binary, cold verify -> silenced.
	if !sp.matches(target, base) {
		t.Fatal("legit binary must match (be silenced) on cold verify")
	}
	// Swap in an imposter at the same path. Cold verify (cache expired by
	// advancing now past selfRecheck) must now detect it -> NOT silenced.
	if err := os.WriteFile(target, []byte("IMPOSTER payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if sp.matches(target, base.Add(selfRecheck+time.Second)) {
		t.Error("swapped imposter at same path must NOT match (must be detected)")
	}
}

// TestIsSelfChildDisabledWhenEmpty: an empty/nil selfParents must be a no-op
// (never silence), e.g. when os.Executable() failed or no sibling was readable.
func TestIsSelfChildDisabledWhenEmpty(t *testing.T) {
	s := &sysmonRT{parents: nil}
	ev := event.Event{EID: 1, ParentImage: `C:\Users\user01\sentinel.exe`}
	if s.isSelfChild(ev) {
		t.Error("nil selfParents must not silence anything")
	}
	s.parents = &selfParents{want: map[string]string{}, ok: map[string]time.Time{}}
	if s.isSelfChild(ev) {
		t.Error("empty selfParents must not silence anything")
	}
}
