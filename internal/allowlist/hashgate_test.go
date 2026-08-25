package allowlist

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"sentinel/internal/event"
)

// hashGateJSONC is a minimal allowlist exercising BOTH tiers. The Tier-2
// (hash_gated_path) gate here is a fixed Windows-shaped Cursor path; tests that
// need a gate matching a t.TempDir() override a.tbHashGated directly (same
// package) to avoid backslash-counting in JSONC.
const hashGateJSONC = `{
  "trusted_binaries": {
    "path": [
      "\\\\windows\\\\system32\\\\.*\\.exe$"
    ],
    "hash_gated_path": [
      "\\\\users\\\\[^\\\\]+\\\\appdata\\\\local\\\\programs\\\\cursor\\\\.*\\.exe$"
    ],
    "allowed_signers": ["Anysphere, Inc."]
  }
}`

// gateRegexForTempDir compiles a Tier-2 gate regex matching files at
// <dir>\<sub>\<name>.exe against NormalizePath's lowercased backslash form.
// Compiled in Go (not JSONC) to avoid backslash-counting hell.
func gateRegexForTempDir(t *testing.T, dir string) *regexp.Regexp {
	t.Helper()
	normDir := strings.ToLower(strings.ReplaceAll(dir, "/", "\\"))
	re, err := regexp.Compile("(?i)^" + regexp.QuoteMeta(normDir) + `\\[^\\]+\\[^\\]+\.exe$`)
	if err != nil {
		t.Fatalf("compile gate: %v", err)
	}
	return re
}

// compileWithTempGate returns an Allowlist loaded from hashGateJSONC but with
// its Tier-2 gate overridden to match a tempdir, plus a fake verifier that
// returns true only for legitPath. legitPath + plantPath files are created.
// Returns the allowlist, the real SHA256 of each file, and the verify-call
// counter. This is the shared setup for the Tier-2 fake-verifier tests.
func compileWithTempGate(t *testing.T) (a *Allowlist, legitPath, plantPath, legitSHA, plantSHA string, calls *int64) {
	t.Helper()
	dir := t.TempDir()
	legitPath = filepath.Join(dir, "cursor", "Cursor.exe")
	plantPath = filepath.Join(dir, "cursor", "evil.exe")
	if err := os.MkdirAll(filepath.Dir(legitPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(legitPath, []byte("legit-bytes"), 0o600); err != nil {
		t.Fatalf("write legit: %v", err)
	}
	if err := os.WriteFile(plantPath, []byte("plant-bytes"), 0o600); err != nil {
		t.Fatalf("write plant: %v", err)
	}
	var ls, ps string
	var lerr, perr error
	if ls, lerr = hashFile(legitPath); lerr != nil {
		t.Fatalf("hash legit: %v", lerr)
	}
	if ps, perr = hashFile(plantPath); perr != nil {
		t.Fatalf("hash plant: %v", perr)
	}
	a, err := Compile([]byte(hashGateJSONC))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	a.tbHashGated = []*regexp.Regexp{gateRegexForTempDir(t, dir)} // override gate
	var c int64
	a.SetSigVerifier(func(imagePath string, allowedSigners []string) bool {
		atomic.AddInt64(&c, 1)
		return imagePath == legitPath // "signed by Anysphere" only for the legit path
	})
	return a, legitPath, plantPath, ls, ps, &c
}

// TestTier2HashGateClosesBypassB is the regression for per-user-profile mimicry
// (Bypass B): a planted evil.exe matches the wildcarded user path, so path
// anchoring cannot distinguish it from a real Cursor install. Tier-2 requires
// path match AND signature; this pins all four cases plus cache behavior.
func TestTier2HashGateClosesBypassB(t *testing.T) {
	a, legitPath, plantPath, legitSHA, plantSHA, calls := compileWithTempGate(t)

	cases := []struct {
		name  string
		image string
		sha   string // empty = no SHA256 on event
		want  bool
	}{
		{"legit Cursor (signed by allowed vendor)", legitPath, legitSHA, true},
		{"planted evil.exe (same path, not signed)", plantPath, plantSHA, false}, // <- the bypass B case
		{"legit Cursor but no SHA256 on event", legitPath, "", false},            // fail closed: can't cache/verify
		{"planted evil.exe, no SHA256", plantPath, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := &event.Event{Image: c.image}
			if c.sha != "" {
				ev.Hashes = map[string]string{"SHA256": c.sha}
			}
			if got := a.ImageTrusted(ev); got != c.want {
				t.Errorf("ImageTrusted(%q)=%v want %v", c.image, got, c.want)
			}
		})
	}

	// The signed binary must hit the cache (no re-verify). The unsigned plant
	// deliberately does NOT: negative verify results are never cached so a
	// transient failure (AV lock) self-heals on the next sighting instead of
	// poisoning trust until restart.
	firstCalls := atomic.LoadInt64(calls)
	for i := 0; i < 10; i++ {
		a.ImageTrusted(&event.Event{Image: legitPath, Hashes: map[string]string{"SHA256": legitSHA}})
		a.ImageTrusted(&event.Event{Image: plantPath, Hashes: map[string]string{"SHA256": plantSHA}})
	}
	if got := atomic.LoadInt64(calls); got != firstCalls+10 {
		t.Errorf("legit should hit cache; unsigned plant should re-verify each sighting: before=%d after=%d", firstCalls, got)
	}
}

// TestTier2WithoutVerifierFailsClosed asserts the safe default: if no verifier
// is injected (non-Windows, or sigverify unavailable), Tier-2 paths never
// auto-trust. This matches the pre-Tier-2 posture exactly, so it is a clean
// fail-closed, not a regression.
func TestTier2WithoutVerifierFailsClosed(t *testing.T) {
	a, err := Compile([]byte(hashGateJSONC))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// No SetSigVerifier call: sigVerify is nil.
	ev := &event.Event{
		Image:  `C:\Users\alice\AppData\Local\Programs\Cursor\Cursor.exe`,
		Hashes: map[string]string{"SHA256": "whatever"},
	}
	if a.ImageTrusted(ev) {
		t.Error("Tier-2 path must NOT trust without an injected verifier (fail closed)")
	}
}

// TestTier2WrongVendorRejected: even with a verifier wired, a binary signed by a
// vendor NOT in allowed_signers is rejected (provenance pinning, not just "any
// valid signature").
func TestTier2WrongVendorRejected(t *testing.T) {
	a, err := Compile([]byte(hashGateJSONC))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	a.SetSigVerifier(func(imagePath string, allowedSigners []string) bool {
		return false // verifier says "not signed by an allowed vendor"
	})
	ev := &event.Event{
		Image:  `C:\Users\alice\AppData\Local\Programs\Cursor\Cursor.exe`,
		Hashes: map[string]string{"SHA256": "h"},
	}
	if a.ImageTrusted(ev) {
		t.Error("binary signed by a non-allowed vendor must NOT be trusted")
	}
}

// TestTier2CacheConcurrent sanity-checks the RWMutex-guarded cache under
// concurrency: many goroutines hitting the same first-sight miss must not race
// (no panic, no double-verify explosion). go test -race covers the data-race side.
func TestTier2CacheConcurrent(t *testing.T) {
	dir := t.TempDir()
	legitPath := filepath.Join(dir, "cursor", "Cursor.exe")
	if err := os.MkdirAll(filepath.Dir(legitPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(legitPath, []byte("shared-bytes"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	legitSHA, _ := hashFile(legitPath)
	a, err := Compile([]byte(hashGateJSONC))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	a.tbHashGated = []*regexp.Regexp{gateRegexForTempDir(t, dir)}

	var verifyCalls int64
	a.SetSigVerifier(func(imagePath string, allowedSigners []string) bool {
		atomic.AddInt64(&verifyCalls, 1)
		return imagePath == legitPath
	})
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ev := &event.Event{Image: legitPath, Hashes: map[string]string{"SHA256": legitSHA}}
			if !a.ImageTrusted(ev) {
				t.Errorf("concurrent legit Cursor should be trusted")
			}
		}()
	}
	wg.Wait()
	// With one shared hash, verify should run at most a handful of times (cache
	// races may let a few through), NOT goroutines times.
	if n := atomic.LoadInt64(&verifyCalls); n >= goroutines {
		t.Errorf("cache should bound verify calls; got %d (>= %d goroutines)", n, goroutines)
	}
}

// TestTier2TOCTOUGuardBlocksCachePoisoning is the regression for the cache-
// poisoning race found in review: the cache key is Sysmon's event-time SHA256,
// but winverify reads the file at verify time. Without the re-hash guard, an
// attacker could swap a planted malware file to genuine signed bytes inside the
// verify window, letting winverify pass and poison cache[malware-hash]=true.
//
// The guard: on a passing verify, re-hash the file; cache true ONLY if that hash
// equals the event-time sha. This test simulates the attack by giving the event
// a SHA256 that does NOT match the on-disk file's real hash (the "swap" left the
// event-time bytes different from the verify-time bytes). The verifier PASSES
// (good bytes), but the guard must still reject and NOT cache true, so a replay
// stays untrusted. Contrast: the real hash DOES trust.
func TestTier2TOCTOUGuardBlocksCachePoisoning(t *testing.T) {
	dir := t.TempDir()
	legitPath := filepath.Join(dir, "cursor", "Cursor.exe")
	if err := os.MkdirAll(filepath.Dir(legitPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(legitPath, []byte("these-are-the-on-disk-bytes"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	realSHA, _ := hashFile(legitPath)
	attackerEventSHA := "deadbeef" + realSHA // intentionally != realSHA (the malware's hash, pre-swap)

	a, err := Compile([]byte(hashGateJSONC))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	a.tbHashGated = []*regexp.Regexp{gateRegexForTempDir(t, dir)}
	// Verifier PASSES unconditionally (simulating: winverify read genuine signed
	// bytes during the swap window). The guard must override when hashes disagree.
	a.SetSigVerifier(func(imagePath string, allowedSigners []string) bool { return true })

	// Attack: event carries the MALWARE hash; on-disk file is the swapped good
	// bytes (verifier passes); guard must NOT cache true and must return false.
	ev := &event.Event{Image: legitPath, Hashes: map[string]string{"SHA256": attackerEventSHA}}
	if a.ImageTrusted(ev) {
		t.Fatal("TOCTOU: verify-pass-with-mismatched-hash must NOT be trusted (cache poisoning)")
	}
	// Replay proves no poison: the attacker's hash is not cached true.
	if a.ImageTrusted(ev) {
		t.Fatal("TOCTOU: attacker hash must not have been cached true (replay still trusted)")
	}

	// Contrast: the REAL on-disk hash DOES trust (guard allows when hashes match).
	good := &event.Event{Image: legitPath, Hashes: map[string]string{"SHA256": realSHA}}
	if !a.ImageTrusted(good) {
		t.Error("matching hash + passing verify should be trusted (guard must not over-reject)")
	}
}
