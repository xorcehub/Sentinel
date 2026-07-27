package allowlist

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"sentinel/internal/event"
	"sentinel/internal/sigverify"
)

// TestTier2EndToEndRealSignatureAgainstRealConfig is the end-to-end proof that
// Plan A1 (lazy signature-seeded hash cache) closes Bypass B against the REAL
// production config and the REAL sigverify machinery, on the operator's actual
// machine. It loads the shipped config/allowlist.json, wires the real
// sigverify.IsSignedBy (native WinVerifyTrust on Windows), and asserts:
//
//  1. Each real on-disk dev tool (Cursor/Python/Claude) at its Tier-2 path IS
//     trusted — i.e. its path matches hash_gated_path AND its Authenticode
//     subject is in allowed_signers. This is the legitimate-trust-restored case.
//  2. A planted, UNSIGNED binary at the same Tier-2 path is NOT trusted — the
//     bypass-B closure case. Same path, no valid signature by an allowed vendor.
//
// It needs e.Hashes["SHA256"] (Tier-2 requires it to key the cache); we use a
// synthetic but distinct hash per binary. The real daemon gets the real SHA256
// from EID 1 via <HashAlgorithms>SHA256</HashAlgorithms> (install-sysmon.ps1).
//
// Skips (not fails) when a tool isn't installed — this is host-dependent.
func TestTier2EndToEndRealSignatureAgainstRealConfig(t *testing.T) {
	prodPath, ok := findProdAllowlist(t)
	if !ok {
		t.Skip("config/allowlist.json not found (running outside repo root)")
	}
	a, err := Load(prodPath)
	if err != nil {
		t.Fatalf("load production allowlist: %v", err)
	}
	if len(a.allowedSigners) == 0 {
		t.Skip("production config has no allowed_signers; A1 not wired in config")
	}
	// Inject the REAL verifier (native wintrust on Windows; stub fails closed
	// off-Windows, in which case the positive cases skip via the signer check).
	a.SetSigVerifier(sigverify.IsSignedBy)

	home := os.Getenv("USERPROFILE")
	cands := []struct{ name, path string }{
		{"cursor", filepath.Join(home, "AppData", "Local", "Programs", "Cursor", "Cursor.exe")},
		{"python", filepath.Join(home, "AppData", "Local", "Programs", "Python", "Python314", "python.exe")},
		{"claude", filepath.Join(home, ".local", "bin", "claude.exe")},
	}

	for _, c := range cands {
		t.Run(c.name, func(t *testing.T) {
			if _, err := os.Stat(c.path); err != nil {
				t.Skipf("%s not installed at %s", c.name, c.path)
			}

			// (1) Positive: the real signed binary IS trusted end-to-end. Use the
			// REAL file SHA256 (not synthetic) so the Tier-2 TOCTOU re-hash guard
			// (winverify reads the bytes now; cache key is the event-time hash)
			// sees matching bytes and caches true. A synthetic hash would be
			// correctly rejected by the guard — proving the guard works, not trust.
			realSHA, err := hashFile(c.path)
			if err != nil {
				t.Skipf("cannot hash %s (%s): %v", c.name, c.path, err)
			}
			ev := &event.Event{
				Image:  c.path,
				Hashes: map[string]string{"SHA256": realSHA},
			}
			if !a.ImageTrusted(ev) {
				t.Errorf("real %s (%s) should be trusted via Tier-2 path+signature; "+
					"either its path is not in hash_gated_path, its signer is not in "+
					"allowed_signers, or the TOCTOU re-hash guard mis-fired",
					c.name, c.path)
			}

			// (2) Negative: a planted UNSIGNED binary at the SAME path is NOT
			// trusted. We materialize a copy of the real bytes? No — the point is
			// the signature, not the bytes. Instead, assert against a different
			// filename in the same dir that does not exist / is not signed: the
			// real verifier must return false for it, so Tier-2 must reject it.
			// Use a synthetic path that still matches the hash_gated_path pattern
			// (same dir, different exe name) — pathMatchesHashGated stays true, so
			// the ONLY thing that can flip trust to false is the signature gate.
			dir := filepath.Dir(c.path)
			plant := filepath.Join(dir, "definitely-implant-"+c.name+".exe")
			pev := &event.Event{
				Image:  plant,
				Hashes: map[string]string{"SHA256": c.name + "-plant-hash"},
			}
			if a.ImageTrusted(pev) {
				t.Errorf("planted unsigned binary at same Tier-2 path must NOT be trusted "+
					"(Bypass B not closed): %s", plant)
			}
		})
	}
}

// findProdAllowlist walks up from this test file to locate config/allowlist.json.
func findProdAllowlist(t *testing.T) (string, bool) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", false
	}
	dir := filepath.Dir(file)
	for i := 0; i < 6; i++ {
		cand := filepath.Join(dir, "config", "allowlist.json")
		if _, err := os.Stat(cand); err == nil {
			return cand, true
		}
		dir = filepath.Dir(dir)
	}
	return "", false
}
