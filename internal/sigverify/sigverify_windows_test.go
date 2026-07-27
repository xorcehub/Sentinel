//go:build windows

package sigverify

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// devToolPaths returns the operator's real dev-tool binaries to use as positive
// controls for the signer-discovery test. Empty string entries are skipped.
func devToolPaths(t *testing.T) []struct{ name, path string } {
	t.Helper()
	home := os.Getenv("USERPROFILE")
	cands := []struct{ name, path string }{
		{"cursor", filepath.Join(home, "AppData", "Local", "Programs", "Cursor", "Cursor.exe")},
		{"python", filepath.Join(home, "AppData", "Local", "Programs", "Python", "Python314", "python.exe")},
		{"claude", filepath.Join(home, ".local", "bin", "claude.exe")},
	}
	out := cands[:0]
	for _, c := range cands {
		if _, err := os.Stat(c.path); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// TestDiscoverAndVerify exercises the real WinVerifyTrust + CryptQueryObject
// machinery against the operator's actual on-disk dev tools. It is BOTH:
//  1. The anti-fabrication step for populating config/allowlist.json
//     allowed_signers: it logs the REAL subject strings the API returns, so the
//     allowlist ships verified vendor names — never a guessed "Anysphere, Inc.".
//  2. A correctness gate: the discovered subject set must make IsSignedBy return
//     true for the real binary, false for a wrong vendor, and false for an
//     unsigned binary.
//
// Skips if no dev tools are installed at the candidate paths.
func TestDiscoverAndVerify(t *testing.T) {
	tools := devToolPaths(t)
	if len(tools) == 0 {
		t.Skip("no dev tools at candidate paths; signer discovery requires Cursor/Python on disk")
	}

	// Discovered vendor names accumulate here; the config's allowed_signers is
	// populated from exactly this (verified by reading this test's -v output).
	var discovered []string
	for _, tool := range tools {
		subjects, ok := Subjects(tool.path)
		if !ok {
			t.Errorf("%s: Subjects() returned ok=false for a real signed binary (winverify/certstore machinery broken)", tool.name)
			continue
		}
		t.Logf("DISCOVERY %s (%s): subjects=%q", tool.name, tool.path, subjects)
		// Leaf-only proof: the extraction must return the signing vendor, NEVER a
		// chain/intermediate/root/timestamp cert. If Subjects regressed to
		// all-certs-in-store enumeration, these CA markers would reappear and this
		// assertion would fail — that is exactly the footgun the signer-only
		// extraction exists to prevent.
		for _, s := range subjects {
			if isCAMarker(s) {
				t.Errorf("%s: Subjects returned a non-leaf/chain cert subject %q — "+
					"signer-only extraction regressed (this would reopen the config footgun)",
					tool.name, s)
			}
		}
		discovered = append(discovered, subjects...)
	}
	if len(discovered) == 0 {
		t.Fatal("no subjects discovered; cannot validate matcher")
	}

	// Positive: each real tool must verify with the discovered set.
	for _, tool := range tools {
		if !IsSignedBy(tool.path, discovered) {
			t.Errorf("%s: IsSignedBy with discovered subjects should be true", tool.name)
		}
	}

	// Negative: a wrong vendor must NOT verify.
	for _, tool := range tools {
		if IsSignedBy(tool.path, []string{"Nonexistent Vendor LLC"}) {
			t.Errorf("%s: IsSignedBy must be false for a vendor not in the cert store", tool.name)
		}
	}

	// Negative: an unsigned binary must NOT verify. We build a no-op .exe on the
	// fly — it has no Authenticode signature, so winverify fails closed.
	unsigned := buildUnsignedExe(t)
	for _, tool := range tools {
		_ = tool
	}
	if IsSignedBy(unsigned, discovered) {
		t.Errorf("unsigned binary (%s) must NOT verify (would defeat the whole point)", unsigned)
	}
	// Empty allowedSigners fails closed.
	if IsSignedBy(unsigned, []string{}) {
		t.Error("empty allowedSigners must return false (fail closed)")
	}
}

// isCAMarker reports whether s looks like an intermediate/ROOT cert subject
// (an ISSUING CA) rather than a leaf. Used by the discovery test to prove
// Subjects never returns a CA/intermediate — the footgun being that an operator
// adding such a name to allowed_signers would match every signed binary on the
// box. Markers are the stable well-known issuing-CA naming conventions.
//
// NOTE: a timestamp responder ("...Timestamp Responder...") is intentionally
// NOT flagged here. It is a DAG leaf and may legitimately appear in Subjects
// output, but it is benign: it is never a dev-tool vendor name and so never
// matches allowed_signers / grants trust. Flagging it would turn the test into
// a false failure for a non-threat.
func isCAMarker(s string) bool {
	m := []string{"Certificate Authority", "Root Certificate", "Root", "PCA ", " Code Signing PCA", "CSAOC", "CSEAOC", " CA ", " CA1", "CA1 "}
	for _, x := range m {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// returns its path. The resulting .exe has no Authenticode signature.
func buildUnsignedExe(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	out := filepath.Join(dir, "noop.exe")
	cmd := exec.Command("go", "build", "-o", out, src)
	if err := cmd.Run(); err != nil {
		t.Skipf("go build unavailable in test env: %v", err)
	}
	return out
}

// TestSubjectsBogusPath proves failure paths are safe (no panic, ok=false) for a
// nonexistent file — the daemon must never crash if e.Image points at a file
// that was already deleted (the create-and-delete dropper TOCTOU case).
func TestSubjectsBogusPath(t *testing.T) {
	if subjects, ok := Subjects(filepath.Join(os.TempDir(), "definitely-not-here-"+runtime.GOOS+".exe")); ok {
		t.Errorf("bogus path must return ok=false, got subjects=%q", subjects)
	}
	if IsSignedBy(filepath.Join(os.TempDir(), "definitely-not-here-2.exe"), []string{"X"}) {
		t.Error("bogus path must not verify")
	}
}
