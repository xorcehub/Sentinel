//go:build !windows

// Package sigverify provides Authenticode signature verification for the
// allowlist's Tier-2 (hash-gated) trust. On non-Windows (Linux dev/CI) there is
// no WinVerifyTrust, so verification is a no-op that fails closed: Tier-2 paths
// never auto-trust off-Windows. Production runs on Windows; this stub keeps the
// package compilable for cross-platform dev and the go test ./... CI gate.
package sigverify

// IsSignedBy always returns false on non-Windows (no Tier-2 signature trust).
func IsSignedBy(path string, allowedSigners []string) bool { return false }

// VerifyAndHash is the pinned verify+hash primitive; non-Windows fails closed.
func VerifyAndHash(path string, allowedSigners []string) (bool, string) { return false, "" }

// Subjects returns no subjects on non-Windows.
func Subjects(path string) ([]string, bool) { return nil, false }
