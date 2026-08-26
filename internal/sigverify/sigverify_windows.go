//go:build windows

// Package sigverify answers one question for the allowlist's Tier-2 (hash-gated)
// trust: is this on-disk PE validly Authenticode-signed by a vendor we pinned?
//
// It uses the native WinVerifyTrust + CryptQueryObject + CertGetNameString APIs
// (all via golang.org/x/sys/windows — no hand-rolled structs). The x/sys test
// suite (syscall_windows_test.go, TestWinVerifyTrust) is the reference for the
// WinVerifyTrustEx struct-filling sequence; this mirrors it exactly.
//
// Why signature verification exists at all (Bypass B closure): the allowlist's
// per-user install patterns (e.g. ^[a-z]:\users\[^\\]+\...\cursor\...) wildcard
// the username by design — any user's real Cursor install must match — which
// also lets malware running AS the user plant Cursor\evil.exe and match the
// path. Path anchoring cannot close this; only provenance can. Tier-2 trust
// therefore requires path match AND signature-by-an-allowed-vendor, cached by
// SHA256 (in the allowlist) so a legit auto-update (same vendor, new hash)
// re-verifies once and is re-trusted with zero operator action.
//
// Fail-closed by construction: an unsigned/wrong-signer plant is never trusted,
// whether it runs before or after legit Cursor (no learn-on-first-seen race).
package sigverify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// VerifyAndHash is the TOCTOU-hardened Tier-2 primitive: it verifies
// Authenticode provenance AND hashes the file under a SINGLE pinning open, so
// the bytes that winverify judged are provably the bytes being hashed.
//
// The pin: the file is opened with FILE_SHARE_READ only (no write/delete
// sharing). Windows blocks renames, replaces, deletes, and content writes for
// as long as the handle is open, so an attacker's swap loop cannot change what
// any step observes — the swap-to-signed-during-verify attack against the
// separate-open flow (verify-by-name, then re-hash-by-name) cannot land here.
//
// Returns (subject matches allowedSigners, lowercase hex SHA256 of the pinned
// bytes). On any error: (false, "") — fail closed.
func VerifyAndHash(path string, allowedSigners []string) (bool, string) {
	if len(allowedSigners) == 0 || path == "" {
		return false, ""
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, ""
	}
	// GENERIC_READ + FILE_SHARE_READ: concurrent readers fine; writers and
	// renamers get a sharing violation until we're done. This is the lock that
	// makes every observation below see one immutable set of bytes.
	h, err := windows.CreateFile(
		path16,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return false, ""
	}
	// os.NewFile takes ownership of the handle (its Close closes it) and gives us
	// stdlib hashing for free.
	file := os.NewFile(uintptr(h), path)
	if file == nil {
		windows.CloseHandle(h)
		return false, ""
	}
	defer file.Close()

	h256 := sha256.New()
	if _, err := io.Copy(h256, file); err != nil {
		return false, ""
	}
	sha := hex.EncodeToString(h256.Sum(nil))

	if !isValidlySignedHandle(path, h) {
		return false, sha
	}
	store, ok := openCertStore(path) // by-name safe: rename blocked by the pin
	if !ok {
		return false, sha
	}
	defer windows.CertCloseStore(store, 0)
	subjects, ok := leafSubjects(store)
	if !ok {
		return false, sha
	}
	set := make(map[string]bool, len(allowedSigners))
	for _, s := range allowedSigners {
		set[strings.ToLower(strings.TrimSpace(s))] = true
	}
	for _, s := range subjects {
		if set[strings.ToLower(strings.TrimSpace(s))] {
			return true, sha
		}
	}
	return false, sha
}

// IsSignedBy reports whether path is a validly Authenticode-signed PE whose
// signing (leaf) cert's subject — simple-display name — matches one of
// allowedSigners (case-insensitive, trimmed).
//
// Two-stage: (1) WinVerifyTrustEx confirms the signature is valid and chains to
// a trusted root; (2) a signer-subject match pins provenance so a binary signed
// by a DIFFERENT vendor (or a renamed/repurposed one) is rejected.
//
// allowedSigners must contain dev-tool VENDOR names only — never a vendor that
// also signs dangerous LOLBins (e.g. "Microsoft Corporation", which signs
// mshta/certutil). Otherwise a planted, renamed LOLBin would match the signer
// set and reopen the mimicry hole this exists to close. Empty allowedSigners
// returns false (fail closed).
func IsSignedBy(path string, allowedSigners []string) bool {
	if len(allowedSigners) == 0 {
		return false
	}
	subjects, ok := Subjects(path)
	if !ok {
		return false
	}
	set := make(map[string]bool, len(allowedSigners))
	for _, s := range allowedSigners {
		set[strings.ToLower(strings.TrimSpace(s))] = true
	}
	for _, s := range subjects {
		if set[strings.ToLower(strings.TrimSpace(s))] {
			return true
		}
	}
	return false
}

// Subjects returns the simple-display subject name(s) of the SIGNING cert(s) of
// path — the leaf/leaves of the embedded PKCS7 trust graph, NOT any
// intermediate/root CA cert in its chain.
//
// Why signer-only (not all certs in the store): the store from CryptQueryObject
// holds the signer leaf PLUS every intermediate/root CA (and, for some files, a
// timestamp responder). Returning all of them would make allowed_signers a
// footgun — adding a plausible CA name (e.g. "Microsoft Identity Verification
// Root...") would match EVERY signed binary on the box and silently grant total
// Tier-2 trust. By returning only DAG leaves (certs whose Subject is not the
// Issuer of any other cert in this store), a CA name in allowed_signers matches
// nothing: the config cannot footgun itself. This is the mechanism-level fix for
// that bypass class; no denylist test is needed because no CA/intermediate can
// ever be returned.
//
// Implementation: DAG-leaf detection over a plain store enumeration. We tried
// CryptMsgGetParam(CMSG_SIGNER_CERT_INFO_PARAM) + CertFindCertificateInStore
// (CERT_FIND_SUBJECT_CERT) but that call spins indefinitely on real binaries
// (the copied CERT_INFO's internal blob pointers reference the message buffer
// and the content-match never resolves). DAG-leaf detection has no such failure
// mode and is structurally correct: in a PKCS7 signature the signer is always a
// leaf of the embedded trust graph.
//
// Residual: a timestamp responder (a separate leaf, present in some signatures)
// can also be returned, since it too is a DAG leaf. This is benign — a timestamp
// responder is never a dev-tool vendor name, so it never matches allowed_signers
// and never grants trust; it only appears in Subjects()'s discovery output.
//
// Exposed so the operator can discover the real signer string to put in
// allowed_signers, and so tests assert provenance against real on-disk binaries.
func Subjects(path string) ([]string, bool) {
	if !isValidlySigned(path) {
		return nil, false
	}
	store, ok := openCertStore(path)
	if !ok {
		return nil, false
	}
	defer windows.CertCloseStore(store, 0)
	return leafSubjects(store)
}

// leafSubjects runs the DAG-leaf signer extraction over an OPENED cert store.
// Split from Subjects so VerifyAndHash can reuse it.
func leafSubjects(store windows.Handle) ([]string, bool) {
	// First pass: gather every cert's (subject, issuer) raw name blobs and the
	// human-readable subject name. CertEnumCertificatesInStore frees the previous
	// context when called again with it, and frees the final context on the
	// NULL-returning call that ends the loop, so we must NOT
	// CertFreeCertificateContext these — just hold prev and advance. The name
	// blobs reference the cert context's memory, which is freed by the next call,
	// so nameBlobBytes copies them out.
	type cert struct {
		subject []byte
		issuer  []byte
		name    string
	}
	var all []cert
	var prev *windows.CertContext
	for {
		ctx, _ := windows.CertEnumCertificatesInStore(store, prev)
		if ctx == nil {
			break
		}
		prev = ctx
		info := ctx.CertInfo
		if info == nil {
			continue
		}
		all = append(all, cert{
			subject: nameBlobBytes(info.Subject),
			issuer:  nameBlobBytes(info.Issuer),
			name:    subjectName(ctx),
		})
	}
	if len(all) == 0 {
		return nil, false
	}
	// A cert is a LEAF (signer candidate) if its Subject is not any other cert's
	// Issuer — i.e. it issues nothing in this store. Roots and intermediates are
	// excluded because their Subject IS some other cert's Issuer. O(n^2) on a
	// store that holds <8 certs in practice.
	isLeaf := func(i int) bool {
		for j, other := range all {
			if i == j {
				continue
			}
			if bytes.Equal(all[i].subject, other.issuer) {
				return false
			}
		}
		return true
	}
	var out []string
	seen := map[string]bool{}
	for i, c := range all {
		if isLeaf(i) && c.name != "" && !seen[c.name] {
			seen[c.name] = true
			out = append(out, c.name)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// nameBlobBytes copies the encoded name (DER) out of a CertNameBlob from a
// CERT_INFO. The blob's Data pointer references the cert context's memory, which
// is freed by the next CertEnumCertificatesInStore call, so callers must copy
// before advancing. Empty/nil-safe.
func nameBlobBytes(b windows.CertNameBlob) []byte {
	if b.Size == 0 || b.Data == nil {
		return nil
	}
	out := make([]byte, b.Size)
	copy(out, unsafe.Slice(b.Data, b.Size))
	return out
}

// isValidlySigned verifies by path (unpinned — used for discovery/tests).
func isValidlySigned(path string) bool { return isValidlySignedHandle(path, 0) }

// isValidlySignedHandle runs WinVerifyTrustEx with no UI and no revocation
// check. A nonzero h pins the verified bytes to the caller's open handle
// (WinTrustFileInfo.File) so the verdict applies to exactly the bytes the
// caller hashed. No revocation: the daemon runs as an offline scheduled task
// and must not fail closed when the network/CRL is unreachable; revocation is
// not the trust signal relied on here (vendor pinning is). Mirrors
// TestWinVerifyTrust exactly, including the mandatory VERIFY→CLOSE pairing
// (close runs even on failure to free state — see WinVerifyTrust docs).
func isValidlySignedHandle(path string, h windows.Handle) bool {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	data := &windows.WinTrustData{
		Size:             uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_NONE,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: path16,
			File:     h,
		}),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return verifyErr == nil
}

// openCertStore opens the embedded certificate store of path via CryptQueryObject.
// Only the certStore out-param is requested (msg/context left NULL) — DAG-leaf
// detection works on the store handle alone, so the message handle is neither
// needed nor leaked. Accepts both signed PKCS7 content types; validity is gated
// upstream by isValidlySigned.
func openCertStore(path string) (windows.Handle, bool) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	const signedFlags = windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED
	var store windows.Handle
	if err := windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(path16),
		signedFlags,
		windows.CERT_QUERY_FORMAT_FLAG_ALL,
		0,
		nil, nil, nil,
		&store,
		nil, nil,
	); err != nil {
		return 0, false
	}
	return store, true
}

// subjectName returns the CERT_NAME_SIMPLE_DISPLAY_TYPE subject string of ctx
// (e.g. "Anysphere, Inc."). SIMPLE_DISPLAY_TYPE collapses to the most specific
// RDN attribute (CN) for typical vendor certs.
func subjectName(ctx *windows.CertContext) string {
	var buf [1024]uint16
	n := windows.CertGetNameString(ctx, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &buf[0], uint32(len(buf)))
	if n <= 1 { // 0 = error, 1 = empty (lone terminator)
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// Pinned is the allowlist-injectable adapter (allowlist.PinnedVerifier) that
// routes Tier-2 verification through VerifyAndHash: ONE open handle held for
// the whole verify+hash, blocking rename/replace/content-write for the
// duration and closing the by-name reopen swap window.
type Pinned struct{}

// VerifyAndHash implements allowlist.PinnedVerifier.
func (Pinned) VerifyAndHash(path string, allowedSigners []string) (bool, string) {
	return VerifyAndHash(path, allowedSigners)
}
