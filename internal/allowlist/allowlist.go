// Package allowlist loads config/allowlist.json and answers the subtractive
// `except` checks referenced by Sigma rules' x-sentinel.except block
// (docs/03-RULES.md §3, docs/04-TELEMETRY.md §2).
//
// Five sets, mapping 1:1 to the except operators:
//
//	image_in_allowlist: trusted_binaries   -> ImageTrusted(hash or path)
//	image_in_dev_tools: dev_tool_paths     -> ImageInDevTools(path)
//	cmdline_in_dev_scripts: dev_scripts    -> CmdLineInDevScripts(cmdline)
//	dst_in_allowlist: allowed_destinations -> DstInCIDR(ip)
//	dst_in_allowlist: known_loopback_listeners -> DstIsKnownLoopback(ip, port)
//
// trusted_binaries splits into two TIERS (see ImageTrusted):
//   - Tier-1 (`path`): admin-owned install dirs (system32, Program Files).
//     Planting there already requires admin = game over, so path match alone
//     suffices.
//   - Tier-2 (`hash_gated_path`): user-writable install dirs (per-user
//     AppData: Cursor, Python, ...). The username is wildcarded by design (any
//     user's real install must match), so malware running AS the user can plant
//     a same-path binary. Path match alone is NOT trust here: the binary must
//     ALSO be Authenticode-signed by an allowed_signers vendor (verified lazily
//     via internal/sigverify, cached by SHA256). Closes per-user-profile
//     mimicry ("Bypass B") with provenance rather than bytes.
//
// dev_scripts is the ONLY set anchored on the CommandLine rather than the
// Image. It exists for the dev-workflow EXEC-001 case: a developer running
// their OWN script as `powershell -ExecutionPolicy Bypass -File <dev.ps1>`.
// The Image is powershell.exe (a system binary), so image-based sets can't
// scope it without blinding EXEC-001 to every PS-bypass attack. Anchoring on
// the script in the commandline suppresses ONLY the named dev workflow while
// keeping EXEC-001 armed for everything else.
//
// Optional sixth section, event_log_filter, is NOT an `except` operator and is
// not consumed by the rule engine — it is a log-only noise filter read by the
// app layer. Each entry is an AND of its predicates (eid / image / cmdline); an
// event matching ANY entry suppresses ONLY the per-event DEBUG dump line. Rule
// evaluation is unaffected: real hits are logged on a separate "HIT" line and
// never depend on that dump. See IsLogNoise and the app layer's handleEvent.
//
// Optional seventh section, file_capture, is also not an `except` operator and
// is not consumed by the rule engine. It names path patterns whose created
// files (EID 11) the app layer snapshots to a forensic vault before they can
// be deleted — the create-and-delete dropper pattern (e.g. Cursor's
// Temp\ps-script-<guid>.ps1). Like event_log_filter it carries no detection
// decision: it can neither suppress nor produce a hit. See ShouldCapture.
//
// The allowlist file is JSONC (allows // comments), matching the docs' format.
// We strip comments before json.Unmarshal so the operator can annotate freely.
package allowlist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"

	"sentinel/internal/event"
	"sentinel/internal/pathnorm"
)

// SigVerifier is the signature-verification primitive injected by the app
// layer (internal/sigverify.IsSignedBy on Windows). It exists as an injected
// type so the allowlist policy + lazy cache are unit-testable without Windows,
// and so a nil verifier cleanly means "Tier-2 never auto-trusts" (fail closed).
// The implementation must be safe for concurrent use.
type SigVerifier func(imagePath string, allowedSigners []string) bool

// Allowlist is the compiled, read-optimized form. All methods are safe for
// concurrent use: the compiled structures (paths/cidrs/filters) are immutable
// after Compile; only the Tier-2 lazy verify cache (verified) is mutable, and it
// is guarded by mu. sigVerify is set once via SetSigVerifier before the first
// Evaluate and read-only thereafter.
type Allowlist struct {
	tbSHA          map[string]bool  // lowercased sha256 (Tier-1+2 authoritative)
	tbPath         []*regexp.Regexp // Tier-1 admin-owned path patterns, normalized lower path
	tbHashGated    []*regexp.Regexp // Tier-2 user-writable path patterns (path match NOT sufficient — see ImageTrusted)
	allowedSigners []string         // vendor subjects allowed for Tier-2 (dev-tool vendors only; never a LOLBin signer)
	devPath        []*regexp.Regexp
	devScript      []*regexp.Regexp // commandline anchors (dev scripts run via a LOLBin)
	cidrs          []*net.IPNet
	loopback       map[string]bool   // "host:port" lowercased
	logFilter      []*logFilterEntry // event_log_filter: suppresses the per-event DEBUG dump only
	capPatterns    []*regexp.Regexp  // file_capture: path patterns matched on EID 11/23 TargetFile

	sigVerify SigVerifier // injected; nil = Tier-2 never auto-trusts (fail closed)
	mu        sync.RWMutex
	verified  map[string]bool // Tier-2 lazy cache: lowercased sha256 -> sigVerify(path) result
	// ponytail: `verified` is unbounded. Ceiling = number of distinct SHA256s ever
	// seen at a Tier-2 path, which is tiny in practice (a handful of dev-tool
	// exes per box). It never grows from attacker traffic: an attacker plant at
	// a Tier-2 path adds at most one entry (its hash). Add an LRU/size cap only
	// if a box is observed to run many distinct signed dev-tool binaries.
}

// logFilterEntry is one AND-conjunction rule from the optional event_log_filter
// allowlist section. A zero/nil field means "match anything" (predicate
// omitted). IsLogNoise reports a match when every SET predicate agrees, so an
// entry like {eid:11, image:powershell, cmdline:"^$"} matches ONLY PowerShell
// FileCreate with an empty command line — a same-image event carrying a command
// fails the cmdline clause and is still logged.
type logFilterEntry struct {
	eid     int            // 0 = any EID
	image   *regexp.Regexp // nil = any image; matched on the normalized lower path
	cmdline *regexp.Regexp // nil = any cmdline; matched on the raw (un-normalized) cmdline
}

// Load reads and compiles a JSONC allowlist file.
func Load(path string) (*Allowlist, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist %s: %w", path, err)
	}
	return Compile(stripJSONC(raw))
}

// Compile parses already-read JSONC bytes (comments stripped by caller or via
// stripJSONC) into an Allowlist.
func Compile(jsonBytes []byte) (*Allowlist, error) {
	var doc rawDoc
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse allowlist json: %w", err)
	}
	a := &Allowlist{
		tbSHA:    map[string]bool{},
		loopback: map[string]bool{},
		verified: map[string]bool{},
	}
	for _, h := range doc.TrustedBinaries.SHA256 {
		a.tbSHA[strings.ToLower(strings.TrimSpace(h))] = true
	}
	for _, p := range doc.TrustedBinaries.Path {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("bad trusted_binaries path regex %q: %w", p, err)
		}
		a.tbPath = append(a.tbPath, re)
	}
	for _, p := range doc.TrustedBinaries.HashGatedPath {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("bad trusted_binaries.hash_gated_path regex %q: %w", p, err)
		}
		a.tbHashGated = append(a.tbHashGated, re)
	}
	for _, s := range doc.TrustedBinaries.AllowedSigners {
		if s = strings.TrimSpace(s); s != "" {
			a.allowedSigners = append(a.allowedSigners, s)
		}
	}
	for _, p := range doc.DevToolPaths.Path {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("bad dev_tool_paths regex %q: %w", p, err)
		}
		a.devPath = append(a.devPath, re)
	}
	for _, p := range doc.DevScripts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("bad dev_scripts regex %q: %w", p, err)
		}
		a.devScript = append(a.devScript, re)
	}
	for _, c := range doc.AllowedDestinations.CIDR {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("bad allowed_destinations cidr %q: %w", c, err)
		}
		a.cidrs = append(a.cidrs, n)
	}
	for _, e := range doc.KnownLoopbackListeners {
		a.loopback[strings.ToLower(strings.TrimSpace(e))] = true
	}
	for _, f := range doc.EventLogFilter {
		ent, err := compileFilter(f)
		if err != nil {
			return nil, err
		}
		a.logFilter = append(a.logFilter, ent)
	}
	for _, p := range doc.FileCapture.Patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("bad file_capture pattern %q: %w", p, err)
		}
		a.capPatterns = append(a.capPatterns, re)
	}
	return a, nil
}

// compileFilter compiles one event_log_filter entry. eid 0 and empty image/cmd
// are wildcards (left nil/0). An entry with NO predicate set is rejected: it
// would match every event and silently blank the per-event DEBUG dump. Regexes
// get the same case-insensitive prefix and normalized-path matching contract as
// trusted_binaries / dev_tool_paths.
func compileFilter(f filterRaw) (*logFilterEntry, error) {
	ent := &logFilterEntry{eid: f.EID}
	if img := strings.TrimSpace(f.Image); img != "" {
		re, err := regexp.Compile("(?i)" + img)
		if err != nil {
			return nil, fmt.Errorf("bad event_log_filter image regex %q: %w", img, err)
		}
		ent.image = re
	}
	if cmd := strings.TrimSpace(f.Cmdline); cmd != "" {
		re, err := regexp.Compile("(?i)" + cmd)
		if err != nil {
			return nil, fmt.Errorf("bad event_log_filter cmdline regex %q: %w", cmd, err)
		}
		ent.cmdline = re
	}
	if ent.eid == 0 && ent.image == nil && ent.cmdline == nil {
		return nil, fmt.Errorf("event_log_filter entry must set at least one of eid/image/cmdline (an all-wildcard entry would suppress every event's debug dump line)")
	}
	return ent, nil
}

// ImageTrusted reports whether the event's acting process is trusted. Trust is
// resolved in three tiers, first match wins:
//
//  1. Known-good SHA256 (operator-seeded tbSHA, or a cached Tier-2 verify) —
//     authoritative for any tier.
//  2. Tier-1 admin-owned path (system32, Program Files): path match alone is
//     trusted, because planting there requires admin (already game over).
//  3. Tier-2 user-writable path (per-user AppData: Cursor, Python, ...): path
//     match is NOT sufficient — the binary must ALSO be Authenticode-signed by
//     an allowed_signers vendor. The sigVerify result is cached by SHA256 so a
//     legit auto-update (same vendor, new hash) re-verifies once and is
//     re-trusted with zero operator action. Requires e.Hashes["SHA256"] (always
//     present on EID 1 when <HashAlgorithms>SHA256</HashAlgorithms> is set, per
//     install-sysmon.ps1); without it Tier-2 simply never auto-trusts (fail
//     closed = same posture as before this tier existed, no regression).
func (a *Allowlist) ImageTrusted(e *event.Event) bool {
	if a == nil {
		return false
	}
	sha := ""
	if e.Hashes != nil {
		if s, ok := e.Hashes["SHA256"]; ok && s != "" {
			sha = strings.ToLower(s)
		}
	}
	if sha != "" && a.tbSHA[sha] {
		return true
	}
	if a.pathMatchesTrusted(e.Image) { // Tier-1
		return true
	}
	// Tier-2: user-writable path -> require provenance (sig by allowed vendor).
	if sha != "" && a.pathMatchesHashGated(e.Image) && a.sigVerifiedCached(sha, e.Image) {
		return true
	}
	return false
}

// SetSigVerifier injects the Tier-2 signature verifier. Call once after Load,
// before the first Evaluate. nil (the default) means Tier-2 paths never
// auto-trust — safe (fail closed), just noisier for legit dev tools. The cache
// is guarded by mu; the verifier itself must be safe for concurrent use.
func (a *Allowlist) SetSigVerifier(v SigVerifier) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.sigVerify = v
	a.mu.Unlock()
}

// pathMatchesHashGated reports whether image's normalized path matches a Tier-2
// (user-writable) trusted path pattern. A match here is necessary but NOT
// sufficient for trust — the caller (ImageTrusted) additionally requires a
// passing signature verify.
func (a *Allowlist) pathMatchesHashGated(image string) bool {
	np := pathnorm.NormalizePath(image)
	for _, re := range a.tbHashGated {
		if re.MatchString(np) {
			return true
		}
	}
	return false
}

// sigVerifiedCached returns the Tier-2 signature result for sha, verifying
// on first sight (outside the read lock, so concurrent first-sight checks of
// different hashes don't serialize) and caching both positive and negative
// results by hash.
//
// TOCTOU guard (re-hash on success): the cache key is `sha` = Sysmon's
// e.Hashes["SHA256"] computed at EVENT time, but sigVerify reads the file at
// VERIFY time. Those are two separate observations of the bytes. Without a
// guard, an attacker could swap a planted malware file to genuine signed bytes
// inside the verify window, letting winverify pass on the good bytes and poison
// cache[sha-of-the-malware]=true. So on a PASSING verify we re-hash the file and
// only cache true if that hash == sha; a mismatch (bytes changed between event
// and verify) leaves the entry uncached and returns false (fail closed, and the
// next sighting re-verifies). A file deleted between event and verify likewise
// fails closed (hashFile errors -> no cache write -> false).
func (a *Allowlist) sigVerifiedCached(sha, imagePath string) bool {
	a.mu.RLock()
	if v, ok := a.verified[sha]; ok {
		a.mu.RUnlock()
		return v
	}
	vf := a.sigVerify
	a.mu.RUnlock()
	if vf == nil {
		return false
	}
	result := vf(imagePath, a.allowedSigners)
	// TOCTOU guard: a passing verify proves the CURRENT on-disk bytes are signed
	// by an allowed vendor, but `sha` was computed from the bytes at event time.
	// Only trust the verify if those are the same bytes: re-hash now and require a
	// match. Any divergence (swap-to-signed attack, file replaced mid-window) and
	// we do NOT cache true — return false so the caller fails closed.
	if result {
		if got, err := hashFile(imagePath); err != nil || got != sha {
			return false
		}
	}
	a.mu.Lock()
	// Re-check: another goroutine may have populated the same hash meanwhile.
	if v, ok := a.verified[sha]; ok {
		a.mu.Unlock()
		return v
	}
	a.verified[sha] = result
	a.mu.Unlock()
	return result
}

// hashFile returns the lowercased hex SHA256 of the file at path, mirroring how
// Sysmon computes e.Hashes["SHA256"] (full-file SHA256, hex). Used by the Tier-2
// TOCTOU guard to confirm the bytes winverify read are the bytes `sha` keys.
// Stdlib only. ponytail: reads the whole file into a streaming hasher; fine for
// dev-tool PEs (tens of MB), not a hot path (called only on a verify miss).

// hashFile returns the lowercased hex SHA256 of the file at path, mirroring how
// Sysmon computes e.Hashes["SHA256"] (full-file SHA256, hex). Used by the Tier-2
// TOCTOU guard to confirm the bytes winverify read are the bytes `sha` keys.
// Stdlib only. ponytail: reads the whole file into a streaming hasher; fine for
// dev-tool PEs (tens of MB), not a hot path (called only on a verify miss).
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (a *Allowlist) pathMatchesTrusted(image string) bool {
	np := pathnorm.NormalizePath(image)
	for _, re := range a.tbPath {
		if re.MatchString(np) {
			return true
		}
	}
	return false
}

// ImageInDevTools reports whether image's normalized path matches a dev tool
// path pattern (the scoped set used by NET-002/NET-003).
func (a *Allowlist) ImageInDevTools(image string) bool {
	if a == nil {
		return false
	}
	np := pathnorm.NormalizePath(image)
	for _, re := range a.devPath {
		if re.MatchString(np) {
			return true
		}
	}
	return false
}

// CmdLineInDevScripts reports whether cmdline references a developer-trusted
// script. Used by EXEC-001's `cmdline_in_dev_scripts` except so a developer's
// own `powershell -ep bypass -File <dev.ps1>` workflow doesn't fire while
// EXEC-001 stays armed for every other PS-bypass launch. Matched on the raw
// (un-normalized) commandline with case-insensitive regex; anchor on the
// script filename or path so it survives both absolute and relative -File
// invocations. Evasion note: an attacker who names a payload exactly like a
// trusted dev script AND runs it via powershell -ep bypass would evade
// EXEC-001 — keep dev_scripts entries specific and review them.
func (a *Allowlist) CmdLineInDevScripts(cmdline string) bool {
	if a == nil || cmdline == "" {
		return false
	}
	for _, re := range a.devScript {
		if re.MatchString(cmdline) {
			return true
		}
	}
	return false
}

// DstInCIDR reports whether ip falls in any allowed_destinations CIDR.
func (a *Allowlist) DstInCIDR(ip string) bool {
	if a == nil || ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range a.cidrs {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// DstIsKnownLoopback reports whether (ip, port) is a known-good loopback server
// in known_loopback_listeners (host:port set).
func (a *Allowlist) DstIsKnownLoopback(ip string, port int) bool {
	if a == nil || port == 0 {
		return false
	}
	key := strings.ToLower(fmt.Sprintf("%s:%d", strings.TrimSpace(ip), port))
	return a.loopback[key]
}

// IsLogNoise reports whether ev matches any event_log_filter entry. It is used
// ONLY to suppress the per-event DEBUG dump line in the app layer; it NEVER
// affects rule evaluation. An entry matches when ALL of its set predicates agree
// (AND within an entry; OR across entries). An omitted field is a wildcard.
//
// The per-entry AND is the 1:1 safety contract: {eid:11, image:powershell,
// cmdline:"^$"} suppresses ONLY PowerShell FileCreate with an empty command
// line; the same event carrying a command fails the cmdline clause and still
// logs. image is matched on the normalized lower path (same contract as
// ImageTrusted); cmdline on the raw value. A nil Allowlist or nil event is safe.
func (a *Allowlist) IsLogNoise(e *event.Event) bool {
	if a == nil || e == nil || len(a.logFilter) == 0 {
		return false
	}
	np := pathnorm.NormalizePath(e.Image)
	for _, ent := range a.logFilter {
		if ent.eid != 0 && ent.eid != e.EID {
			continue
		}
		if ent.image != nil && !ent.image.MatchString(np) {
			continue
		}
		if ent.cmdline != nil && !ent.cmdline.MatchString(e.CmdLine) {
			continue
		}
		return true // every set predicate matched
	}
	return false
}

// ShouldCapture reports whether the created file in ev should be snapshotted to
// the forensic vault before it can be deleted. It is consulted ONLY by the app
// layer's snapshot path, NEVER by Evaluate — like IsLogNoise it carries no
// detection decision and can neither suppress nor produce a hit.
//
// A capture is requested when ev is an EID 11 (FileCreate) whose TargetFile
// matches any file_capture pattern. Patterns are matched on the normalized
// lower path (same contract as trusted_binaries / event_log_filter.image).
// Returns the TargetFile to copy (== ev.TargetFile) when matched, "" otherwise
// — so the caller has both the decision and the path to act on in one call.
//
// Use case: the create-and-delete dropper pattern. Cursor spawns
// powershell -ep bypass -File <TEMP>\ps-script-<guid>.ps1 and deletes the
// script immediately after; without a snapshot the contents are never
// inspectable. ShouldCapture lets the app layer copy such files the instant
// Sysmon reports creation. Nil Allowlist / nil event / non-FileCreate events
// are safe (return "").
func (a *Allowlist) ShouldCapture(e *event.Event) string {
	if a == nil || e == nil || (e.EID != 11 && e.EID != 23) || e.TargetFile == "" || len(a.capPatterns) == 0 {
		return ""
	}
	np := pathnorm.NormalizePath(e.TargetFile)
	for _, re := range a.capPatterns {
		if re.MatchString(np) {
			return e.TargetFile
		}
	}
	return ""
}

// --- raw document schema (matches docs/04-TELEMETRY.md §2) ---

type rawDoc struct {
	TrustedBinaries struct {
		SHA256         []string `json:"sha256"`
		Path           []string `json:"path"`            // Tier-1 admin-owned
		HashGatedPath  []string `json:"hash_gated_path"` // Tier-2 user-writable (path AND sig)
		AllowedSigners []string `json:"allowed_signers"` // vendor subjects for Tier-2
	} `json:"trusted_binaries"`
	AllowedDestinations struct {
		CIDR []string `json:"cidr"`
	} `json:"allowed_destinations"`
	KnownLoopbackListeners []string `json:"known_loopback_listeners"`
	DevToolPaths           struct {
		Path []string `json:"path"`
	} `json:"dev_tool_paths"`
	// dev_scripts: commandline anchors (regex), NOT image paths. Flat array —
	// see CmdLineInDevScripts / the package doc for why this set is CmdLine-based.
	DevScripts []string `json:"dev_scripts"`

	// event_log_filter: optional log-only noise filter (NOT an except operator).
	// AND within an entry, OR across entries; suppresses only the per-event
	// DEBUG dump line. See IsLogNoise.
	EventLogFilter []filterRaw `json:"event_log_filter"`

	// file_capture: optional path patterns whose created files (EID 11) the app
	// layer snapshots to a forensic vault before they can be deleted. NOT an
	// except operator; not consulted by Evaluate. See ShouldCapture.
	FileCapture struct {
		Patterns []string `json:"patterns"`
	} `json:"file_capture"`
}

// filterRaw is the JSON shape of one event_log_filter entry. eid 0 and empty
// image/cmdline are wildcards; at least one field must be set (enforced in
// compileFilter) so an entry can never suppress every event's debug line.
type filterRaw struct {
	EID     int    `json:"eid"`
	Image   string `json:"image"`
	Cmdline string `json:"cmdline"`
}

// stripJSONC removes // line comments that are outside double-quoted strings,
// so standard encoding/json can parse the operator-edited allowlist.
func stripJSONC(data []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(data))
	inStr := false
	escaped := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inStr {
			out.WriteByte(c)
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			// skip to end of line (leave the newline so line numbers stay sane)
			for i < len(data) && data[i] != '\n' {
				i++
			}
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}
