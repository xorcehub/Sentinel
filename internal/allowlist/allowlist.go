// Package allowlist loads config/allowlist.json and answers the subtractive
// `except` checks referenced by Sigma rules' x-sentinel.except block
// (docs/03-RULES.md §3, docs/04-TELEMETRY.md §2).
//
// Five sets, mapping 1:1 to the except operators:
//   image_in_allowlist: trusted_binaries   -> ImageTrusted(hash or path)
//   image_in_dev_tools: dev_tool_paths     -> ImageInDevTools(path)
//   cmdline_in_dev_scripts: dev_scripts    -> CmdLineInDevScripts(cmdline)
//   dst_in_allowlist: allowed_destinations -> DstInCIDR(ip)
//   dst_in_allowlist: known_loopback_listeners -> DstIsKnownLoopback(ip, port)
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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"sentinel/internal/event"
	"sentinel/internal/pathnorm"
)

// Allowlist is the compiled, read-optimized form. All methods are safe for
// concurrent use (they read immutable compiled structures).
type Allowlist struct {
	tbSHA     map[string]bool       // lowercased sha256
	tbPath    []*regexp.Regexp      // path patterns, matched on normalized lower path
	devPath   []*regexp.Regexp
	devScript []*regexp.Regexp      // commandline anchors (dev scripts run via a LOLBin)
	cidrs     []*net.IPNet
	loopback  map[string]bool       // "host:port" lowercased
	logFilter []*logFilterEntry     // event_log_filter: suppresses the per-event DEBUG dump only
	capPatterns []*regexp.Regexp    // file_capture: path patterns matched on EID 11/23 TargetFile
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

// ImageTrusted reports whether the event's acting process is trusted:
// SHA256 match is authoritative; otherwise the normalized Image path matches a
// trusted path pattern.
func (a *Allowlist) ImageTrusted(e *event.Event) bool {
	if a == nil {
		return false
	}
	if e.Hashes != nil {
		if sha, ok := e.Hashes["SHA256"]; ok && sha != "" {
			if a.tbSHA[strings.ToLower(sha)] {
				return true
			}
		}
	}
	return a.pathMatchesTrusted(e.Image)
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
		SHA256 []string `json:"sha256"`
		Path   []string `json:"path"`
	} `json:"trusted_binaries"`
	AllowedDestinations struct {
		CIDR []string `json:"cidr"`
	} `json:"allowed_destinations"`
	KnownLoopbackListeners []string `json:"known_loopback_listeners"`
	DevToolPaths struct {
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
