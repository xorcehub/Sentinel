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
	return a, nil
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
