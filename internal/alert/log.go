package alert

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"sentinel/internal/event"
)

// LogAlerter writes every hit to an append-only ALERTS.log file (05-ALERTING.md
// §5). Format is one block per hit, machine-parseable + human-readable:
//
//	[2026-06-26T14:03:11+02:00] CRITICAL  rule=PERSIST-001  title=...
//	    image : C:\Windows\System32\conhost.exe
//	    cmd   : conhost.exe --headless powershell ...
//	    match : ...
//	    action: popup,toast,eventlog
//
// Suppressions are written marked [SUPPRESSED] so the audit trail records them
// even though no alert fired.
//
// Rotation at 10MB x 5 is deferred (Phase 2 polish); for now the file is
// reopened per write via a persistent handle guarded by a mutex. Concurrency:
// safe — all writes go through the mutex.
type LogAlerter struct {
	mu  sync.Mutex
	f   *os.File
	dst io.Writer // if set, writes here instead of the file (tests)
}

const alerterLogName = "log"

// NewLogAlerter opens path for append (created if absent).
func NewLogAlerter(path string) (*LogAlerter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open ALERTS.log %s: %w", path, err)
	}
	return &LogAlerter{f: f}, nil
}

// NewLogAlerterTo writes to an arbitrary io.Writer (for tests / stderr).
func NewLogAlerterTo(w io.Writer) *LogAlerter {
	return &LogAlerter{dst: w}
}

// Name implements Alerter.
func (a *LogAlerter) Name() string { return alerterLogName }

// Alert writes one hit as a formatted block.
func (a *LogAlerter) Alert(h event.Hit) error {
	block := formatHit(h)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dst != nil {
		_, err := fmt.Fprintln(a.dst, block)
		return err
	}
	if a.f == nil {
		return fmt.Errorf("ALERTS.log not open")
	}
	_, err := a.f.WriteString(block + "\n")
	return err
}

// WriteSuppression writes a suppression record (audit trail — matches are logged
// even when no alert fires). Not part of the Alerter interface; called by the
// dispatcher for each Suppression it receives.
func (a *LogAlerter) WriteSuppression(s Suppression) error {
	block := formatSuppression(s)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dst != nil {
		_, err := fmt.Fprintln(a.dst, block)
		return err
	}
	if a.f == nil {
		return fmt.Errorf("ALERTS.log not open")
	}
	_, err := a.f.WriteString(block + "\n")
	return err
}

// Close releases the underlying file handle.
func (a *LogAlerter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f != nil {
		err := a.f.Close()
		a.f = nil
		return err
	}
	return nil
}

func formatHit(h event.Hit) string {
	ts := h.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	var b strings.Builder
	// Header carries the correlation key (hid) so this block joins 1:1 with the
	// msg=HIT line in sentinel.log, plus rec (source Sysmon EventRecordID) so an
	// analyst can pivot to the raw event in Event Viewer. rec is omitted for
	// baseline pseudo-events (RecordID == 0) since 0 carries no Sysmon event.
	hdr := fmt.Sprintf("[%s] %-8s hid=%s ",
		ts.Format(time.RFC3339), upper(string(h.Severity)), h.ID)
	if h.Event.RecordID > 0 {
		hdr += fmt.Sprintf("rec=%d ", h.Event.RecordID)
	}
	fmt.Fprintf(&b, "%srule=%-12s title=%s\n    image : %s\n    cmd   : %s",
		hdr,
		h.RuleID,
		h.RuleName,
		sanitize(h.Event.Image),
		trunc(sanitize(h.Event.CmdLine), 200),
	)
	for _, line := range contextLines(h.Event) {
		fmt.Fprintf(&b, "\n    %s", line)
	}
	fmt.Fprintf(&b, "\n    match : %s\n    action: %s",
		trunc(sanitize(h.Matched), 200),
		joinActions(h.AlertTo),
	)
	return b.String()
}

// contextLines returns human-readable "label : value" lines for whichever Event
// fields are non-empty AND relevant to the hit. The parent process (parent/pcmd)
// is universal — present on every real Sysmon event — so it leads the block:
// process lineage is the most useful triage field when the acting image is
// generic (powershell.exe) and the parent (e.g. cursor.exe) disambiguates a dev
// tool from malware. The rest is EID-specific — network / injection / file /
// registry / DNS alerts gain the dst IP:port, victim process, loaded DLL, target
// file, etc. An event with no parent and no EID-specific context stays compact
// (just image+cmd). Shared by LogAlerter, PopupAlerter, EventLogAlerter so every
// channel surfaces the same context (05-ALERTING.md observability) — including
// the parent, which previously only the popup surfaced (hardcoded in formatPopup).
func contextLines(e event.Event) []string {
	// cl formats one "label : value" line, sanitizing control chars out of the
	// value so no attacker-reachable field (command line, registry value data,
	// DNS answer, cert subject, ...) can inject a forged line into ALERTS.log.
	// Routing every context line through cl means a newly-added field can't
	// regress the protection. See sanitize for why every field (even FS paths)
	// is sanitized uniformly rather than classifying per field.
	cl := func(label, value string) string {
		return fmt.Sprintf("%-6s: %s", label, sanitize(value))
	}
	var lines []string
	// Parent process — universal (every Sysmon event carries it). Emitted first
	// so lineage reads Proc → cmd → parent → [specific context]. See the comment
	// above for why this matters for generic-image alerts (powershell/cursor).
	if e.ParentImage != "" {
		lines = append(lines, cl("parent", e.ParentImage))
		if e.ParentCmdLine != "" {
			lines = append(lines, cl("pcmd", trunc(sanitize(e.ParentCmdLine), 160)))
		}
	}
	// EID 3 (NetworkConnect)
	if e.DstIP != "" {
		dst := e.DstIP
		if e.DstPort != 0 {
			dst = fmt.Sprintf("%s:%d", dst, e.DstPort)
		}
		if e.DstProto != "" {
			dst += "/" + e.DstProto
		}
		lines = append(lines, cl("dst", dst))
	}
	// EID 7 (ImageLoad)
	if e.ImageLoaded != "" {
		lines = append(lines, cl("loaded", e.ImageLoaded))
		if e.Signed != "" {
			lines = append(lines, cl("signed", e.Signed))
		}
		if e.Signature != "" {
			lines = append(lines, cl("signer", e.Signature))
		}
	}
	// EID 8 / 10 (CreateRemoteThread / ProcessAccess)
	if e.TargetImage != "" {
		lines = append(lines, cl("target", e.TargetImage))
		if e.GrantedAccess != "" {
			lines = append(lines, cl("access", e.GrantedAccess))
		}
	}
	// EID 11 / 23 (FileCreate / FileDelete)
	if e.TargetFile != "" {
		lines = append(lines, cl("file", e.TargetFile))
	}
	// EID 12 / 13 (Registry)
	if e.TargetRegKey != "" {
		lines = append(lines, cl("regkey", e.TargetRegKey))
		if e.Details != "" {
			lines = append(lines, cl("detail", e.Details))
		}
	}
	// EID 22 (DNSQuery)
	if e.QueryName != "" {
		lines = append(lines, cl("query", e.QueryName))
		if e.QueryResults != "" {
			lines = append(lines, cl("results", e.QueryResults))
		}
	}
	return lines
}

func formatSuppression(s Suppression) string {
	return fmt.Sprintf("[%s] SUPPRESSED rule=%-12s reason=%s\n    image : %s\n    cmd   : %s",
		time.Now().Format(time.RFC3339),
		s.RuleID, s.Reason,
		sanitize(s.Event.Image),
		trunc(sanitize(s.Event.CmdLine), 200),
	)
}

func upper(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// trunc returns the first n bytes of s (backed up to a rune boundary so the
// result is always valid UTF-8) with "…" appended when truncated. The naive
// s[:n] slice split multibyte runes in non-ASCII command lines (Cyrillic/CJK
// usernames and paths are common on Windows), emitting invalid UTF-8 like a
// lone 0xd0 lead byte — garbled as � in popups/ALERTS.log/EventLog and a
// broken escape in the JSON toast payload. Rune-safe for ~the cost of a scan.
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n-- // back up to a rune-start byte; never slice through a multibyte seq
	}
	return s[:n] + "…"
}

// sanitize replaces C0 control characters (0x00-0x1F: newline, carriage
// return, tab, and the rest) with a space so an attacker cannot forge lines
// in ALERTS.log by embedding '\n' in attacker-controlled event data. The live
// vectors are command lines (lpCommandLine accepts any byte), registry value
// data (Details), registry key paths, DNS names/answers, and cert subjects —
// Windows filesystem paths cannot hold 0x0A, but every event-derived field is
// sanitized anyway: it's a free no-op on clean values and removes the fragile
// "which field is injectable" classification (an earlier fix narrowed it to
// command lines only and missed Details, a confirmed registry-value vector).
// Applied at every ALERTS.log embedding site in formatHit/contextLines/
// formatSuppression. DEL (0x7f) and C1 (0x80-0x9f) are out of scope: they
// don't break line structure in a text log.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 {
			return ' '
		}
		return r
	}, s)
}

func joinActions(a []string) string {
	out := ""
	for i, s := range a {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
