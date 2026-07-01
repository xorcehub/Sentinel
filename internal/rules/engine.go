// Package rules is Sentinel's rule engine. It wires together the pure Sigma
// evaluator (internal/sigmaeval), the allowlist (internal/allowlist), and the
// dedup state, turning an Event into a set of routed Hits (or suppressions).
//
// Pipeline per event (docs/02-ARCHITECTURE.md §4.2, docs/03-RULES.md §6):
//
//	normalize paths
//	  -> RT/sweep RecordID gate (skip sweep events already seen by RT)
//	  -> for each rule:
//	       Sigma Match?
//	         no  -> skip
//	         yes -> x-sentinel.except allowlist check?
//	                 pass -> Suppressed{allowlist}
//	                 fail -> compute target_key, check dedup window
//	                          within  -> Suppressed{dedup-window}
//	                          outside -> build Hit with severity-routed alerters
//	                                     (flood-collapse strips popup/toast if a
//	                                      rule exceeds 50 hits/min)
//
// This package owns severity resolution, alert routing, target_key templating,
// and flood collapse. It does NOT own delivering alerts (dispatcher) or
// ingesting events — those are upstream/downstream.
package rules

import (
	"fmt"
	"strings"
	"sync"
	"text/template"
	"time"

	"sentinel/internal/event"
	"sentinel/internal/pathnorm"
	"sentinel/internal/sigmaeval"
)

// Allowlist is the subset internal/allowlist.Allowlist satisfies. Declared as
// an interface so the engine (and its tests) can run against an in-memory fake.
type Allowlist interface {
	ImageTrusted(e *event.Event) bool
	ImageInDevTools(imagePath string) bool
	CmdLineInDevScripts(cmdline string) bool
	DstInCIDR(ip string) bool
	DstIsKnownLoopback(ip string, port int) bool
	IsLogNoise(e *event.Event) bool // log-only filter; never consulted by Evaluate
}

// Deduper is the dedup state subset internal/state.State satisfies.
type Deduper interface {
	SweepSeen(recordID uint64) bool
	MarkSeen(recordID uint64)
	ReAlert(ruleID, targetKey string, window time.Duration) bool
}

// Engine evaluates loaded Sigma rules against events.
type Engine struct {
	rules []*sigmaeval.Rule
	al    Allowlist
	dedup Deduper

	// compiled target_key templates, keyed by rule id (x-sentinel.id or title)
	tmpls map[string]*template.Template

	// per-rule flood rollers
	floods sync.Map // ruleID -> *roller
}

// New builds an engine. rules and al may be nil (engine becomes a no-op / always
// non-suppressed); dedup must be non-nil for correct sweep behavior.
func New(rules []*sigmaeval.Rule, al Allowlist, dedup Deduper) (*Engine, error) {
	eng := &Engine{rules: rules, al: al, dedup: dedup, tmpls: map[string]*template.Template{}}
	for _, r := range rules {
		id := ruleID(r)
		if r.XTargetKey == "" {
			continue
		}
		t, err := template.New(id).Parse(r.XTargetKey)
		if err != nil {
			return nil, fmt.Errorf("rule %s: bad target_key template %q: %w", id, r.XTargetKey, err)
		}
		eng.tmpls[id] = t
	}
	return eng, nil
}

// Evaluation is the result of evaluating one event.
type Evaluation struct {
	Hits       []event.Hit // actionable alerts, routed
	Suppressed []Suppression
}

// Suppression records why a matching event did NOT produce an alert, so the
// dispatcher can still log it (docs/03 §3: suppressed hits are logged marked
// [SUPPRESSED] unless the rule opts out).
type Suppression struct {
	RuleID   string
	RuleName string
	Reason   string // "allowlist" | "dedup-window"
	Event    event.Event
}

// Evaluate runs all rules against e and returns hits + suppressions.
// It normalizes path-valued fields on e in place before matching.
func (eng *Engine) Evaluate(e *event.Event) *Evaluation {
	eng.normalize(e)
	res := &Evaluation{}

	// RT/sweep overlap gate (RecordID high-water). Only sweep events are gated;
	// RT always flows through and raises the high-water.
	if e.Source == event.SrcSysmonSweep && e.RecordID > 0 && eng.dedup.SweepSeen(e.RecordID) {
		return res
	}
	if e.RecordID > 0 {
		eng.dedup.MarkSeen(e.RecordID)
	}

	for _, r := range eng.rules {
		if !r.Match(e) {
			continue
		}
		id := ruleID(r)
		if eng.exceptSuppresses(r, e) {
			res.Suppressed = append(res.Suppressed, Suppression{id, r.Title, "allowlist", *e})
			continue
		}
		tk := eng.targetKey(id, r, e)
		// Baseline events bypass the per-rule time-window dedup. The baseline loop
		// applies its OWN authoritative dedup (state.BaselineAlerted — the
		// "alert once until reset" Option-A gate) before routing, so ReAlert here
		// is redundant for them. Worse, ReAlert would suppress a baseline event
		// whose Option-A mark was just cleared by a re-snapshot, racing the mark
		// (applied before handleEvent) and silently swallowing the re-alert.
		// Baseline scans run 24h apart, so the 15-min ReAlert never fires in
		// steady state anyway — bypassing it is a no-op in production and fixes
		// the reset edge case. Surfaced by the on-host log: scan after a reset
		// showed alerted=64 but every entry suppressed=dedup-window.
		if e.Source != event.SrcBaseline && !eng.dedup.ReAlert(id, tk, dedupWindow(r)) {
			res.Suppressed = append(res.Suppressed, Suppression{id, r.Title, "dedup-window", *e})
			continue
		}
		h := eng.buildHit(r, e, tk)
		// flood collapse: >50 hits/min from one rule strips popup/toast/eventlog
		// so a runaway rule can't pile up MessageBoxes. The hit still logs.
		if eng.bumpFlood(id) {
			h.AlertTo = []string{"log"}
			h.Matched = "[FLOOD] " + h.Matched
		}
		res.Hits = append(res.Hits, h)
	}
	return res
}

// IsLogNoise exposes the allowlist's event_log_filter so the app layer can drop
// the per-event DEBUG dump line for configured noise. It is deliberately NOT
// consulted by Evaluate — rule evaluation never depends on this, so filtering
// the dump can never cause a false negative (real hits are logged on the "HIT"
// line produced above). Nil-safe: a nil Engine (raw passthrough) or nil
// allowlist returns false, so the dump stays on in those modes (safe and useful
// for tuning).
func (eng *Engine) IsLogNoise(e *event.Event) bool {
	if eng == nil || eng.al == nil {
		return false
	}
	return eng.al.IsLogNoise(e)
}

// ---- except (allowlist subtraction) ----

func (eng *Engine) exceptSuppresses(r *sigmaeval.Rule, e *event.Event) bool {
	if eng.al == nil {
		return false
	}
	// ANY except check passing suppresses (OR).
	for op, setName := range r.XExcept {
		switch op {
		case "image_in_allowlist":
			if eng.al.ImageTrusted(e) {
				return true
			}
		case "image_in_dev_tools":
			if eng.al.ImageInDevTools(e.Image) {
				return true
			}
		case "cmdline_in_dev_scripts":
			if eng.al.CmdLineInDevScripts(e.CmdLine) {
				return true
			}
		case "dst_in_allowlist":
			// set-type-driven: a CIDR set matches by IP; a host:port set by addr:port.
			switch setName {
			case "allowed_destinations":
				if eng.al.DstInCIDR(e.DstIP) {
					return true
				}
			case "known_loopback_listeners":
				if eng.al.DstIsKnownLoopback(e.DstIP, e.DstPort) {
					return true
				}
			default:
				// unknown set name: be safe (do not suppress) — surfaces a config typo.
			}
		}
	}
	return false
}

// ---- target_key ----

// tctx embeds *event.Event so templates can write {{.Image}}, {{.DstIP}},
// {{.DstPort}} (promoted) as well as {{.ID}} (the rule mnemonic). This matches
// the x-sentinel.target_key examples in docs/03-RULES.md verbatim.
type tctx struct {
	ID string
	*event.Event
}

func (eng *Engine) targetKey(id string, r *sigmaeval.Rule, e *event.Event) string {
	t := eng.tmpls[id]
	if t == nil {
		// default: RuleID|Image|CmdLine
		return id + "|" + e.Image + "|" + e.CmdLine
	}
	var sb strings.Builder
	if err := t.Execute(&sb, &tctx{ID: id, Event: e}); err != nil {
		return id + "|" + e.Image + "|" + e.CmdLine
	}
	return sb.String()
}

// ---- severity + alert routing ----

var defaultAlerters = map[event.Severity][]string{
	event.SevCritical:   {"popup", "toast", "log", "eventlog"},
	event.SevSuspicious: {"toast", "log", "eventlog"},
	event.SevInfo:       {"log"},
}

func severity(r *sigmaeval.Rule) event.Severity {
	if r.XSeverity != "" {
		switch strings.ToLower(r.XSeverity) {
		case "critical":
			return event.SevCritical
		case "suspicious":
			return event.SevSuspicious
		case "info":
			return event.SevInfo
		}
	}
	// fallback from Sigma level (docs/03 §4)
	switch strings.ToLower(r.Level) {
	case "critical":
		return event.SevCritical
	case "high", "medium":
		return event.SevSuspicious
	default:
		return event.SevInfo
	}
}

func alerters(r *sigmaeval.Rule, sev event.Severity) []string {
	if len(r.XAlert) > 0 {
		return r.XAlert
	}
	if def, ok := defaultAlerters[sev]; ok {
		return def
	}
	return []string{"log"}
}

func dedupWindow(r *sigmaeval.Rule) time.Duration {
	if r.XDedup != "" {
		if d, err := time.ParseDuration(r.XDedup); err == nil {
			return d
		}
	}
	return 15 * time.Minute
}

func (eng *Engine) buildHit(r *sigmaeval.Rule, e *event.Event, targetKey string) event.Hit {
	sev := severity(r)
	return event.Hit{
		RuleID:   ruleID(r),
		RuleUUID: r.ID,
		RuleName: r.Title,
		Severity: sev,
		Event:    *e,
		Matched:  fmt.Sprintf("%s on %s", r.XID, matchedActor(e)),
		AlertTo:  alerters(r, sev),
		Time:     time.Now(),
	}
}

// matchedActor returns the best available actor identifier for the matched-on
// display string. Image is normally the actor; for EID 8/10 it's already been
// copied from SourceImage in normalize(). Fall back to SourceImage, then
// TargetImage, then a placeholder so the string is never empty ("INJECT-001 on "
// was a real bug from EID 8 having no Image field).
func matchedActor(e *event.Event) string {
	if e.Image != "" {
		return e.Image
	}
	if e.SourceImage != "" {
		return e.SourceImage
	}
	if e.TargetImage != "" {
		return e.TargetImage
	}
	return "<unknown>"
}

// ---- flood collapse ----

const (
	floodWindow  = time.Minute
	floodThreshold = 50
)

type roller struct {
	mu sync.Mutex
	ts []time.Time
}

// bumpFlood records a hit for id and reports whether the rule is now in flood
// state (>threshold hits in the last minute).
func (eng *Engine) bumpFlood(id string) bool {
	v, _ := eng.floods.LoadOrStore(id, &roller{})
	rl := v.(*roller)
	now := time.Now()
	cutoff := now.Add(-floodWindow)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	// trim to window
	i := 0
	for ; i < len(rl.ts); i++ {
		if rl.ts[i].After(cutoff) {
			break
		}
	}
	rl.ts = rl.ts[i:]
	rl.ts = append(rl.ts, now)
	return len(rl.ts) > floodThreshold
}

// ---- helpers ----

func ruleID(r *sigmaeval.Rule) string {
	if r.XID != "" {
		return r.XID
	}
	if r.ID != "" {
		return r.ID
	}
	return r.Title
}

// normalize lowercases path-valued fields (and collapses /x/ -> X:\) so rule
// and allowlist matching are form-insensitive. Registry paths are left alone.
func (eng *Engine) normalize(e *event.Event) {
	// EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess) report the acting
	// process as SourceImage, NOT Image - Sysmon's XML has no <Image> for these
	// events. Rules/alerts expect Image to be the actor ("the thing that did
	// it"), so copy SourceImage into Image when Image is empty. Without this,
	// INJECT-001 (EID 8) and CRED-002 (EID 10) alerts show a blank injector and
	// `except: image_in_allowlist` can never suppress them.
	if e.Image == "" && (e.EID == 8 || e.EID == 10) && e.SourceImage != "" {
		e.Image = e.SourceImage
	}
	e.Image = pathnorm.NormalizePath(e.Image)
	e.ParentImage = pathnorm.NormalizePath(e.ParentImage)
	e.ImageLoaded = pathnorm.NormalizePath(e.ImageLoaded)
	e.SourceImage = pathnorm.NormalizePath(e.SourceImage)
	e.TargetImage = pathnorm.NormalizePath(e.TargetImage)
	e.TargetFile = pathnorm.NormalizePath(e.TargetFile)
}
