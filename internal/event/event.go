// Package event defines the normalized Event that flows through the Sentinel
// pipeline, and the Sigma/Sysmon EventData field-name → Event-field map
// documented in docs/04-TELEMETRY.md §1.1.
//
// Rule matchers never touch struct fields directly; they call Event.Field(name)
// with the Sigma field name (e.g. "DestinationIp", "ImageLoaded", "TargetImage").
// This is the single place that maps Sigma spelling to struct fields, so the
// "matched the wrong field" bug class (INJECT-002 / CRED-002 in the original
// draft) cannot recur: a rule on EID 10 that writes target_image resolves here
// to Event.TargetImage, period.
package event

import (
	"fmt"
	"strings"
	"time"
)

type Source string

const (
	SrcSysmonRT    Source = "sysmon_rt"
	SrcSysmonSweep Source = "sysmon_sweep"
	SrcBaseline    Source = "baseline"
	SrcFirewall    Source = "firewall"
)

type Severity string

const (
	SevCritical   Severity = "critical"
	SevSuspicious Severity = "suspicious"
	SevInfo       Severity = "info"
)

// Hit is what a rule produces when an Event matches.
type Hit struct {
	ID        string   // per-alert correlation key; R-YYYYMMDD-<nonce>-<NNNNNN> (05-ALERTING.md §5). Stamped once in rules.buildHit; emitted by every channel so sentinel.log and ALERTS.log join on this key, not a colliding timestamp.
	RuleID    string   // x-sentinel.id mnemonic (stable); falls back to Sigma title
	RuleUUID  string   // canonical Sigma id
	RuleName  string   // Sigma title
	Severity  Severity
	Event     Event
	Matched   string   // human description of what matched
	AlertTo   []string // ["popup","toast","log","eventlog","webhook"]
	Time      time.Time
}

// Event is the unified, source-agnostic pipeline item. Real Sysmon events,
// sweep replays, baseline pseudo-events, and firewall tails all normalize to it.
type Event struct {
	Source        Source
	RecordID      uint64 // Sysmon EventRecordID; PRIMARY key for RT/sweep overlap dedup
	EID           int    // Sysmon event ID (0 for pseudo-events)
	Time          time.Time
	Image         string // acting process (loader on EID7, source on EID8/10 — see 04 §1.1)
	CmdLine       string
	ParentImage   string
	ParentCmdLine string
	User          string

	// EID 7 (ImageLoad)
	ImageLoaded string  // the DLL that loaded (NOT Image)
	Signed      string  // "true"/"false" — signature status of the LOADED MODULE
	Signature   string  // signer of the loaded module

	// EID 8 (CreateRemoteThread) / 10 (ProcessAccess)
	SourceImage   string // acting process (= Image; kept explicit so EID8/10 rules read naturally)
	TargetImage   string // victim process, e.g. lsass.exe — CRED-002 matches THIS
	GrantedAccess string // EID10 access mask

	// EID 3 (NetworkConnect)
	DstIP    string
	DstPort  int
	DstProto string

	// EID 11/23 (FileCreate/Delete)
	TargetFile string // created/deleted file path (files ONLY — never a process victim)
	Archived   string // EID 23 only: "true"/"false" — whether Sysmon archived the deleted file

	// EID 12/13 (Registry)
	TargetRegKey string // TargetObject
	Details      string // EID13 value data

	// EID 22 (DNSQuery)
	QueryName    string
	QueryResults string

	// EID 1 (Hashes) — parsed into a map
	Hashes map[string]string
}

// Field returns the string value of a Sigma/Sysmon EventData field name and
// whether that field is present in this event. Field names are matched
// case-insensitively (Sigma convention). A field that is absent or empty
// returns ok=false, which makes any selection referencing it not match — the
// correct Sigma semantics, and what makes `not filter` behave intuitively.
func (e *Event) Field(name string) (val string, ok bool) {
	switch strings.ToLower(name) {
	case "source":
		return string(e.Source), e.Source != ""
	case "eventid":
		if e.EID == 0 {
			return "", false
		}
		return fmt.Sprintf("%d", e.EID), true
	case "image":
		return e.Image, e.Image != ""
	case "commandline":
		return e.CmdLine, e.CmdLine != ""
	case "parentimage":
		return e.ParentImage, e.ParentImage != ""
	case "parentcommandline":
		return e.ParentCmdLine, e.ParentCmdLine != ""
	case "user":
		return e.User, e.User != ""
	case "imageloaded":
		return e.ImageLoaded, e.ImageLoaded != ""
	case "signed":
		return e.Signed, e.Signed != ""
	case "signature":
		return e.Signature, e.Signature != ""
	case "sourceimage":
		// SourceImage defaults to Image when not separately populated.
		if e.SourceImage != "" {
			return e.SourceImage, true
		}
		return e.Image, e.Image != ""
	case "targetimage":
		return e.TargetImage, e.TargetImage != ""
	case "grantedaccess":
		return e.GrantedAccess, e.GrantedAccess != ""
	case "destinationip":
		return e.DstIP, e.DstIP != ""
	case "destinationport":
		if e.DstPort == 0 {
			return "", false
		}
		return fmt.Sprintf("%d", e.DstPort), true
	case "protocol":
		return e.DstProto, e.DstProto != ""
	case "targetfilename":
		return e.TargetFile, e.TargetFile != ""
	case "targetobject":
		return e.TargetRegKey, e.TargetRegKey != ""
	case "details":
		return e.Details, e.Details != ""
	case "queryname":
		return e.QueryName, e.QueryName != ""
	case "queryresults":
		return e.QueryResults, e.QueryResults != ""
	default:
		// Unknown field name → treat as absent. (raw.<name> passthrough and
		// Hashes/SHA256/IMPHASH sub-fields can be added here later.)
		return "", false
	}
}
