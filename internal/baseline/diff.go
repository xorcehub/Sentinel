package baseline

import (
	"sort"
	"strings"
	"time"

	"sentinel/internal/event"
)

// Diff compares a daily snapshot against the signed-off clean baseline and
// returns one pseudo-event per NEW entry (present in daily, absent in clean).
// Removed entries are ignored - the threat model is "new persistence appeared",
// not "something vanished" (uninstallers remove things constantly; removed
// entries would be pure noise).
//
// Each returned Event has Source=SrcBaseline, EID=0, and a descriptive payload
// (TargetRegKey or TargetFile + CmdLine) so BASE-001 fires (the baseline
// catch-all) and the alert is actionable. Note: existing behavior rules
// (PERSIST-003 etc.) gate on a Sysmon EventID and will NOT fire on these EID=0
// events by design - BASE-001 is the detector. See 06-BASELINE.md §4.
//
// Diff is a thin wrapper over DiffEntries + EntriesToEvents; callers that need
// to dedup at the ENTRY level (e.g. the daemon's alert-once gate) use those.
func Diff(clean, daily Snapshot) []event.Event {
	return EntriesToEvents(DiffEntries(clean, daily))
}

// DiffEntries returns the NEW entries (present in daily, absent in clean),
// sorted deterministically by Location then Entry. Same NEW-only / removed-
// ignored semantics as Diff, but operates on entries so callers can apply their
// own per-entry gating (e.g. the daemon's Option-A "alert once" dedup on
// Entry.Key()) before converting to events.
func DiffEntries(clean, daily Snapshot) []Entry {
	seen := make(map[string]bool, len(clean.Entries))
	for _, e := range clean.Entries {
		seen[e.Key()] = true
	}

	var newEntries []Entry
	for _, e := range daily.Entries {
		if seen[e.Key()] {
			continue
		}
		// Per-user-service fallback. Windows registers a bare template
		// (cbdhsvc) plus a per-session instance (cbdhsvc_<hex>) whose suffix
		// rotates every logon/user, so a legit service churns as "new"
		// daily. If this daily entry is a <base>_<hex> instance under the
		// Services hive AND base is one of the documented Windows per-user
		// service families (perUserSvcFamily), treat it as known. The family
		// list is the safety gate, not the suffix shape: a hex-tailed name
		// whose base is NOT a real family (PrintWorkflowSvc_deadbeef mimicking
		// the real PrintWorkflowUserSvc, or HWiNFO_214) stays flagged.
		if base, ok := serviceTemplateBase(e.Location, e.Entry); ok && perUserSvcFamily[strings.ToLower(base)] {
			continue
		}
		newEntries = append(newEntries, e)
	}

	// Deterministic ordering: by Location then Entry. So repeated diffs of the
	// same input produce events in the same order - critical for review and
	// for the tests to be stable.
	sort.Slice(newEntries, func(i, j int) bool {
		if newEntries[i].Location != newEntries[j].Location {
			return newEntries[i].Location < newEntries[j].Location
		}
		return newEntries[i].Entry < newEntries[j].Entry
	})
	return newEntries
}

// EntriesToEvents converts NEW entries into baseline pseudo-events (one per
// entry), timestamped now. Exposed so the daemon can filter entries (alert-once
// dedup) and then convert only the survivors to events for routing.
func EntriesToEvents(es []Entry) []event.Event {
	out := make([]event.Event, 0, len(es))
	now := time.Now()
	for _, e := range es {
		out = append(out, baselineEvent(e, now))
	}
	return out
}

// baselineEvent builds the pseudo-event for one new entry. We populate several
// Event fields so the alert carries useful triage context (Image, CmdLine,
// Signer-in-CmdLine) regardless of which channel renders it.
func baselineEvent(e Entry, now time.Time) event.Event {
	ev := event.Event{
		Source:  event.SrcBaseline,
		Time:    now,
		EID:     0,
		Image:   e.ImagePath,
		CmdLine: e.Launch,
	}
	// TargetRegKey for registry-backed locations (so the alert names the key);
	// TargetFile for filesystem locations (Startup folder, etc.). The split is
	// purely cosmetic - both render in the alert's context lines.
	if isRegistryLocation(e.Location) {
		ev.TargetRegKey = e.Location + "\\" + e.Entry
	} else {
		ev.TargetFile = e.Location + " :: " + e.Entry
	}
	// Tuck the signer into the existing User field for alert context (there's
	// no dedicated Signer field on Event; User is the closest unused one that
	// won't collide with rule matchers).
	if e.Signer != "" {
		ev.User = e.Signer
	}
	return ev
}

// isServicesLocation reports whether loc is the Services registry hive
// (HKLM\System\CurrentControlSet\Services). Only there do per-user-service
// instances live; the gate keeps the suffix heuristic off unrelated locations.
// Lowercase compare is a cheap guard against registry-key case drift; autoruns
// reports the path consistently but we don't bet on it.
func isServicesLocation(loc string) bool {
	return strings.HasSuffix(strings.ToLower(loc), `\currentcontrolset\services`)
}

// perUserSvcFamily is the fixed, documented set of Windows per-user service
// families. Each registers a bare template plus a per-session instance
// <template>_<LogonId hex> whose suffix rotates every logon/user. Only these
// bases qualify for the suffix-rotation fallback in DiffEntries — a hardcoded
// family list (not "any template present in the baseline") so an attacker who
// creates BackdoorSvc_deadbeef or PrintWorkflowSvc_deadbeef (mimicking the real
// PrintWorkflowUserSvc) is NOT suppressed. Live creation is still caught by
// PERSIST-005 (Sysmon EID 13); this list only governs the retroactive baseline
// diff. Sourced from the operator's baseline_clean.csv (24 Microsoft families;
// Kaspersky's klupd_..._arkmon is excluded — it's a hex-tail coincidence, not a
// per-user service). Lowercased for case-insensitive lookup.
var perUserSvcFamily = func() map[string]bool {
	m := make(map[string]bool, len(rawPerUserSvcFamily))
	for _, n := range rawPerUserSvcFamily {
		m[strings.ToLower(n)] = true
	}
	return m
}()

var rawPerUserSvcFamily = []string{
	"AarSvc", "BcastDVRUserService", "BluetoothUserService", "CaptureService",
	"cbdhsvc", "CDPUserSvc", "CloudBackupRestoreSvc", "ConsentUxUserSvc",
	"CredentialEnrollmentManagerUserSvc", "DeviceAssociationBrokerSvc",
	"DevicePickerUserSvc", "DevicesFlowUserSvc", "MessagingService", "NPSMSvc",
	"OneSyncSvc", "P9RdrService", "PenService", "PimIndexMaintenanceSvc",
	"PrintWorkflowUserSvc", "UdkUserSvc", "UnistoreSvc", "UserDataSvc",
	"webthreatdefusersvc", "WpnUserService",
}

// serviceTemplateBase reports whether entry looks like a per-user-service
// instance <base>_<hex> under the Services hive, returning the base name. The
// hex suffix is Windows' per-session LogonId and rotates every logon/user
// (observed widths 5-7; we accept 5-8). Returning ok=true means ONLY "the shape
// matches" — the caller MUST still check perUserSvcFamily[base] before relying
// on it, since a hex tail alone is not proof (HWiNFO_214,
// klupd_..._arkmon_DFE8DCB8, and any attacker-chosen <name>_<hex> all share the
// shape).
func serviceTemplateBase(loc, entry string) (base string, ok bool) {
	if !isServicesLocation(loc) {
		return "", false
	}
	i := strings.LastIndex(entry, "_")
	if i <= 0 || i >= len(entry)-1 {
		return "", false
	}
	suffix := entry[i+1:]
	// Real Windows per-user session LogonIds are 5-7 hex chars wide. Accept
	// 5-8 (with a lower bound of 5) so a version-suffixed name with a short tail
	// (HWiNFO_214) is never considered. The perUserSvcFamily membership check in
	// the caller is the primary safety gate; this width bound is a cheap belt.
	if len(suffix) < 5 || len(suffix) > 8 {
		return "", false
	}
	for _, c := range []byte(suffix) {
		if !isHex(c) {
			return "", false
		}
	}
	return entry[:i], true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isRegistryLocation is a heuristic: registry-backed autostart locations start
// with a hive abbreviation (HKLM/HKCU/HKCR/HKU/HKCC). Filesystem locations
// (Startup folders) start with a drive letter or %VAR%.
func isRegistryLocation(loc string) bool {
	upper := strings.ToUpper(loc)
	for _, hive := range []string{"HKLM", "HKCU", "HKCR", "HKU", "HKCC"} {
		if strings.HasPrefix(upper, hive) {
			return true
		}
	}
	return false
}
