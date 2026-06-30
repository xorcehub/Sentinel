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
		if !seen[e.Key()] {
			newEntries = append(newEntries, e)
		}
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
