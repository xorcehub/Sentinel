package main

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"
)

// Sysmon XML structure for parsing the snippet.
type TargetFilename struct {
	Condition string `xml:"condition,attr"`
	Inner     string `xml:",chardata"`
}

type Include struct {
	TargetFilenames []TargetFilename `xml:"TargetFilename"`
}

type RuleGroup struct {
	Name          string  `xml:"name,attr"`
	GroupRelation string  `xml:"groupRelation,attr"`
	Include       Include `xml:"include"`
}

type Sysmon struct {
	XMLName    xml.Name    `xml:"Root"` // wrapper for snippet parsing
	RuleGroups []RuleGroup `xml:"RuleGroup"`
	// Snippet is flat <TargetFilename> elements (no RuleGroup wrapper),
	// so we also parse them directly.
	DirectTargets []TargetFilename `xml:"TargetFilename"`
}

// parseFileCreateXML parses the sysmon-filecreate.xml snippet. The snippet
// is a fragment (not a full Sysmon config), so we wrap it in a <Root> element
// for xml.Unmarshal.
func parseFileCreateXML(t *testing.T) []TargetFilename {
	t.Helper()
	raw, err := os.ReadFile("sysmon-filecreate.xml")
	if err != nil {
		t.Fatalf("read sysmon-filecreate.xml: %v", err)
	}
	wrapped := "<Root>" + string(raw) + "</Root>"
	var root Sysmon
	if err := xml.Unmarshal([]byte(wrapped), &root); err != nil {
		t.Fatalf("parse sysmon-filecreate.xml: %v", err)
	}
	// The snippet is flat <TargetFilename> elements (no RuleGroup).
	return root.DirectTargets
}

// TestFileCreateHasCred001Entries: the sysmon-filecreate.xml MUST contain all
// browser-vault staging-path entries for CRED-001 to fire. If any are missing,
// a stealer copying logins.json to Temp produces no EID 11 and CRED-001 is blind.
// This pins the entries from commit 81616fe so accidental deletion is caught.
func TestFileCreateHasCred001Entries(t *testing.T) {
	targets := parseFileCreateXML(t)

	// Build a set of what's actually in the XML.
	got := make(map[string]bool)
	for _, tf := range targets {
		got[strings.TrimSpace(tf.Inner)] = true
	}

	// Every one of these MUST be present. The staging-path prefix (\Temp\,
	// \Downloads\, \Desktop\) is the whole point — without it, the browser's
	// own profile writes would flood alerts.
	//
	// Firefox / NSS SQLite vaults:
	mustContain := []string{
		`\Temp\logins.json`,
		`\Downloads\logins.json`,
		`\Desktop\logins.json`,
		`\Temp\key4.db`,
		`\Downloads\key4.db`,
		`\Desktop\key4.db`,
		`\Temp\key3.db`,
		`\Temp\signons.sqlite`,
		`\Temp\cookies.sqlite`,
		`\Temp\formhistory.sqlite`,
		// Chromium / Edge / Chrome / Brave:
		`\Temp\Login Data`,
		`\Downloads\Login Data`,
		`\Desktop\Login Data`,
		`\Temp\Login Data For Account`,
		`\Temp\Web Data`,
		`\Temp\Local State`,
		`\Temp\Cookies`,
	}

	for _, want := range mustContain {
		if !got[want] {
			t.Errorf("missing CRED-001 entry: %q\n  Without this, a stealer copying this file to a staging path produces no EID 11.", want)
		}
	}

	// Also verify entries are path-scoped (must contain a staging prefix).
	// An unscoped entry like just "logins.json" would fire on the browser's
	// own profile writes → popup flood.
	for _, tf := range targets {
		v := strings.TrimSpace(tf.Inner)
		// Skip non-CRED entries (ps-script, rules.d, allowlist, etc.)
		if !isCredVaultName(v) {
			continue
		}
		if !strings.Contains(v, `\Temp\`) && !strings.Contains(v, `\Downloads\`) && !strings.Contains(v, `\Desktop\`) {
			t.Errorf("CRED-001 entry %q is NOT path-scoped to staging — will fire on browser's own profile writes (popup flood)", v)
		}
	}
}

// TestFileCreateHasOriginalEntries: the pre-existing entries must still be
// present (regression guard against accidental deletion during CRED-001 edits).
func TestFileCreateHasOriginalEntries(t *testing.T) {
	targets := parseFileCreateXML(t)
	got := make(map[string]bool)
	for _, tf := range targets {
		got[strings.TrimSpace(tf.Inner)] = true
	}

	originals := []string{
		`\Temp\ps-script-`,
		`\Start Menu\Programs\Startup`,
		`\rules.d\`,
		`allowlist.json`,
		`sentinel.conf`,
		`state.db`,
		`baseline_clean.json`,
	}
	for _, want := range originals {
		if !got[want] {
			t.Errorf("missing original entry: %q", want)
		}
	}
}

// TestFileCreateNoDuplicates: duplicate entries waste Sysmon parse time and
// make the config harder to reason about.
func TestFileCreateNoDuplicates(t *testing.T) {
	targets := parseFileCreateXML(t)
	seen := make(map[string]int)
	for _, tf := range targets {
		v := strings.TrimSpace(tf.Inner)
		seen[v]++
	}
	for v, count := range seen {
		if count > 1 {
			t.Errorf("duplicate entry: %q (appears %d times)", v, count)
		}
	}
}

// isCredVaultName reports whether v looks like a browser vault filename
// (the CRED-001 set), as opposed to a sentinel config entry.
func isCredVaultName(v string) bool {
	credNames := []string{
		"logins.json", "key4.db", "key3.db", "signons.sqlite",
		"cookies.sqlite", "formhistory.sqlite", "Login Data",
		"Login Data For Account", "Web Data", "Local State", "Cookies",
	}
	for _, n := range credNames {
		if strings.HasSuffix(v, n) {
			return true
		}
	}
	return false
}
