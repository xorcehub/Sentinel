package alert

import (
	"strings"
	"testing"
)

// Regression: "]]>" in attacker-influenced event data must not survive into the
// go-toast CDATA template — it terminates the CDATA section early and breaks
// XmlDocument.LoadXml (dropping the toast, or worse, triggering beeep's
// PowerShell fallback).
func TestStripToastCharsNeutralizesCDATATerminator(t *testing.T) {
	in := `C:\x]]>y -c "payload"]]>more`
	got := stripToastChars(in)
	if strings.Contains(got, "]]>") {
		t.Fatalf("stripToastChars output still contains CDATA terminator: %q", got)
	}
	if !strings.Contains(got, "] ]>") {
		t.Fatalf("expected neutralized sequence, got %q", got)
	}
	const clean = `plain C:\path arg`
	if got := stripToastChars(clean); got != clean {
		t.Fatalf("clean input mangled: %q", got)
	}
}
