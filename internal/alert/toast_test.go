package alert

import (
	"strings"
	"testing"

	"git.sr.ht/~jackmordaunt/go-toast"
)

// Regression: "]]>" in attacker-influenced event data must not survive into the
// go-toast CDATA template — it terminates the CDATA section early and breaks
// XmlDocument.LoadXml (dropping the toast, or worse, triggering go-toast's
// PowerShell fallback when a fallback-enabled push was still in use).
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

// XML-1.0-illegal characters (C0 controls other than tab/LF/CR, U+FFFE/U+FFFF)
// make LoadXml fail. They must be dropped so the COM push succeeds.
func TestStripToastCharsDropsXMLIllegalChars(t *testing.T) {
	in := "a\x01b\x1fc\uFFFEd\uFFFFe\tf\ng"
	got := stripToastChars(in)
	if got != "abcde\tf\ng" {
		t.Fatalf("stripToastChars(%q) = %q, want illegal chars dropped, tab/LF kept", in, got)
	}
}

// The silent tier must stay silent and short (the suspicious-tier contract),
// under the shared app identity.
func TestSilentNotificationPolicy(t *testing.T) {
	n := silentNotification("T", "B")
	if n.Audio != toast.Silent || n.Duration != toast.Short || n.AppID != toastAppID || n.Loop {
		t.Fatalf("silent notification policy changed: %+v", n)
	}
	if n.Title != "T" || n.Body != "B" {
		t.Fatalf("title/body not passed through: %+v", n)
	}
}
