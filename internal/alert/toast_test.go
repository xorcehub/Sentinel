package alert

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"git.sr.ht/~jackmordaunt/go-toast"

	"sentinel/internal/event"
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

// With no PowerShell fallback a COM failure drops the toast, so failures must
// surface at WARN (default level) — but at most once per window, with the total.
func TestToastFailureWarnsRateLimited(t *testing.T) {
	var buf bytes.Buffer
	ta := &ToastAlerter{log: slog.New(slog.NewTextHandler(&buf, nil))} // default level: INFO
	h := event.Hit{RuleID: "EXEC-001"}
	t0 := time.Now()
	ta.noteFailure(errors.New("first"), h, t0)
	ta.noteFailure(errors.New("second"), h, t0.Add(time.Second))                   // inside window: not at WARN
	ta.noteFailure(errors.New("third"), h, t0.Add(toastFailWarnEvery+time.Second)) // window expired
	out := buf.String()
	if strings.Count(out, "level=WARN") != 2 || !strings.Contains(out, "first") || !strings.Contains(out, "third") || strings.Contains(out, "second") {
		t.Fatalf("want WARN for first and third only, got:\n%s", out)
	}
	if !strings.Contains(out, "failed_total=3") {
		t.Fatalf("running total missing:\n%s", out)
	}
}
