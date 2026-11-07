package alert

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
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

// Every toast is cleaned at render time, not only the daemon's: the tray relay
// passes pipe-supplied text straight to SilentToast/LoudToast. A "]]>" there
// must not close the CDATA section and inject elements, and an illegal char
// must not reach LoadXml.
func TestRenderToastXMLCleansRelayText(t *testing.T) {
	evil := `x]]></text><image src="\host\share\a.png"/><text><![CDATA[y` + "\x01"
	for name, n := range map[string]toast.Notification{
		"silent": silentNotification(evil, evil),
		"loud":   criticalNotification(evil, evil),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := renderToastXML(n)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, "\x01") {
				t.Fatalf("illegal char survived:\n%s", out)
			}
			dec := xml.NewDecoder(strings.NewReader(out))
			var texts, images int
			for {
				tok, err := dec.Token()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("rendered toast is not well-formed XML: %v\n%s", err, out)
				}
				if se, ok := tok.(xml.StartElement); ok {
					switch se.Name.Local {
					case "text":
						texts++
					case "image":
						images++
					}
				}
			}
			if texts != 2 || images != 0 {
				t.Fatalf("CDATA breakout injected elements: texts=%d images=%d\n%s", texts, images, out)
			}
		})
	}
}

// A permanently broken toast channel must settle at a slow WARN rate (doubling
// back-off up to toastFailWarnMax), and a successful push resets it.
func TestToastFailureWarnBackoffAndReset(t *testing.T) {
	var buf bytes.Buffer
	ta := &ToastAlerter{log: slog.New(slog.NewTextHandler(&buf, nil))}
	h := event.Hit{RuleID: "EXEC-001"}
	t0 := time.Now()
	warns := func() int { return strings.Count(buf.String(), "level=WARN") }

	ta.noteFailure(errors.New("f"), h, t0) // WARN 1, interval stays 1m
	at := t0
	for _, step := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
		ta.noteFailure(errors.New("f"), h, at.Add(step-time.Second)) // just before: no WARN
		at = at.Add(step)
		ta.noteFailure(errors.New("f"), h, at) // on time: WARN, interval doubles
	}
	if got := warns(); got != 4 {
		t.Fatalf("want 4 WARNs on the 1m/2m/4m back-off schedule, got %d:\n%s", got, buf.String())
	}
	for i := 1; i <= 20; i++ { // long outage: interval caps at toastFailWarnMax
		ta.noteFailure(errors.New("f"), h, at.Add(time.Duration(i)*time.Hour))
	}
	if ta.warnEvery != toastFailWarnMax {
		t.Fatalf("warnEvery=%v, want cap %v", ta.warnEvery, toastFailWarnMax)
	}

	ta.noteSuccess()
	before := warns()
	ta.noteFailure(errors.New("after-success"), h, at.Add(21*time.Hour))
	if warns() != before+1 {
		t.Fatalf("first failure after a successful push must WARN immediately:\n%s", buf.String())
	}
}
