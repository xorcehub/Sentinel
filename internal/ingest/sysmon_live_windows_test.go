//go:build windows

package ingest

import (
	"bytes"
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe log sink (the read loop writes, the test reads).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestNativeSubscriptionDeliversLiveEvents drives the real wevtapi path end to
// end on a channel every Windows box has and an unprivileged process can read
// and trigger: starting powershell.exe writes to PowerShell/Operational. It
// proves the pull subscription opens (the old binding failed here with
// ERROR_INVALID_PARAMETER), the backlog is replayed, and a record logged after
// Start arrives through the signal-event loop. It then idles across several
// wait timeouts: draining an idle subscription must not be mistaken for a
// broken one (EvtNext answers ERROR_INVALID_OPERATION there, not
// ERROR_NO_MORE_ITEMS), which would tear it down and reopen it every pass.
func TestNativeSubscriptionDeliversLiveEvents(t *testing.T) {
	const channel = "Microsoft-Windows-PowerShell/Operational"
	var logBuf syncBuffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	ing, err := NewSysmonRT(channel, "*", log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, err := ing.Start(ctx)
	if err != nil {
		t.Skipf("channel %s not usable on this box: %v", channel, err)
	}

	// Drain the backlog replay: it is emitted first and in RecordId order.
	var backlogMax uint64
	n := ing.(*sysmonRT).backlogN
	for i := 0; i < n; i++ {
		select {
		case ev := <-out:
			if ev.RecordID < backlogMax {
				t.Fatalf("backlog not oldest-first: %d after %d", ev.RecordID, backlogMax)
			}
			backlogMax = ev.RecordID
		case <-time.After(10 * time.Second):
			t.Fatalf("backlog replay stalled after %d of %d events", i, n)
		}
	}

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "exit 0")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	if err := cmd.Run(); err != nil {
		t.Fatalf("spawn powershell: %v", err)
	}

	deadline := time.After(15 * time.Second)
	for {
		select {
		case ev, ok := <-out:
			if !ok {
				t.Fatal("ingester channel closed unexpectedly")
			}
			if ev.RecordID > backlogMax {
				// A live record came through. Now idle past a few wait timeouts.
				time.Sleep(3500 * time.Millisecond)
				if l := logBuf.String(); strings.Contains(l, "EvtNext failed") || strings.Contains(l, "resubscribe") {
					t.Fatalf("idle subscription was treated as broken:\n%s", l)
				}
				return
			}
		case <-deadline:
			t.Fatalf("no live event after spawning powershell (backlog max RecordId %d)", backlogMax)
		}
	}
}

func TestLogClearsQueryRuns(t *testing.T) {
	if _, err := queryLogClears(); err != nil {
		t.Skipf("System log not readable here: %v", err)
	}
}
