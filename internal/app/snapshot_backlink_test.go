package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"sentinel/internal/allowlist"
	"sentinel/internal/event"
	"sentinel/internal/ingest/mock"
	"sentinel/internal/rules"
	"sentinel/internal/sigmaeval"
	"sentinel/internal/snapshot"
)

// TestSnapshotBackLinksHitToCapture is the A.4 end-to-end wiring test: an EID 11
// captures a file, then an EID 1 detection event whose cmdline references that
// file fires a hit. The hit's hid MUST be stamped into the capture's manifest
// — the forensics pivot from alert to captured content.
//
// Two Run calls model the real temporal ordering: the file is created (EID 11)
// and snapshotted FIRST, then the process that references it (EID 1) fires
// LATER. Splitting the Runs + snap.Wait() between them makes the test
// deterministic: by the time the detection event fires, the capture is already
// indexed. In production there's a natural gap (file must exist before
// powershell can -File it), but the test compresses this into two batches to
// avoid a flaky async race between the capture worker and the hit loop.
func TestSnapshotBackLinksHitToCapture(t *testing.T) {
	vault := t.TempDir()
	srcDir := t.TempDir()

	// Create the real file so the capture succeeds (status=ok).
	scriptPath := filepath.Join(srcDir, "ps-script-backlink.ps1")
	content := []byte("Write-Host 'back-link me'\n")
	if err := os.WriteFile(scriptPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	// Allowlist: capture pattern matching the script's filename + no excepts
	// (so the detection rule fires unconditionally). The pattern anchors on
	// the filename, not the dir, so it's deterministic regardless of where
	// t.TempDir() places the file (the dir name is a test-generated random).
	const alJSON = `{
  "file_capture": { "patterns": ["ps-script-backlink"] }
}`
	al, err := allowlist.Compile([]byte(alJSON))
	if err != nil {
		t.Fatalf("allowlist Compile: %v", err)
	}

	// Rule: fires on powershell -ExecutionPolicy Bypass (EID 1).
	const ruleYAML = `
title: powershell bypass execution
id: deadbeef-bbbb-0000-0000-000000000001
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-ExecutionPolicy Bypass'
  condition: selection
level: high
x-sentinel: { id: EXEC-BACKLINK-001, severity: critical }
`
	rs, err := sigmaeval.Load([]byte(ruleYAML))
	if err != nil {
		t.Fatalf("sigmaeval Load: %v", err)
	}
	eng, err := rules.New(rs, al, newFakeDedup())
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}

	snap, err := snapshot.New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("snapshot New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { snap.Run(ctx); close(done) }()
	defer func() { snap.Close(); <-done }()

	// EID 11: file create — triggers capture (file_capture pattern matches).
	capEv := event.Event{
		EID:        11,
		RecordID:   1,
		TargetFile: scriptPath,
		Image:      `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
	}
	// EID 1: process create — triggers detection (bypass cmdline).
	// The cmdline REFERENCES the captured path — this is what LinkHit matches on.
	detEv := event.Event{
		EID:      1,
		RecordID: 2,
		Image:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CmdLine:  `powershell.exe -ExecutionPolicy Bypass -File ` + scriptPath,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var hitHID string
	var hits atomic.Uint64

	// Phase 1: process the EID 11 (capture). The snapshot worker copies the
	// file and indexes the path async; snap.Wait() below blocks until it's done.
	a1, err := New(Options{
		Logger:   logger,
		Ingester: mock.New(capEv),
		Engine:   eng,
		Snapshot: snap,
	})
	if err != nil {
		t.Fatalf("New (phase 1): %v", err)
	}
	if err := a1.Run(context.Background()); err != nil {
		t.Fatalf("Run (phase 1): %v", err)
	}
	snap.Wait() // capture worker has now processed + indexed the file
	if snap.Captured() != 1 {
		t.Fatalf("captured = %d, want 1 after phase 1", snap.Captured())
	}

	// Phase 2: process the EID 1 (detection). Now the index has the captured
	// path, so LinkHit in the hit loop will find it and stamp the hid.
	a2, err := New(Options{
		Logger:   logger,
		Ingester: mock.New(detEv),
		Engine:   eng,   // shared — dedup state carries over (distinct RecordIDs)
		Snapshot: snap,  // shared — the index from phase 1 is live
		OnHit: func(h event.Hit) {
			hits.Add(1)
			hitHID = h.ID
		},
	})
	if err != nil {
		t.Fatalf("New (phase 2): %v", err)
	}
	if err := a2.Run(context.Background()); err != nil {
		t.Fatalf("Run (phase 2): %v", err)
	}

	// Detection fired.
	if got := hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1 (the bypass event must fire)", got)
	}
	if hitHID == "" || !strings.HasPrefix(hitHID, "R-") {
		t.Fatalf("hit hid = %q, want an R-YYYYMMDD-<nonce>-<NNNNNN> format", hitHID)
	}

	// THE back-link: the capture's manifest must have linked_hid == the hit's
	// hid. Find the capture dir and read its manifest.
	entries, err := os.ReadDir(vault)
	if err != nil {
		t.Fatalf("ReadDir vault: %v", err)
	}
	var foundLinked bool
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		mp := filepath.Join(vault, e.Name(), "manifest.json")
		b, err := os.ReadFile(mp)
		if err != nil {
			continue
		}
		var m struct {
			LinkedHID string `json:"linked_hid"`
			Status    string `json:"status"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		if m.LinkedHID != "" {
			foundLinked = true
			if m.LinkedHID != hitHID {
				t.Errorf("linked_hid = %q, want %q (the hit's hid)", m.LinkedHID, hitHID)
			}
		}
	}
	if !foundLinked {
		t.Error("no capture manifest has a linked_hid — the back-link wiring is broken")
	}
}
