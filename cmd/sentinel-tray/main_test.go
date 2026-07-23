// Round-trip self-check for the toast relay: client writes a toastMsg over the
// named pipe, the relay reads+parses it and fires notifyFn (swapped to capture
// in this test). Exercises the full Windows pipe handshake end-to-end.

//go:build windows

package main

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestPipeRoundTrip(t *testing.T) {
	const testPipe = `\\.\pipe\sentinel-toast-test`
	namePtr, err := windows.UTF16PtrFromString(testPipe)
	if err != nil {
		t.Fatalf("UTF16 pipe name: %v", err)
	}

	// Capture the parsed toast instead of firing a real one.
	type captured struct {
		title, body string
	}
	got := make(chan captured, 1)
	orig := notifyFn
	notifyFn = func(title, body string, _ any) error {
		got <- captured{title, body}
		return nil
	}
	defer func() { notifyFn = orig }()

	// Relay instance: one connection then return (handleConnection, not the
	// infinite serveInstance loop).
	go handleConnection(0, namePtr)

	// Client: poll CreateFile briefly while the relay's instance comes up
	// (CreateNamedPipe + ConnectNamedPipe). In production the daemon drops on
	// ERROR_PIPE_BUSY; the test retries to avoid the startup race.
	var h windows.Handle
	deadline := time.Now().Add(2 * time.Second)
	for {
		var openErr error
		h, openErr = windows.CreateFile(
			namePtr, windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, 0, 0,
		)
		if openErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("client could not connect (pipe never ready): %v", openErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	want := toastMsg{Title: "Sentinel: EXEC-001", Body: "CRITICAL - powershell.exe"}
	payload := []byte(`{"title":"` + want.Title + `","body":"` + want.Body + `"}`)
	var written uint32
	if err := windows.WriteFile(h, payload, &written, nil); err != nil {
		windows.CloseHandle(h)
		t.Fatalf("WriteFile: %v", err)
	}
	// Close once to signal EOF to the relay. Do NOT also defer CloseHandle(h):
	// a double-close recycles the handle value, which can close an unrelated
	// runtime semaphore and crash shutdown with errno 6 (ERROR_INVALID_HANDLE).
	windows.CloseHandle(h)

	select {
	case c := <-got:
		if c.title != want.Title || c.body != want.Body {
			t.Fatalf("round-trip mismatch:\n got  title=%q body=%q\n want title=%q body=%q",
				c.title, c.body, want.Title, want.Body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not deliver the toast (notifyFn never called)")
	}
}

// TestPipeOverflowDropped pins the relay's DoS bound: a client that streams
// past maxRead without closing must NOT OOM the tray. readUntilClose returns
// nil, handleConnection drops without notifying, so notifyFn is never called.
// Regression guard for the unbounded readUntilClose bug.
func TestPipeOverflowDropped(t *testing.T) {
	const testPipe = `\\.\pipe\sentinel-toast-overflow`
	namePtr, err := windows.UTF16PtrFromString(testPipe)
	if err != nil {
		t.Fatalf("UTF16 pipe name: %v", err)
	}

	// notifyFn must NOT fire on an overflow connection.
	fired := make(chan struct{}, 1)
	orig := notifyFn
	notifyFn = func(_, _ string, _ any) error {
		fired <- struct{}{}
		return nil
	}
	defer func() { notifyFn = orig }()

	go handleConnection(0, namePtr)

	var h windows.Handle
	deadline := time.Now().Add(2 * time.Second)
	for {
		var openErr error
		h, openErr = windows.CreateFile(
			namePtr, windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, 0, 0,
		)
		if openErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("client could not connect (pipe never ready): %v", openErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Stream well past maxRead in 4 KiB chunks, then close. Before the fix this
	// grew the buffer unbounded (or hung the relay on a huge payload); after it,
	// readUntilClose hits the cap and returns nil at the first over-cap read.
	sent := 0
	chunk := make([]byte, 4096)
	for sent <= maxRead+4096 {
		var n uint32
		if err := windows.WriteFile(h, chunk, &n, nil); err != nil {
			// The relay closes its handle once readUntilClose returns nil, which
			// can break the pipe mid-write; that's the expected drop signal.
			break
		}
		sent += int(n)
	}
	// Single close (no defer) - see TestPipeRoundTrip: a double-close recycles
	// the handle value and can close a runtime semaphore (errno 6 at shutdown).
	windows.CloseHandle(h)

	select {
	case <-fired:
		t.Fatal("overflow connection must be dropped without notifying; " +
			"notifyFn fired (relay accepted an over-cap payload)")
	case <-time.After(500 * time.Millisecond):
		// Good: dropped, no notify. Half a second is ample for the relay to
		// parse-or-drop a single buffered connection.
	}
}
