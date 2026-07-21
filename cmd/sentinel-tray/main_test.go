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
	defer windows.CloseHandle(h)

	want := toastMsg{Title: "Sentinel: EXEC-001", Body: "CRITICAL - powershell.exe"}
	payload := []byte(`{"title":"` + want.Title + `","body":"` + want.Body + `"}`)
	var written uint32
	if err := windows.WriteFile(h, payload, &written, nil); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	windows.CloseHandle(h) // signal EOF so the relay stops reading

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
