// Command sentinel-tray is a user-session relay that surfaces toasts for the
// SYSTEM daemon. The daemon runs in Session 0 (SYSTEM Scheduled Task), where
// WinRT toast notifications fail with "Access is denied" (no user profile /
// notification infrastructure). This relay runs in the interactive user's
// session (autostarted via HKLM\...\Run by install.ps1) and listens on a named
// pipe; the daemon's PipeToastAlerter writes one JSON toast per connection.
//
// Protocol: one connection = one toast. Client writes JSON {title,body} then
// closes; server reads until EOF, parses, toasts. Length-prefix bounds checking
// and pipe-ACL hardening are Phase 2 (docs/plan-toasts_1707.md). Phase 1 MVP is
// localhost single-user.
//
//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/gen2brain/beeep"
	"golang.org/x/sys/windows"

	"sentinel/internal/alert"
)

const (
	pipeName = `\\.\pipe\sentinel-toast`
	// instances: concurrent toasts the relay can handle. Each instance is one
	// blocking ConnectNamedPipe in its own goroutine. Ceiling: bursts beyond
	// this drop (best-effort, same as the toast contract). Phase 2 raises it.
	instances = 4
	// maxRead bounds how many bytes one connection may send before the relay
	// drops it. The pipe is unauthenticated (documented in THREAT-MODEL.md), so
	// without this a local process that connects and streams without closing
	// grows readUntilClose's buffer forever -> tray OOM (a trivial local DoS).
	// Legit toasts are tiny: title <= ~70 chars ("Sentinel: " + rule name
	// truncated to 60) + body <= ~95 chars (severity + image truncated to 80) +
	// JSON framing ~= 200 bytes total. 64 KiB is ~300x headroom and caps total
	// relay RAM at 4 instances x 64 KiB = 256 KiB. Nothing legit is near it.
	maxRead = 64 * 1024
)

type toastMsg struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	Severity string `json:"severity"` // "critical" => loud looping-alarm (alert.LoudToast); "" / other => silent beeep. Optional: absent in older daemons, treated as non-critical.
}

// notifyFn is the toast call, indirected so the round-trip test can capture
// instead of firing a real toast. Production: notify (below). It routes
// critical-severity toasts to the loud looping-alarm path (alert.LoudToast) and
// everything else to the silent beeep path — mirroring the interactive
// ToastAlerter's tiering so a Session-0 daemon's critical hits stand out too.
// The loud-toast policy is shared (alert.LoudToast) so tuning it updates both
// the interactive and relay paths in one place.
var notifyFn = notify

func notify(title, body, severity string) error {
	if severity == "critical" {
		return alert.LoudToast(title, body)
	}
	return beeep.Notify(title, body, "")
}

func main() {
	// windowsgui process: no console, so log to a file for visibility.
	if f, err := os.OpenFile("sentinel-tray.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(f)
	}
	namePtr, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		log.Fatalf("UTF16 pipe name: %v", err)
	}
	log.Printf("sentinel-tray: listening on %s (%d instances)", pipeName, instances)

	for i := 0; i < instances; i++ {
		go serveInstance(i, namePtr)
	}
	// Block forever; the instances run for the life of the session.
	select {}
}

// serveInstance runs one named-pipe instance in a loop: create, wait for a
// client connect, read one toast, toast, repeat.
func serveInstance(id int, namePtr *uint16) {
	for {
		handleConnection(id, namePtr)
	}
}

// handleConnection services exactly one client connection on a fresh pipe
// instance. Split from serveInstance so the round-trip test can exercise one
// handshake without spinning an infinite loop.
func handleConnection(id int, namePtr *uint16) {
	// PIPE_ACCESS_INBOUND: client->server only. PIPE_TYPE_BYTE + PIPE_WAIT:
	// blocking byte stream (read-until-close). PIPE_UNLIMITED_INSTANCES: the
	// OS hands each client connect to any free instance, so concurrent
	// goroutines don't collide.
	h, err := windows.CreateNamedPipe(
		namePtr,
		windows.PIPE_ACCESS_INBOUND,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		0, 0, 0, nil,
	)
	if err != nil {
		log.Printf("instance %d: CreateNamedPipe: %v", id, err)
		time.Sleep(time.Second)
		return
	}
	// Block until the daemon connects. ERROR_PIPE_CONNECTED (client attached
	// before we called Connect) is benign - fall through and read.
	if err := windows.ConnectNamedPipe(h, nil); err != nil {
		log.Printf("instance %d: ConnectNamedPipe: %v", id, err)
		windows.CloseHandle(h)
		return
	}
	data := readUntilClose(h)
	windows.DisconnectNamedPipe(h)
	windows.CloseHandle(h)
	if data == nil {
		// readUntilClose hit the maxRead cap (unclosed/malicious client) and
		// already logged the drop. Nothing to parse; never notify.
		return
	}

	var msg toastMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("instance %d: bad JSON (%d bytes): %v", id, len(data), err)
		return
	}
	if err := notifyFn(msg.Title, msg.Body, msg.Severity); err != nil {
		log.Printf("instance %d: notify: %v", id, err)
		return
	}
	log.Printf("instance %d: toasted %q", id, msg.Title)
}

// readUntilClose reads a byte-mode pipe until the client closes (ReadFile
// returns ERROR_BROKEN_PIPE or 0 bytes). It returns nil if the client sent more
// than maxRead bytes without closing — the overflow is logged and the caller
// must drop without notifying (no legit toast is anywhere near maxRead). This
// bounds relay memory so an unauthenticated local client cannot OOM the tray
// by streaming forever.
func readUntilClose(h windows.Handle) []byte {
	var buf bytes.Buffer
	chunk := make([]byte, 4096)
	for {
		var n uint32
		err := windows.ReadFile(h, chunk, &n, nil)
		if n > 0 {
			buf.Write(chunk[:n])
		}
		if err != nil || n == 0 {
			break // client closed (broken pipe) or EOF
		}
		if buf.Len() > maxRead {
			log.Printf("instance: toast pipe read exceeded %d-byte cap; dropping (unclosed/malicious client)", maxRead)
			return nil
		}
	}
	return buf.Bytes()
}
