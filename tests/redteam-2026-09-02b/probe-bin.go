//go:build ignore

// probe-bin.go — round-2 red-team live-fire probe (BENIGN, own box, own rules).
//
// Every mode is inert: it runs a harmless powershell echo or loops one TCP
// byte back to itself. It exists only to make Sysmon emit real events for the
// bypass shapes proven statically in evasion_vector_test.go, so you can confirm
// the running daemon agrees with the in-process engine result.
//
// Build (output stays inside this dir):
//
//	go build -o tests/redteam-2026-09-02b/bin/probe.exe tests/redteam-2026-09-02b/probe-bin.go
//
// Modes:
//
//	probe.exe bypassps        spawn `powershell -nop -ep b -c Write-Host ok`      expect: QUIET (F1)
//	probe.exe bypassps-full   spawn `powershell -nop -ep bypass -c Write-Host ok` expect: EXEC-001 CRITICAL toast (control C1)
//	probe.exe loopctl <port>  listen on 127.0.0.1:<port>, dial it, close          expect: QUIET on 9080 (F8b), NET-005 CRITICAL on 9081 (control C8)
//
// Expected desktop effect per run: 0 toasts for the quiet modes, 1 CRITICAL
// toast per control. That is the test working.
//
// Nothing here persists, writes outside this repo, or leaves the machine: the
// only network traffic is one byte to 127.0.0.1.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		die("usage: probe <bypassps|bypassps-full|loopctl> [port]")
	}
	switch os.Args[1] {
	case "bypassps":
		spawnPS("-nop", "-ep", "b", "-c", "Write-Host probe-ok")
	case "bypassps-full":
		spawnPS("-nop", "-ep", "bypass", "-c", "Write-Host probe-ok")
	case "loopctl":
		if len(os.Args) != 3 {
			die("loopctl: need <port>")
		}
		loop(os.Args[2])
	default:
		die("unknown mode %q", os.Args[1])
	}
}

// spawnPS runs powershell with args, waiting so the child's EID 1 carries this
// process (a repo-path image) as ParentImage.
func spawnPS(args ...string) {
	out, err := exec.Command("powershell", args...).CombinedOutput()
	fmt.Printf("powershell %v\n-> exit=%v\n%s\n", args, err, out)
}

// loopctl: one self-contained loopback round trip on the given port. EID 3
// fires on the client half; NET-005 keys the destination, so :9080 (the
// known_loopback_listeners entry) must be quiet and any other port fires.
func loop(port string) {
	addr := net.JoinHostPort("127.0.0.1", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		die("listen %s: %v", addr, err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
		c.Close()
		done <- nil
	}()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		die("dial %s: %v", addr, err)
	}
	_, _ = c.Write([]byte{0x7e})
	c.Close()
	if err := <-done; err != nil {
		die("accept: %v", err)
	}
	fmt.Println("loopctl: 1 byte round-tripped on", addr)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "probe: "+format+"\n", args...)
	os.Exit(1)
}
