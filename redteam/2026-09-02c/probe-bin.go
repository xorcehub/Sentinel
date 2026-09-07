//go:build ignore

// probe-bin.go — round-3 red-team live-fire probe (BENIGN, own box, own rules).
//
// Confirms the custom-binary bypass shapes proven statically in
// custombin_vector_test.go against the RUNNING daemon. Every mode is inert:
// a powershell Write-Host, a loopback 1-byte round trip, or a file write in
// THIS directory that is deleted again. Nothing persists, nothing leaves the
// machine, no file lands outside redteam/2026-09-02c/.
//
// Build (output stays inside this dir):
//
//	go build -o redteam/2026-09-02c/bin/probe.exe redteam/2026-09-02c/probe-bin.go
//
// Modes (EXPECTED column = per the round-3 findings):
//
//	probe.exe gcupiggy    powershell -ep bypass -w h -c "Get-Service -Name 'GCUBridge'; Write-Host probe-ok"
//	                      expect QUIET (F10: dev_scripts marker substring suppresses EXEC-001)
//	probe.exe gcuctl      same cmdline minus the marker
//	                      expect EXEC-001 CRITICAL toast (control)
//	probe.exe nahloop 9080    loopback 1-byte round trip on 127.0.0.1:9080
//	                      with the binary NAMED *nahimic*.exe: expect QUIET (F9);
//	                      with any other name: expect NET-005 CRITICAL toast (control).
//	                      If the real Nahimic owns :9080 the probe connects to it
//	                      and sends ONE junk byte (same plan as round-2 probe).
//	probe.exe nahloop 9081    any name: expect NET-005 CRITICAL toast (C9b control)
//	probe.exe loop6 <port>    listens on 127.0.0.1:<port>, connects via an
//	                      AF_INET6 socket to the v4-mapped address ::ffff:127.0.0.1
//	                      (F12). Expect QUIET if Sysmon renders the mapped
//	                      spelling (grep sentinel.log for "ffff"), NET-005 toast
//	                      if Sysmon normalizes to 127.0.0.1 — either answer is data.
//	probe.exe sentname    writes allowlist.json.probe into the probe's own dir
//	                      (deleted after 6 s). With the binary NAMED sentinel.exe:
//	                      expect QUIET (F11 name-trust). Any other name: expect
//	                      CONFIG-001 CRITICAL toast (control).
//
// Expected desktop effect per full run: 0 toasts for quiet modes, 1 CRITICAL
// toast per control. That is the test working.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	if len(os.Args) < 2 {
		die("usage: probe <gcupiggy|gcuctl|nahloop|loop6|sentname> [port]")
	}
	switch os.Args[1] {
	case "gcupiggy":
		spawnPS("-nop", "-ep", "bypass", "-w", "h", "-c", "Get-Service -Name 'GCUBridge'; Write-Host probe-ok")
	case "gcuctl":
		spawnPS("-nop", "-ep", "bypass", "-w", "h", "-c", "Write-Host probe-ok")
	case "nahloop":
		if len(os.Args) != 3 {
			die("nahloop: need <port>")
		}
		loop(os.Args[2])
	case "loop6":
		if len(os.Args) != 3 {
			die("loop6: need <port>")
		}
		loop6(os.Args[2])
	case "sentname":
		sentname()
	default:
		die("unknown mode %q", os.Args[1])
	}
}

func spawnPS(args ...string) {
	out, err := exec.Command("powershell", args...).CombinedOutput()
	fmt.Printf("powershell %v\n-> exit=%v\n%s\n", args, err, out)
}

// loop: one loopback round trip on 127.0.0.1:<port>. If a listener already
// owns the port (real Nahimic on :9080), connect-only mode: dial, one junk
// byte, close — the EID 3 is what matters.
func loop(port string) {
	addr := net.JoinHostPort("127.0.0.1", port)
	if ln, err := net.Listen("tcp", addr); err == nil {
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
	} else {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			die("connect-only %s: %v", addr, err)
		}
		_, _ = c.Write([]byte{0x7e}) // one junk byte to the legit owner; it ignores it
		c.Close()
		fmt.Println("loop: port busy, connect-only (1 byte to the existing listener)")
	}
	fmt.Println("loop: 1 byte round-tripped on", addr)
}

// loop6 connects to ::ffff:127.0.0.1:<port> over a raw AF_INET6 socket —
// the IPv4-mapped spelling custom binaries would need to produce the F12
// event shape. RESULT (2026-09-02, this probe): Winsock REFUSES connect() to
// a v4-mapped destination with WSAEADDRNOTAVAIL (unlike Linux dual-stack),
// while raw-v4 and native-::1 connects work — i.e. NO user-mode Windows TCP
// connection can carry that dst spelling, so Sysmon can never log it. F12
// stays an engine-semantics gap (pinned by the quiet test row), not a
// reachable live bypass. The diagnostics below reproduce that verdict.
func loop6(port string) {
	// WSAGetLastError is per-thread TLS: pin so connect + error read stay on
	// one OS thread (goroutines migrate between syscall.Calls otherwise).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var portn int
	if _, err := fmt.Sscanf(port, "%d", &portn); err != nil {
		die("loop6: bad port %q", port)
	}
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

	if err := windows.WSAStartup(0x202, &windows.WSAData{}); err != nil {
		die("WSAStartup: %v", err)
	}
	defer windows.WSACleanup()
	s, err := windows.Socket(windows.AF_INET6, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		die("socket(AF_INET6): %v", err)
	}
	defer windows.Closesocket(s)
	fmt.Printf("loop6: socket handle=%v\n", s)

	// sockaddr_in6 { AF_INET6(23), port(BO), flowinfo 0, ::ffff:127.0.0.1, 0 }
	var sa [28]byte
	sa[0], sa[1] = 23, 0 // AF_INET6, little-endian
	sa[2], sa[3] = byte(portn>>8), byte(portn)
	sa[8+10], sa[8+11] = 0xff, 0xff // v4-mapped prefix
	sa[8+12], sa[8+13], sa[8+14], sa[8+15] = 127, 0, 0, 1

	var modws2_32 = windows.NewLazySystemDLL("ws2_32.dll")
	connect := modws2_32.NewProc("connect")
	wsaGetLast := modws2_32.NewProc("WSAGetLastError")

	// Diagnostics: raw AF_INET connect to 127.0.0.1 (does raw connect work at
	// all?) and AF_INET6 connect to ::1 (is the v6 stack usable?), then the
	// v4-mapped attempt.
	tryRawConnect := func(af int, sa []byte, what string) {
		s2, err := windows.Socket(af, windows.SOCK_STREAM, windows.IPPROTO_TCP)
		if err != nil {
			fmt.Printf("loop6: %s: socket: %v\n", what, err)
			return
		}
		defer windows.Closesocket(s2)
		r, _, callErr := connect.Call(uintptr(s2), uintptr(unsafe.Pointer(&sa[0])), uintptr(len(sa)))
		werr, _, _ := wsaGetLast.Call()
		fmt.Printf("loop6: %s: connect r1=%d callErr=%v wsaErr=%d\n", what, r, callErr, werr)
	}
	var sa4 [16]byte
	sa4[0], sa4[1] = 2, 0 // AF_INET
	sa4[2], sa4[3] = byte(portn>>8), byte(portn)
	sa4[4], sa4[5], sa4[6], sa4[7] = 127, 0, 0, 1
	tryRawConnect(windows.AF_INET, sa4[:], "raw-v4 (baseline: must succeed)")

	var sa6n [28]byte // ::1 native (v6 stack sanity: expect refused — listener is v4)
	sa6n[0], sa6n[1] = 23, 0
	sa6n[2], sa6n[3] = byte(portn>>8), byte(portn)
	sa6n[8+15] = 1
	tryRawConnect(windows.AF_INET6, sa6n[:], "raw-v6-::1")

	r1, _, callErr := connect.Call(uintptr(s), uintptr(unsafe.Pointer(&sa[0])), 28)
	if r1 != 0 {
		fmt.Printf("loop6: VERDICT: connect(::ffff:127.0.0.1) refused by Winsock (%v) — "+
			"the v4-mapped dst spelling is NOT producible by any user-mode TCP connect "+
			"on Windows, so F12 is not reachable live (engine-semantics gap only).\n", callErr)
		return
	}
	send := modws2_32.NewProc("send")
	buf := []byte{0x7e}
	r2, _, _ := send.Call(uintptr(s), uintptr(unsafe.Pointer(&buf[0])), 1, 0)
	if int32(r2) == -1 {
		die("send: ws2_32 send failed")
	}
	if err := <-done; err != nil {
		die("accept: %v", err)
	}
	fmt.Println("loop6: 1 byte round-tripped via ::ffff:127.0.0.1 on", addr)
	fmt.Println("loop6: now grep sentinel.log for 'ffff' — mapped spelling = F12 live-confirmed")
}

// sentname writes a file whose name contains 'allowlist.json' next to the
// probe, then deletes it. CONFIG-001 keys on that name; only the writer's
// IMAGE NAME (sentinel.exe vs anything else) decides whether it is seen.
func sentname() {
	p := filepath.Join(mustSelfDir(), "allowlist.json.probe")
	if err := os.WriteFile(p, []byte("benign round-3 redteam artifact (deleted)\n"), 0o600); err != nil {
		die("write %s: %v", p, err)
	}
	base := filepath.Base(os.Args[0])
	fmt.Printf("sentname: wrote %s as %q — expect %s\n", p, base,
		quietOrToast(base))
	time.Sleep(6 * time.Second)
	os.Remove(p)
	fmt.Println("sentname: artifact deleted")
}

func quietOrToast(base string) string {
	if strings.HasPrefix(strings.ToLower(base), "sentinel") {
		return "QUIET (F11: \\sentinel.exe name-trust)"
	}
	return "CONFIG-001 CRITICAL toast (control)"
}

func mustSelfDir() string {
	d, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		die("selfdir: %v", err)
	}
	return d
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "probe: "+format+"\n", args...)
	os.Exit(1)
}
