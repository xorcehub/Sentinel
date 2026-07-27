//go:build ignore

// detection-bin.go — Sentinel detection-test probe (multi-mode).
//
// This is a HARMLESS test harness for the operator's OWN Sentinel rules on
// their OWN box. It is NOT operational tooling, NOT a real implant, and does
// nothing destructive: every mode prints a marker and exits, or makes a single
// throwaway connection/load. It exists only to make Sysmon emit the events that
// the Sentinel rules key on, so the operator can confirm each rule fires.
//
// Build (Windows, from repo root):
//
//	go build -o tests/bin/detection.exe tests/detection-bin.go
//
// Run modes (see tests/Invoke-DetectionTests.ps1 for the orchestration that
// copies/renames this binary to the paths the rules expect):
//
//	detection.exe dropper                      write %TEMP%\sentinel-test.marker, exit 0
//	detection.exe connect <host> <port>        open TCP, send 1 byte, close  (NET-004/005)
//	detection.exe loader <dll-abs-path>        LoadLibraryW the DLL, sleep, exit  (INJECT-002)
//	detection.exe inject <pid>                 CreateRemoteThread(ExitThread) into <pid>  (INJECT-001)
//	detection.exe lsass                        OpenProcess(lsass, VM_READ), close at once  (CRED-002)
//
// inject / lsass need elevation; the driver gates them behind -IncludeDangerous.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: detection <dropper|connect|loader|inject|lsass> [args]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "dropper":
		dropper()
	case "connect":
		if len(os.Args) != 4 {
			die("connect: need <host> <port>")
		}
		connect(os.Args[2], os.Args[3])
	case "loader":
		if len(os.Args) != 3 {
			die("loader: need <dll-abs-path>")
		}
		loader(os.Args[2])
	case "inject":
		if len(os.Args) != 3 {
			die("inject: need <pid>")
		}
		inject(parsePID(os.Args[2]))
	case "lsass":
		lsass()
	default:
		die("unknown mode %q", os.Args[1])
	}
}

// dropper: write a marker file to %TEMP% and exit. When copied to a hex/GUID
// name under Temp/AppData/ProgramData and run, its process Image satisfies
// EXEC-004's regex and NET-004's "Temp/AppData/ProgramData" image clause.
func dropper() {
	tmp := os.Getenv("TEMP")
	if tmp == "" {
		tmp = "."
	}
	marker := tmp + `\sentinel-test.marker`
	if err := os.WriteFile(marker, []byte("sentinel detection self-test probe\n"), 0644); err != nil {
		die("dropper: write marker: %v", err)
	}
	fmt.Println("dropper: wrote", marker)
}

// connect: one TCP connect + one byte + close. From a Temp/AppData image this
// fires NET-004 (Temp/AppData image outbound) and, if dst is loopback to a
// non-baseline listener, NET-005 too. Point at 127.0.0.1:<discard> to avoid
// any real egress.
func connect(host, port string) {
	addr := net.JoinHostPort(host, port)
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		// A failed dial still produced an EID 3 attempt in many configs; report
		// and exit cleanly rather than crashing the harness.
		fmt.Fprintf(os.Stderr, "connect: dial %s failed (ok for a probe): %v\n", addr, err)
		return
	}
	defer c.Close()
	_, _ = c.Write([]byte{0x7e})
	fmt.Println("connect: sent probe byte to", addr)
}

// loader: LoadLibrary a DLL by absolute path. With an unsigned DLL in Temp
// this triggers EID 7 (ImageLoaded in Temp, Signed=false) -> INJECT-002.
func loader(dll string) {
	h, err := windows.LoadLibrary(dll)
	if err != nil {
		die("loader: LoadLibrary %s: %v", dll, err)
	}
	defer windows.FreeLibrary(h)
	time.Sleep(500 * time.Millisecond) // let Sysmon flush the EID 7
	fmt.Println("loader: loaded", dll)
}

// inject: CreateRemoteThread into a foreign PID with StartAddress=kernel32
//!ExitThread, lpParameter=0. The remote thread immediately exits; the victim
// process keeps running. This is the textbook EID 8 trigger for INJECT-001
// without actually executing attacker logic. Needs elevation + a victim PID.
func inject(pid uint32) {
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	procExitThread := k32.NewProc("ExitThread")
	procCreateRemoteThread := k32.NewProc("CreateRemoteThread")

	h, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_OPERATION,
		false, pid)
	if err != nil {
		die("inject: OpenProcess %d: %v", pid, err)
	}
	defer windows.CloseHandle(h)

	// ExitThread's address resolves identically in the target (kernel32 base is
	// constant per boot). lpParameter 0 -> the remote thread calls ExitThread(0).
	r1, _, e := procCreateRemoteThread.Call(
		uintptr(h), 0, 0,
		procExitThread.Addr(),
		0, 0, 0)
	if r1 == 0 {
		die("inject: CreateRemoteThread: %v", e)
	}
	windows.CloseHandle(windows.Handle(r1))
	fmt.Printf("inject: remote thread spawned+exited in pid %d (ExitThread)\n", pid)
}

// lsass: locate lsass.exe and OpenProcess it with a read-only access mask, then
// close the handle immediately. Emits EID 10 (TargetImage=...\lsass.exe) ->
// CRED-002. Reads NOTHING. Needs elevation; Defender may also flag it.
func lsass() {
	pid, ok := findPID("lsass.exe")
	if !ok {
		die("lsass: lsass.exe not found")
	}
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		die("lsass: OpenProcess %d: %v", pid, err)
	}
	windows.CloseHandle(h)
	fmt.Printf("lsass: opened+closed lsass.exe (pid %d), read nothing\n", pid)
}

// findPID walks the toolhelp snapshot for the first match of name (lowercased).
func findPID(name string) (uint32, bool) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return 0, false
	}
	for {
		if eqLower(windows.UTF16ToString(e.ExeFile[:]), name) {
			return e.ProcessID, true
		}
		if err := windows.Process32Next(snap, &e); err != nil {
			return 0, false
		}
	}
}

func eqLower(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func parsePID(s string) uint32 {
	var n uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			die("inject: pid must be numeric, got %q", s)
		}
		n = n*10 + uint32(c-'0')
	}
	if n == 0 {
		die("inject: pid 0 is invalid")
	}
	return n
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "detection: "+format+"\n", args...)
	os.Exit(1)
}
