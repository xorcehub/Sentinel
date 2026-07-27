//go:build ignore

// payload-dll.go — unsigned throwaway DLL for the INJECT-002 self-test.
//
// Build (Windows, from repo root):
//
//	go build -buildmode=c-shared -o tests/bin/payload.dll tests/payload-dll.go
//
// Loading this (detection.exe loader <abs path>) makes Sysmon emit EID 7 with
// ImageLoaded under Temp and Signed=false -> INJECT-002. The DLL does nothing:
// it has one no-op export purely so `go build -buildmode=c-shared` produces a
// valid DLL with a DllMain. No network, no filesystem, no threads.
package main

import "C"

// SentinelProbe is the required //export for c-shared; returns a fixed value.
//
//export SentinelProbe
func SentinelProbe() C.int { return 1 }

func main() {}
