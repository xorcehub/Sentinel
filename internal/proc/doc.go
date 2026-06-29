// Package proc handles process-level concerns for the Sentinel binary:
// primarily single-instance enforcement via a named global mutex.
//
// On Windows a second sentinel.exe instance is detected by attempting to create
// a named mutex (Global\... so it spans sessions of the same user/machine). If
// the mutex already exists, the second instance logs and exits. This prevents
// duplicate alert spam if the launch task fires twice (02-ARCHITECTURE.md §1).
//
// Build-tag split:
//   - mutex_windows.go: real CreateMutexEx implementation.
//   - mutex_other.go:   no-op stub so the rest of the tree compiles & the
//                       mock-driven tests run on non-Windows (Linux dev / CI).
package proc
