//go:build windows

package proc

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
)

// Acquire creates a global named mutex. Returns owned=true with a release
// function to close the handle on shutdown; owned=false (nil release) if another
// instance already holds the mutex — the caller should log and exit.
//
// CreateMutexEx semantics: on success the handle is valid; if the named mutex
// already existed, GetLastError returns ERROR_ALREADY_EXISTS (183) while still
// returning a valid handle to the existing object. We treat that as "already
// running" and close our duplicate handle.
//
// Note: CreateMutexEx takes a *uint16 (wide string), not a Go string —
// UTF16PtrFromString does the conversion.
func Acquire(name string) (owned bool, release func(), err error) {
	if name == "" {
		return false, nil, fmt.Errorf("proc.Acquire: empty mutex name")
	}
	nameW, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, nil, fmt.Errorf("mutex name to utf16: %w", err)
	}

	// flags: CREATE_MUTEX_INITIAL_OWNER (0x1) — take immediate ownership.
	// desiredAccess: SYNCHRONIZE (0x00100000) is sufficient to hold the mutex.
	const (
		createMutexInitialOwner = 0x1
		synchronizeAccess       = 0x00100000
	)
	h, cerr := windows.CreateMutexEx(nil, nameW, createMutexInitialOwner, synchronizeAccess)
	if cerr != nil && !errors.Is(cerr, windows.ERROR_ALREADY_EXISTS) {
		return false, nil, fmt.Errorf("CreateMutexEx: %w", cerr)
	}
	if h == 0 {
		return false, nil, fmt.Errorf("CreateMutexEx returned null handle")
	}
	if errors.Is(cerr, windows.ERROR_ALREADY_EXISTS) {
		// Another instance owns it. Close our duplicate and bow out.
		_ = windows.CloseHandle(h)
		return false, nil, nil
	}
	return true, func() { _ = windows.CloseHandle(h) }, nil
}
