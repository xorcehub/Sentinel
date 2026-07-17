//go:build !windows

package snapshot

import (
	"io"
	"os"
)

// openForCopy opens path for reading. On non-Windows (tests, dev), the plain
// os.Open semantics suffice — there is no Windows share-mode concept, and a
// file held open by another process can still be read. The Windows build
// (open_windows.go) uses CreateFile with full share access to win the race
// against a creator still holding the write handle.
func openForCopy(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

// isNotExist reports whether err means the file is gone (already deleted — the
// lost-race case).
func isNotExist(err error) bool {
	return os.IsNotExist(err)
}
