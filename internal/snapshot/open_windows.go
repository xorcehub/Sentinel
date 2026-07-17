//go:build windows

package snapshot

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// openForCopy opens path for reading with FULL share access (READ|WRITE|DELETE)
// so a file the creator is still writing or holding (e.g. Cursor mid-write to
// its ps-script bootstrap) can still be read. os.Open would request only
// FILE_SHARE_READ and fail with a sharing violation against a held writer —
// the exact failure that makes manual copy lose the race. Returns an
// io.ReadCloser the caller must Close.
func openForCopy(path string) (io.ReadCloser, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// isNotExist reports whether err means the file is gone (already deleted — the
// lost-race case). On Windows, CreateFile returns a windows.Errno.
func isNotExist(err error) bool {
	var errno windows.Errno
	if errors.As(err, &errno) {
		return errno == windows.ERROR_FILE_NOT_FOUND || errno == windows.ERROR_PATH_NOT_FOUND
	}
	return os.IsNotExist(err)
}
