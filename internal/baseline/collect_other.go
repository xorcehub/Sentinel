//go:build !windows

package baseline

import (
	"context"
	"fmt"
	"log/slog"
)

// Capture is Windows-only (it shells out to autorunsc64.exe). On non-Windows it
// returns an error so the symbol resolves for main.go's --baseline-* paths
// without breaking the Linux build/CI. The diff engine (Parse/Diff) is portable
// and tested; only the collector needs Windows.
func Capture(ctx context.Context, autorunscPath string, log *slog.Logger) ([]byte, error) {
	return nil, fmt.Errorf("baseline capture requires Windows (autorunsc64.exe)")
}
