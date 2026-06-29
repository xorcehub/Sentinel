//go:build !windows

package proc

// Acquire is a no-op on non-Windows so the skeleton (mock-driven tests, Linux
// dev, CI) compiles and runs. On the target (Windows) build, mutex_windows.go
// provides the real CreateMutexEx enforcement.
func Acquire(name string) (owned bool, release func(), err error) {
	return true, func() {}, nil
}
