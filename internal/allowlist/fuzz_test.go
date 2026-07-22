package allowlist

import "testing"

// FuzzCompile hunts panics and hangs in the allowlist compile path
// (stripJSONC → json.Decode → regexp.Compile → net.ParseCIDR → compileFilter).
//
// The allowlist is operator-trusted input (threat-model §7: anyone who can
// write the repo dir already has user-level code execution), so this is
// defense-in-depth, not a primary control like the sysmonxml fuzzer. The
// genuine panic surface is stripJSONC (hand-written byte-level state machine)
// and compileFilter (in-house); the rest wraps stdlib calls that return errors.
//
// Run on the host:
//
//	go test -fuzz=FuzzCompile -fuzztime=5m ./internal/allowlist/
func FuzzCompile(f *testing.F) {
	// Seeds: the real sampleJSONC fixture + degenerate inputs the fuzzer
	// mutates. JSONC comment placement and trailing-backslash regex patterns
	// are the historically bug-prone edges.
	f.Add([]byte(sampleJSONC))
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("// comment\n{}"))
	f.Add([]byte(`{"trusted_binaries":{"path":["[bad((("]}}`))
	f.Add([]byte(`{"event_log_filter":[{"image":"[unterminated("}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Full Load path minus the file read. Exercises stripJSONC + Compile.
		// No correctness oracle: a malformed input may return an error or a
		// partial Allowlist, both fine. The invariant is "never panic."
		_, _ = Compile(stripJSONC(data))
	})
}
