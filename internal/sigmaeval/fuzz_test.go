package sigmaeval

import "testing"

// FuzzLoad hunts panics and hangs in the Sigma rule compilation path
// (yaml.Decode → compileRule → buildSelection → parseCondition → regexp.Compile).
//
// Rules are operator-trusted input (threat-model §7), so this is defense-in-
// depth. The genuine panic surface is compileRule + buildSelection +
// parseCondition (in-house, type-asserting over yaml.Unmarshal's
// map[string]interface{}); yaml.v3 and regexp return errors, not panics.
//
// Run on the host:
//
//	go test -fuzz=FuzzLoad -fuzztime=5m ./internal/sigmaeval/
func FuzzLoad(f *testing.F) {
	// Seeds: a complete valid Sigma rule + degenerate YAML the fuzzer mutates.
	// Type-confusion (a string field given a nested map, a list where a scalar
	// is expected) is the historically bug-prone edge in compileRule.
	f.Add([]byte(completeRuleSeed))
	f.Add([]byte(minimalRuleSeed))
	f.Add([]byte(""))
	f.Add([]byte("---\n"))
	f.Add([]byte("title: x\ndetection: not-a-map\n"))
	f.Add([]byte("title: x\ndetection:\n  selection: 123\n  condition: selection\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// No correctness oracle: malformed YAML may return an error or partial
		// rules, both fine. The invariant is "never panic."
		_, _ = Load(data)
	})
}

const completeRuleSeed = `title: Executable written to Startup folder
id: 7b3c1d2e-1234-5678-9abc-def012345678
status: experimental
logsource: { product: windows, service: sysmon }
detection:
  selection:
    EventID: 11
    TargetFilename|contains: '\Start Menu\Programs\Startup'
  condition: selection
level: high
tags: [attack.persistence, attack.t1547.001]
x-sentinel:
  id: PERSIST-004
  severity: critical
  alert: [popup, toast, log, eventlog]
`

const minimalRuleSeed = `title: minimal
detection:
  selection:
    EventID: 1
  condition: selection
`
