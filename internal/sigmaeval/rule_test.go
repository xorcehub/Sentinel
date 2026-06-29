package sigmaeval

import "testing"

// TestScalarIntFieldValue is the regression for the YAML-loading bug that broke
// every rule in the first host compile: `EventID: 1` (bare int) decoded to
// Go int, and toStringSlice returned nil for it -> "field has no value" at load
// time. Cover int, int64, float64, bool, list-of-int, and string.
func TestScalarIntFieldValue(t *testing.T) {
	cases := []struct{ name string; want []string }{
		{"int", []string{"1"}},
		{"int64", []string{"7"}},
		{"float64", []string{"443"}},
		{"bool", []string{"true"}},
		{"string", []string{"hello"}},
		{"list", []string{"11", "23"}},
		{"nil", nil},
	}
	for _, c := range cases {
		var in interface{}
		switch c.name {
		case "int":
			in = 1
		case "int64":
			in = int64(7)
		case "float64":
			in = 443.0
		case "bool":
			in = true
		case "string":
			in = "hello"
		case "list":
			in = []interface{}{11, 23}
		case "nil":
			in = nil
		}
		got := toStringSlice(in)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v (len %d), want %v (len %d)", c.name, got, len(got), c.want, len(c.want))
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s [%d]: got %q want %q", c.name, i, got[i], c.want[i])
			}
		}
	}
}

// TestRuleWithBareIntEventIDLoads confirms end-to-end that a rule using
// `EventID: 1` (not the list form) loads without error.
func TestRuleWithBareIntEventIDLoads(t *testing.T) {
	const yaml = `
title: bare int EventID
id: 22222222-2222-2222-2222-222222222222
detection:
  selection:
    EventID: 1
    Image|endswith: '\x.exe'
  condition: selection
level: low
`
	rules, err := Load([]byte(yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
}
