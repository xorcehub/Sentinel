// Package sigmaeval is Sentinel's in-house Sigma rule evaluator.
//
// It deliberately does NOT depend on an external Sigma library (see
// docs/02-ARCHITECTURE.md §5). It implements the grammar subset our rules
// actually use (docs/03-RULES.md §2): named selections, the contains/startswith/
// endswith/re/all modifiers, and condition with and/or/not/1 of/all of.
// Unsupported constructs make Load return an error for that rule (the engine
// logs and skips it) — never a panic.
//
// This package does PURE MATCHING (Sigma detection + condition). Allowlist
// `except`, dedup, severity routing and alerting live in the engine layer
// (internal/rules) — they need state and config this package doesn't own.
package sigmaeval

import (
	"fmt"
	"io"
	"strings"

	"sentinel/internal/event"

	"gopkg.in/yaml.v3"
)

// Rule is a compiled Sigma rule (plus its x-sentinel extension).
type Rule struct {
	Title    string
	ID       string // canonical Sigma uuid
	Status   string
	Level    string
	Tags     []string
	FalsePos []string

	// x-sentinel extension (engine behavior). Zero values mean "use default".
	XID        string
	XSeverity  string
	XDedup     string
	XTargetKey string
	XExcept    map[string]string // operator -> set name, e.g. "image_in_allowlist"->"trusted_binaries"
	XAlert     []string
	XNote      string

	condition matcher                         // compiled condition over selMatchers
	selMatch  map[string]func(*event.Event) bool // compiled selections, by name
}

// Match reports whether the Sigma detection+condition match the event.
// (Allowlist `except` is NOT applied here — that's the engine's job.)
func (r *Rule) Match(e *event.Event) bool {
	if r.condition == nil {
		return false
	}
	return r.condition(e)
}

// Load parses one or more YAML documents (--- separated, standard Sigma
// multi-doc) into compiled Rules. A single mapping or a list of mappings are
// both accepted.
func Load(data []byte) ([]*Rule, error) {
	docs, err := decodeDocs(data)
	if err != nil {
		return nil, err
	}
	var rules []*Rule
	for _, d := range docs {
		r, err := compileRule(d)
		if err != nil {
			title, _ := d["title"].(string)
			return nil, fmt.Errorf("rule %q: %w", title, err)
		}
		if r != nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func decodeDocs(data []byte) ([]map[string]interface{}, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var out []map[string]interface{}
	for {
		var m map[string]interface{}
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if m != nil {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no YAML documents")
	}
	return out, nil
}

func compileRule(d map[string]interface{}) (*Rule, error) {
	r := &Rule{selMatch: map[string]func(*event.Event)bool{}}
	r.Title, _ = d["title"].(string)
	r.ID, _ = d["id"].(string)
	r.Status, _ = d["status"].(string)
	r.Level, _ = d["level"].(string)
	r.Tags = toStringSlice(d["tags"])
	r.FalsePos = toStringSlice(d["falsepositives"])

	// x-sentinel extension
	if xs, ok := d["x-sentinel"].(map[string]interface{}); ok {
		r.XID, _ = xs["id"].(string)
		r.XSeverity, _ = xs["severity"].(string)
		r.XDedup, _ = xs["dedup"].(string)
		r.XTargetKey, _ = xs["target_key"].(string)
		r.XNote, _ = xs["note"].(string)
		r.XAlert = toStringSlice(xs["alert"])
		if ex, ok := xs["except"].(map[string]interface{}); ok {
			r.XExcept = map[string]string{}
			for k, v := range ex {
				r.XExcept[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	det, ok := d["detection"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing detection")
	}
	condStr, _ := det["condition"].(string)
	if condStr == "" {
		return nil, fmt.Errorf("missing condition")
	}

	// Compile each named selection (everything in detection except "condition").
	for name, raw := range det {
		if name == "condition" {
			continue
		}
		m, err := buildSelection(raw)
		if err != nil {
			return nil, fmt.Errorf("selection %q: %w", name, err)
		}
		r.selMatch[name] = m
	}

	cond, err := parseCondition(condStr, r.selMatch)
	if err != nil {
		return nil, fmt.Errorf("condition %q: %w", condStr, err)
	}
	r.condition = cond
	return r, nil
}

// buildSelection compiles one Sigma selection. A selection is either a map
// (fields ANDed) or a list of maps (OR of those maps).
func buildSelection(raw interface{}) (func(*event.Event) bool, error) {
	switch v := raw.(type) {
	case map[string]interface{}:
		return buildConjunction(v)
	case []interface{}:
		// list of maps → OR
		var parts []func(*event.Event) bool
		for _, el := range v {
			sub, ok := el.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("list selection element is not a map")
			}
			m, err := buildConjunction(sub)
			if err != nil {
				return nil, err
			}
			parts = append(parts, m)
		}
		return func(e *event.Event) bool {
			for _, p := range parts {
				if p(e) {
					return true
				}
			}
			return false
		}, nil
	default:
		return nil, fmt.Errorf("selection must be a map or list of maps, got %T", raw)
	}
}

// buildConjunction compiles a map selection: all field matchers must match (AND).
func buildConjunction(m map[string]interface{}) (func(*event.Event) bool, error) {
	var parts []func(*event.Event) bool
	for key, raw := range m {
		fm, err := buildFieldMatch(key, raw)
		if err != nil {
			return nil, err
		}
		parts = append(parts, fm)
	}
	return func(e *event.Event) bool {
		for _, p := range parts {
			if !p(e) {
				return false
			}
		}
		return true
	}, nil
}

func toStringSlice(v interface{}) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprintf("%v", e))
		}
		return out
	case string:
		return []string{t}
	default:
		// Scalar: int / int64 / float64 / bool. Sigma field values are
		// frequently bare integers (EventID: 1, DestinationPort: 443) — yaml.v3
		// decodes those as int, not string. Stringify so they match.
		return []string{fmt.Sprintf("%v", t)}
	}
}
