package sigmaeval

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"sentinel/internal/event"
)

// matcher is a compiled predicate over an Event.
type matcher func(*event.Event) bool

// buildFieldMatch compiles one Sigma field matcher of the form
// "Field", "Field|modifier", or "Field|m1|m2" (e.g. "CommandLine|contains|all").
// The value may be a scalar or a list. A list means OR (any), unless the
// modifier chain includes "all" (then every item must match = AND).
func buildFieldMatch(key string, raw interface{}) (func(*event.Event) bool, error) {
	parts := strings.Split(key, "|")
	field := parts[0]
	mods := parts[1:]
	if field == "" {
		return nil, fmt.Errorf("empty field name in %q", key)
	}

	values := toStringSlice(raw)
	if len(values) == 0 {
		return nil, fmt.Errorf("field %q has no value", key)
	}

	all := contains(mods, "all")
	op := "" // last non-"all" modifier wins
	for _, m := range mods {
		if m == "all" {
			continue
		}
		// Unknown modifier = rule-author error (typo or unsupported construct).
		// Failing the rule beats silently degrading to equality matching: a
		// quiet semantic change is a false-negative factory in a detection
		// engine. (Package doc: unsupported constructs make Load return an
		// error.) Known set mirrors the matchOne switch below.
		if !knownModifiers[m] {
			return nil, fmt.Errorf("unknown modifier %q in field %q (supported: contains, startswith, beginswith, endswith, re, all)", m, key)
		}
		op = m
	}

	// Precompile regexes once (docs: "compile-once, cache").
	var res []*regexp.Regexp
	if op == "re" {
		res = make([]*regexp.Regexp, 0, len(values))
		for _, v := range values {
			re, err := regexp.Compile("(?i)" + v) // case-insensitive by default
			if err != nil {
				return nil, fmt.Errorf("bad regex %q: %w", v, err)
			}
			res = append(res, re)
		}
	}

	return func(e *event.Event) bool {
		fv, ok := e.Field(field)
		if !ok || fv == "" {
			// Field absent → nothing in this matcher can be satisfied. For a
			// NOT-wrapped filter this yields the correct "filter doesn't match".
			return false
		}
		matchOne := func(i int, v string) bool {
			switch op {
			case "contains":
				return strings.Contains(strings.ToLower(fv), strings.ToLower(v))
			case "startswith", "beginswith":
				return strings.HasPrefix(strings.ToLower(fv), strings.ToLower(v))
			case "endswith":
				return strings.HasSuffix(strings.ToLower(fv), strings.ToLower(v))
			case "re":
				return res[i].MatchString(fv)
			default: // bare equality, case-insensitive (Sigma Windows convention)
				return strings.EqualFold(fv, v)
			}
		}
		if all {
			for i, v := range values {
				if !matchOne(i, v) {
					return false
				}
			}
			return true
		}
		for i, v := range values {
			if matchOne(i, v) {
				return true
			}
		}
		return false
	}, nil
}

// knownModifiers is the supported Sigma field-modifier set (docs/03-RULES.md
// §2). Anything else fails compilation — see buildFieldMatch.
var knownModifiers = map[string]bool{
	"contains":   true,
	"startswith": true,
	"beginswith": true,
	"endswith":   true,
	"re":         true,
}

func contains(s []string, t string) bool {
	for _, v := range s {
		if v == t {
			return true
		}
	}
	return false
}

// ---- condition grammar ----
//
//	expr   := andExpr ('or' andExpr)*
//	andExpr:= unary ('and' unary)*
//	unary  := 'not' unary | atom
//	atom   := '(' expr ')' | quant 'of' name | name
//	quant  := <int> | 'all'
//
// Names refer to compiled selections in sel. A name with a trailing '*' is a
// wildcard (prefix match) usable with the `of` quantifier ("1 of selection_*").
func parseCondition(cond string, sel map[string]func(*event.Event) bool) (matcher, error) {
	toks, err := tokenize(cond)
	if err != nil {
		return nil, err
	}
	p := &cparser{toks: toks, sel: sel}
	m, err := p.expr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected trailing tokens: %q", strings.Join(p.toks[p.pos:], " "))
	}
	return m, nil
}

func tokenize(s string) ([]string, error) {
	var toks []string
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(' || c == ')':
			toks = append(toks, string(c))
			i++
		default:
			j := i
			for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '\n' && s[j] != '(' && s[j] != ')' {
				j++
			}
			toks = append(toks, s[i:j])
			i = j
		}
	}
	return toks, nil
}

type cparser struct {
	toks []string
	pos  int
	sel  map[string]func(*event.Event) bool
}

func (p *cparser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}
func (p *cparser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *cparser) expr() (matcher, error) {
	m, err := p.andExpr()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.next()
		r, err := p.andExpr()
		if err != nil {
			return nil, err
		}
		l := m
		m = func(e *event.Event) bool { return l(e) || r(e) }
	}
	return m, nil
}

func (p *cparser) andExpr() (matcher, error) {
	m, err := p.unary()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.next()
		r, err := p.unary()
		if err != nil {
			return nil, err
		}
		l := m
		m = func(e *event.Event) bool { return l(e) && r(e) }
	}
	return m, nil
}

func (p *cparser) unary() (matcher, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.next()
		m, err := p.unary()
		if err != nil {
			return nil, err
		}
		return func(e *event.Event) bool { return !m(e) }, nil
	}
	return p.atom()
}

func (p *cparser) atom() (matcher, error) {
	t := p.peek()
	if t == "" {
		return nil, fmt.Errorf("unexpected end of condition")
	}
	if t == "(" {
		p.next()
		m, err := p.expr()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, fmt.Errorf("expected ')'")
		}
		return m, nil
	}
	// quantifier form: "<n> of <name>" or "all of <name>"
	if p.pos+1 < len(p.toks) && strings.EqualFold(p.toks[p.pos+1], "of") {
		quant := p.next()
		p.next() // consume "of"
		name := p.next()
		return p.quantMatcher(quant, name)
	}
	name := p.next()
	fn, ok := p.sel[name]
	if !ok {
		return nil, fmt.Errorf("unknown selection %q", name)
	}
	return fn, nil
}

func (p *cparser) quantMatcher(quant, name string) (matcher, error) {
	var sels []func(*event.Event) bool
	if strings.HasSuffix(name, "*") {
		prefix := strings.TrimSuffix(name, "*")
		for n, fn := range p.sel {
			if strings.HasPrefix(n, prefix) {
				sels = append(sels, fn)
			}
		}
	} else {
		fn, ok := p.sel[name]
		if !ok {
			return nil, fmt.Errorf("unknown selection %q in quantifier", name)
		}
		sels = append(sels, fn)
	}
	if strings.EqualFold(quant, "all") {
		return func(e *event.Event) bool {
			for _, fn := range sels {
				if !fn(e) {
					return false
				}
			}
			return len(sels) > 0
		}, nil
	}
	n, err := strconv.Atoi(quant)
	if err != nil {
		return nil, fmt.Errorf("bad quantifier %q (expected int or 'all')", quant)
	}
	return func(e *event.Event) bool {
		c := 0
		for _, fn := range sels {
			if fn(e) {
				c++
			}
		}
		return c >= n
	}, nil
}
