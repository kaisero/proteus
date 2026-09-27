package resolve

import (
	"fmt"
	"sort"
	"strings"
)

// TagFilter is a parsed dynamic address group filter.
//
// PAN-OS writes one as a boolean expression over quoted tags, for example
// 'branch' and not 'decommissioned'. and binds tighter than or, and parentheses
// group.
type TagFilter struct {
	root filterNode
	raw  string
}

// String returns the filter as written.
func (f *TagFilter) String() string { return f.raw }

// Match reports whether an object carrying these tags belongs to the group.
func (f *TagFilter) Match(tags []string) bool {
	if f == nil || f.root == nil {
		return false
	}
	have := make(map[string]bool, len(tags))
	for _, t := range tags {
		have[t] = true
	}
	return f.root.eval(have)
}

// Tags returns every tag the filter names, sorted. An index uses this to know
// which tags are worth tracking.
func (f *TagFilter) Tags() []string {
	if f == nil || f.root == nil {
		return nil
	}
	seen := map[string]bool{}
	f.root.tags(seen)
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

type filterNode interface {
	eval(map[string]bool) bool
	tags(map[string]bool)
}

type tagNode string

func (t tagNode) eval(have map[string]bool) bool { return have[string(t)] }
func (t tagNode) tags(into map[string]bool)      { into[string(t)] = true }

type notNode struct{ inner filterNode }

func (n notNode) eval(have map[string]bool) bool { return !n.inner.eval(have) }
func (n notNode) tags(into map[string]bool)      { n.inner.tags(into) }

type andNode struct{ left, right filterNode }

func (a andNode) eval(have map[string]bool) bool {
	return a.left.eval(have) && a.right.eval(have)
}
func (a andNode) tags(into map[string]bool) { a.left.tags(into); a.right.tags(into) }

type orNode struct{ left, right filterNode }

func (o orNode) eval(have map[string]bool) bool {
	return o.left.eval(have) || o.right.eval(have)
}
func (o orNode) tags(into map[string]bool) { o.left.tags(into); o.right.tags(into) }

// ParseTagFilter parses a dynamic address group filter.
//
// Anything it does not recognise is an error rather than a guess, because a
// mis-read filter puts objects in a group that PAN-OS would leave out.
func ParseTagFilter(raw string) (*TagFilter, error) {
	toks, err := lexFilter(raw)
	if err != nil {
		return nil, err
	}
	p := &filterParser{toks: toks}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("resolve: trailing %q in filter %q", p.toks[p.pos], raw)
	}
	return &TagFilter{root: node, raw: strings.TrimSpace(raw)}, nil
}

// lexFilter splits a filter into quoted tags, operators and parentheses.
func lexFilter(raw string) ([]string, error) {
	var out []string
	for i := 0; i < len(raw); {
		switch c := raw[i]; c {
		case ' ', '\t', '\n', '\r':
			i++
		case '(', ')':
			out = append(out, string(c))
			i++
		case '\'':
			end := strings.IndexByte(raw[i+1:], '\'')
			if end < 0 {
				return nil, fmt.Errorf("resolve: unterminated tag in filter %q", raw)
			}
			out = append(out, raw[i:i+end+2]) // keep the quotes, so a tag is never an operator
			i += end + 2
		default:
			j := i
			for j < len(raw) && !strings.ContainsRune(" \t\n\r()'", rune(raw[j])) {
				j++
			}
			word := strings.ToLower(raw[i:j])
			switch word {
			case "and", "or", "not":
				out = append(out, word)
			default:
				return nil, fmt.Errorf("resolve: unexpected %q in filter %q", raw[i:j], raw)
			}
			i = j
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("resolve: empty filter")
	}
	return out, nil
}

type filterParser struct {
	toks []string
	pos  int
}

func (p *filterParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *filterParser) parseOr() (filterNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}
	return left, nil
}

func (p *filterParser) parseAnd() (filterNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.pos++
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = andNode{left, right}
	}
	return left, nil
}

func (p *filterParser) parseUnary() (filterNode, error) {
	if p.peek() == "not" {
		p.pos++
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{inner}, nil
	}
	return p.parseAtom()
}

func (p *filterParser) parseAtom() (filterNode, error) {
	tok := p.peek()
	switch {
	case tok == "":
		return nil, fmt.Errorf("resolve: filter ended early")
	case tok == "(":
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("resolve: unclosed parenthesis in filter")
		}
		p.pos++
		return inner, nil
	case strings.HasPrefix(tok, "'"):
		p.pos++
		return tagNode(strings.Trim(tok, "'")), nil
	default:
		return nil, fmt.Errorf("resolve: expected a tag, got %q", tok)
	}
}
