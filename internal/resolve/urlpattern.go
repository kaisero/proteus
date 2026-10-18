package resolve

import (
	"fmt"
	"strings"
)

// URLPattern is one member of a custom URL category, parsed into tokens.
//
// PAN-OS matches a URL by tokens, not by substring, and the difference decides
// correctness: "wildcard-example.com.evil.net" contains "wildcard-example.com" but
// the device does not match it.
type URLPattern struct {
	raw  string
	host []urlToken
	path []urlToken
}

// urlToken is one token of a pattern. Exactly one of the three forms applies.
type urlToken struct {
	text   string // a literal token
	star   bool   // "*": one or more tokens
	carets int    // "^" repeated: that many tokens, no more and no fewer
}

// Raw returns the member as the configuration spells it.
func (p URLPattern) Raw() string { return p.raw }

// ParseURLPattern reads one custom URL category member.
//
// The syntax rules are taken from a firewall, not from documentation. The validator
// runs when a member is set, so each form below was offered to a real device and its
// verdict recorded:
//
//	*.example.com          accept    one asterisk, owning a whole token
//	^.example.com          accept    one caret, owning a whole token
//	^^.example.com         accept    carets may repeat
//	example.com/*          accept    a wildcard is legal in a path token
//	https://example.com/x  accept    a scheme is not a syntax error
//	EXAMPLE.com            accept    case is not rejected
//	mail*.example.com      reject    an asterisk must own its whole token
//	**.example.com         reject    adjacent asterisks
//	*.*.example.com        reject    at most one asterisk, even non-adjacent
//
// The last one matters. The device always prints "Consecutive asterisks (*) … is not
// supported", but "*.*.example.com" has no adjacent asterisks and is refused anyway:
// the rule is one asterisk per pattern, while carets may repeat.
func ParseURLPattern(member string) (URLPattern, error) {
	raw := strings.TrimSpace(member)
	if raw == "" {
		return URLPattern{}, fmt.Errorf("empty url category member")
	}
	hostPart, pathPart := splitURL(raw)
	p := URLPattern{raw: raw}
	stars := 0
	var err error
	if p.host, err = parseTokens(hostPart, ".", raw, &stars); err != nil {
		return URLPattern{}, err
	}
	if p.path, err = parseTokens(pathPart, "/", raw, &stars); err != nil {
		return URLPattern{}, err
	}
	if len(p.host) == 0 {
		return URLPattern{}, fmt.Errorf("no host in url category member %q", raw)
	}
	return p, nil
}

// parseTokens reads one side of a member, counting asterisks across the whole
// pattern rather than per side, because the device limit is per member.
func parseTokens(s, sep, raw string, stars *int) ([]urlToken, error) {
	var out []urlToken
	for _, tok := range splitNonEmpty(s, sep) {
		switch {
		case tok == "*":
			*stars++
			if *stars > 1 {
				return nil, fmt.Errorf(
					"more than one %q in %q; a firewall rejects this even when the asterisks are not adjacent", "*", raw)
			}
			out = append(out, urlToken{star: true})
		case strings.Contains(tok, "*"):
			return nil, fmt.Errorf(
				"%q in %q does not own its whole token; an asterisk may not sit beside other characters", tok, raw)
		case isAllCarets(tok):
			out = append(out, urlToken{carets: len(tok)})
		default:
			out = append(out, urlToken{text: tok})
		}
	}
	return out, nil
}

// Match reports whether the pattern covers the URL.
//
// Unlike the syntax above, the matching rules could not be verified against a
// device: test url reports PAN-DB categories only and never names a custom
// category, checked with the category referenced from a url-filtering profile, from
// a disabled rule and from an enabled rule, committing each time. These rules are
// therefore documentation-derived:
//
//   - the host splits on "." and the path on "/"
//   - "*" matches one or more tokens, "^" exactly one
//   - the host must match in full, and the path matches as a prefix, so
//     "example.com/a" covers "example.com/a/b"
//   - there is no implicit subdomain wildcard: "example.com" does not cover
//     "www.example.com"
//
// The host matching in full is the part that is easy to get wrong. Treating the
// whole URL as a prefix instead makes "wildcard-example.com" match
// "wildcard-example.com.evil.net", which is the substring bug wearing a token
// costume: a host is read from the right, so extra tokens on the end are a
// different domain, not a deeper path.
//
// Comparison is case-insensitive, and a scheme is ignored on both sides, because a
// firewall echoes a queried URL back with the scheme removed.
func (p URLPattern) Match(url string) bool {
	hostPart, pathPart := splitURL(url)
	if !matchURLTokens(p.host, splitNonEmpty(hostPart, "."), true) {
		return false
	}
	return matchURLTokens(p.path, splitNonEmpty(pathPart, "/"), false)
}

// matchURLTokens matches a token list. When full is set the URL must be consumed
// exactly; otherwise the pattern running out is a match and the rest of the URL sits
// below it.
func matchURLTokens(pat []urlToken, url []string, full bool) bool {
	if len(pat) == 0 {
		return !full || len(url) == 0
	}
	if len(url) == 0 {
		return false
	}
	t := pat[0]
	switch {
	case t.star:
		// One or more tokens, so try every split that consumes at least one.
		for n := 1; n <= len(url); n++ {
			if matchURLTokens(pat[1:], url[n:], full) {
				return true
			}
		}
		return false
	case t.carets > 0:
		if len(url) < t.carets {
			return false
		}
		return matchURLTokens(pat[1:], url[t.carets:], full)
	default:
		if url[0] != t.text {
			return false
		}
		return matchURLTokens(pat[1:], url[1:], full)
	}
}

// splitURL lowercases a URL or pattern, drops any scheme, and separates the host
// from the path.
func splitURL(s string) (host, path string) {
	v := strings.ToLower(strings.TrimSpace(s))
	if _, rest, found := strings.Cut(v, "://"); found {
		v = rest
	}
	host, path, _ = strings.Cut(v, "/")
	return host, path
}

func splitNonEmpty(s, sep string) []string {
	var out []string
	for part := range strings.SplitSeq(s, sep) {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func isAllCarets(tok string) bool {
	if tok == "" {
		return false
	}
	return strings.Count(tok, "^") == len(tok)
}
