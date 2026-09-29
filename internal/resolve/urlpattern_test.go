package resolve

import "testing"

// Every row here was offered to a firewall and its verdict recorded. The parser has
// to agree with the device about what is even writable, or it will reject
// configurations that exist or accept ones that cannot.
func TestParseURLPatternMatchesTheDeviceValidator(t *testing.T) {
	t.Parallel()
	accept := []string{
		"*.example.com",
		"^.example.com",
		"^^.example.com",
		"example.com/*",
		"example.com/^",
		"https://example.com/x",
		"EXAMPLE.com",
		"example.com:8080",
		"example.com/p?q=1",
		"example.com/",
		"*",
	}
	reject := []string{
		"mail*.example.com",
		"**.example.com",
		"*.*.example.com",
		"",
		"   ",
	}
	for _, m := range accept {
		if _, err := ParseURLPattern(m); err != nil {
			t.Errorf("ParseURLPattern(%q) = %v, want accepted; the device accepts it", m, err)
		}
	}
	for _, m := range reject {
		if _, err := ParseURLPattern(m); err == nil {
			t.Errorf("ParseURLPattern(%q) accepted, want rejected; the device rejects it", m)
		}
	}
}

// The device rejects a second asterisk even when the two are not adjacent, though
// its error message only mentions consecutive ones.
func TestParseURLPatternAllowsOneStarAndManyCarets(t *testing.T) {
	t.Parallel()
	if _, err := ParseURLPattern("*.a.example.com"); err != nil {
		t.Errorf("one star rejected: %v", err)
	}
	if _, err := ParseURLPattern("*.a.*.example.com"); err == nil {
		t.Error("two non-adjacent stars accepted; the device rejects this")
	}
	if _, err := ParseURLPattern("^^^.example.com"); err != nil {
		t.Errorf("three carets rejected: %v", err)
	}
}

// Matching is documentation-derived, not device-verified: test url never reports a
// custom category. These cases pin the documented model so a later device check has
// something exact to contradict.
func TestURLPatternMatch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pattern string
		url     string
		want    bool
		why     string
	}{
		{"bare.example.com", "bare.example.com", true, "exact"},
		{"bare.example.com", "bare.example.com/any/path", true, "a pattern covers what sits below it"},
		{"bare.example.com", "sub.bare.example.com", false, "no implicit subdomain wildcard"},
		{"bare.example.com", "example.com", false, "shorter than the pattern"},

		{"exact.example.com/deep/path", "exact.example.com/deep/path", true, "exact with a path"},
		{"exact.example.com/deep/path", "exact.example.com/deep/path/more", true, "deeper path"},
		{"exact.example.com/deep/path", "exact.example.com/deep", false, "the URL stops short"},
		{"exact.example.com/deep/path", "exact.example.com", false, "host only"},

		{"*.star.example.com", "a.star.example.com", true, "one token for the star"},
		{"*.star.example.com", "a.b.star.example.com", true, "a star takes one or more tokens"},
		{"*.star.example.com", "star.example.com", false, "a star needs at least one token"},
		{"*.star.example.com", "a.star.example.com/path", true, "path below the match"},
		{"*.star.example.com", "a.star.example.com.evil.net", false, "not a suffix match"},

		{"^.caret.example.com", "a.caret.example.com", true, "one token for the caret"},
		{"^.caret.example.com", "a.b.caret.example.com", false, "a caret is exactly one token"},
		{"^^.caret.example.com", "a.b.caret.example.com", true, "two carets, two tokens"},

		{"https://scheme.example.com", "scheme.example.com", true, "a scheme is ignored on both sides"},
		{"CASE.example.com", "case.EXAMPLE.com", true, "case-insensitive"},

		{"example.com/*", "example.com/a", true, "a star in the path takes a token"},
		{"example.com/*", "example.com/a/b", true, "a star in the path takes more than one"},
		{"example.com/*", "example.com", false, "a star in the path needs a path"},
		{"*", "anything.example.com", true, "a bare star matches any host"},
		{"example.com/", "example.com/x", true, "a trailing slash adds no path token"},
		{"example.com:8080", "example.com:8080/x", true, "a port is part of the host token"},
		{"example.com:8080", "example.com/x", false, "a port has to match"},

		// The reason faithful matching cannot be substring matching.
		{"wildcard-example.com", "wildcard-example.com.evil.net", false, "substring matching would wrongly match"},
	}
	for _, c := range cases {
		p, err := ParseURLPattern(c.pattern)
		if err != nil {
			t.Fatalf("ParseURLPattern(%q): %v", c.pattern, err)
		}
		if got := p.Match(c.url); got != c.want {
			t.Errorf("%q matches %q = %v, want %v (%s)", c.pattern, c.url, got, c.want, c.why)
		}
	}
}

// Raw keeps the member as written, so a hit can report what matched.
func TestURLPatternRaw(t *testing.T) {
	t.Parallel()
	p, err := ParseURLPattern("  *.Example.COM  ")
	if err != nil {
		t.Fatal(err)
	}
	if p.Raw() != "*.Example.COM" {
		t.Errorf("Raw = %q, want the trimmed member as written", p.Raw())
	}
}
