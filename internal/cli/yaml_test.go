package cli

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Each string must come back from a YAML reader as the same string (spec §3.3).
func TestYAMLStringsRoundTrip(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("k", 2000)
	for _, s := range []string{
		"<<", "=", "1:20", "12:30:45", "Yes", "On", "y", "N", "0b101", "1e3", "0x1F",
		"2026-09-30", ".inf", "~", "null", "", " lead", "trail ", "a: b", "a #b", "-x",
		"plain words", long,
	} {
		var buf bytes.Buffer
		if err := writeYAML(&buf, envelope{Command: s, Input: map[string]string{s: s}, Results: []string{s}}); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		var got struct {
			Command string            `yaml:"command"`
			Input   map[string]string `yaml:"input"`
			Results []string          `yaml:"results"`
		}
		if err := yaml.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("%q: %v\n%s", s, err, buf.String())
		}
		if got.Command != s || got.Input[s] != s || len(got.Results) != 1 || got.Results[0] != s {
			t.Errorf("%q came back as %+v\n%s", s, got, buf.String())
		}
	}
}

// YAML 1.1 readers misread these unless quoted; yaml.v3 alone leaves them plain.
func TestYAMLQuotesYAML11Words(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"Yes", "On", "y", "1:20", "<<", "=", ""} {
		if n := yamlString(s); n.Style != yaml.DoubleQuotedStyle {
			t.Errorf("%q must be double-quoted", s)
		}
	}
	if n := yamlString("plain"); n.Style != 0 || n.Tag != "!!str" {
		t.Errorf("plain = %+v", n)
	}
}

func TestYAMLNumbersAreExactAndUntagged(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := writeYAML(&buf, envelope{Results: []any{0, uint64(18446744073709551615), 0.5, true, nil}}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"- 0\n", "- 18446744073709551615\n", "- 0.5\n", "- true\n", "- null\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "!!") || strings.HasPrefix(out, "---") {
		t.Errorf("no tags and no document marker:\n%s", out)
	}
}
