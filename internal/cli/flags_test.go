package cli

import (
	"strings"
	"testing"
)

func TestSharedFlagsHaveOneHelpText(t *testing.T) {
	t.Parallel()
	root := newApp(nil, nil, func(string) string { return "" }, nil).root()
	help := map[string]map[string]bool{}
	for _, path := range [][]string{{"simulate", "policy"}, {"simulate", "nat"}, {"simulate", "routing"}} {
		c, _, err := root.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"why", "no-dns", "port"} {
			if f := c.Flags().Lookup(name); f != nil {
				if help[name] == nil {
					help[name] = map[string]bool{}
				}
				help[name][f.Usage] = true
			}
		}
	}
	for name, texts := range help {
		if len(texts) != 1 {
			t.Errorf("--%s has %d help texts: %v", name, len(texts), texts)
		}
	}
}

func TestDiffTakesNoFileAtOrFresh(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	for _, flag := range []string{"--file=x.xml", "--at=2026-01-01", "--fresh"} {
		_, errOut, code := c.run("snapshot", "diff", flag)
		if code != exitUsage || !strings.Contains(errOut, "unknown flag") {
			t.Errorf("%s: exit %d, stderr %q", flag, code, errOut)
		}
	}
}

func TestRoutingHasNoSourcePort(t *testing.T) {
	t.Parallel()
	root := newApp(nil, nil, func(string) string { return "" }, nil).root()
	c, _, _ := root.Find([]string{"simulate", "routing"})
	if c.Flags().Lookup("source-port") != nil || c.Flags().Lookup("protocol") != nil {
		t.Error("routing takes --port only; it gains no flag (spec §7.1)")
	}
}
