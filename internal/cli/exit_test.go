package cli

import (
	"slices"
	"strings"
	"testing"
)

// name returns a completion value's command name, without its tab-separated
// description.
func name(v string) string {
	n, _, _ := strings.Cut(v, "\t")
	return n
}

func TestHelpCompletionOffersSubcommands(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	var got []string
	for _, v := range c.complete("help", "") {
		got = append(got, name(v))
	}
	if !slices.Contains(got, "snapshot") {
		t.Errorf("help <TAB>: got %v, want it to contain snapshot", got)
	}
	got = nil
	for _, v := range c.complete("help", "snapshot", "") {
		got = append(got, name(v))
	}
	for _, want := range []string{"list", "show", "diff"} {
		if !slices.Contains(got, want) {
			t.Errorf("help snapshot <TAB>: got %v, want it to contain %s", got, want)
		}
	}
}

func TestUnknownCommandsAreUsageErrors(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"bogus"}, {"snapshot", "bogus"}, {"simulate", "bogus"}, {"inventory", "bogus"}, {"help", "bogus"}} {
		c := newCLI(t)
		if _, errOut, code := c.run(args...); code != exitUsage {
			t.Errorf("%v: exit %d, want 2; stderr %q", args, code, errOut)
		}
	}
	c := newCLI(t)
	if out := c.want(0, "snapshot"); out == "" {
		t.Error("a bare group still prints its help")
	}
	if out := c.want(0, "help", "snapshot"); out == "" {
		t.Error("help on a known topic prints it")
	}
	if out := c.want(0, "help", "snapshot", "list"); out == "" {
		t.Error("help on a known subcommand prints it")
	}
	if _, errOut, code := c.run("help", "snapshot", "bogus"); code != exitUsage {
		t.Errorf("help snapshot bogus: exit %d, want 2; stderr %q", code, errOut)
	}
}
