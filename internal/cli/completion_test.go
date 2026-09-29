package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// complete runs cobra's hidden completion command and returns the offered values,
// without the trailing directive line.
func (c *cli) complete(args ...string) []string {
	c.t.Helper()
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut, func(k string) string { return c.env[k] }, time.Now)
	argv := append([]string{"__complete", "--config", c.cfgPath}, args...)
	if code := a.execute(context.Background(), argv); code != exitOK {
		c.t.Fatalf("__complete %v: exit %d: %s", args, code, errOut.String())
	}
	var vals []string
	for line := range strings.SplitSeq(strings.TrimSpace(out.String()), "\n") {
		if !strings.HasPrefix(line, ":") {
			vals = append(vals, line)
		}
	}
	return vals
}

func TestCompletionOffersDeviceNamesAndFixedValues(t *testing.T) {
	c := newCLI(t)
	c.inventory(inventoryFor("a.example", "b.example"))
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"fetch offers every device", []string{"fetch", ""}, "fw01,fw02"},
		{"fetch leaves out a device already named", []string{"fetch", "fw01", ""}, "fw02"},
		{"snapshot list takes one device", []string{"snapshot", "list", ""}, "fw01,fw02"},
		{"snapshot list takes no second", []string{"snapshot", "list", "fw01", ""}, ""},
		{"--device on a question", []string{"search", "x", "--device", ""}, "fw01,fw02"},
		{"--device on simulate nat", []string{"simulate", "nat", "a", "b", "--device", ""}, "fw01,fw02"},
		{"--output", []string{"search", "x", "--output", ""}, "text,json"},
		{"--log-level", []string{"fetch", "--log-level", ""}, "error,warn,info,debug"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Join(c.complete(tc.args...), ","); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Without an inventory there is nothing to offer, and completion still succeeds.
func TestCompletionWithoutAnInventory(t *testing.T) {
	c := newCLI(t)
	if got := c.complete("fetch", ""); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}
