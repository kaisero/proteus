package testconfig

import (
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

// The generated file loads, and holds the shape the benchmarks name.
func TestWriteGivesTheShape(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load(Write(t, Groups{Addrs: 2000, Rules: 1000, Ring: 3, Dense: 4}))
	if err != nil {
		t.Fatal(err)
	}
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	if got := len(resolve.ObjectsInScope(cfg, sc, "address")); got != 2000 {
		t.Errorf("%d addresses, want 2000", got)
	}
	groups := map[string]resolve.Object{}
	for _, g := range resolve.ObjectsInScope(cfg, sc, "address-group") {
		groups[g.Name] = g
	}
	if len(groups) != TreeGroups+3+4 {
		t.Errorf("%d groups, want %d", len(groups), TreeGroups+7)
	}
	if !groups["g-0"].Dynamic || groups["g-1"].Dynamic || groups["c-2"].Value != "c-0, a-2" {
		t.Errorf("g-0 %+v, g-1 %+v, c-2 %+v", groups["g-0"], groups["g-1"], groups["c-2"])
	}
	// The tree under the top rule's group: 1 + 3 + 9 + 27 + 81 + 243 groups.
	tg, err := resolve.TargetFor(cfg, "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatal(err)
	}
	var src string
	for _, r := range tg.Rules(resolve.Security) {
		if r.Name == TopRule {
			src = r.Fields["source"][0]
		}
	}
	nodes := 0
	var walk func(string)
	walk = func(g string) {
		o, ok := groups[g]
		if !ok {
			return
		}
		nodes++
		if !o.Dynamic {
			for _, m := range strings.Split(o.Value, ", ") {
				walk(m)
			}
		}
	}
	walk(src)
	if src != "g-1999" || nodes != 364 {
		t.Errorf("%s holds a tree of %d groups, want g-1999 and 364", src, nodes)
	}
}
