package config

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/schema"
)

type edge struct{ entry, field, value string }

func edgesFrom(t testing.TB, _ *Config, walk func(func(Event) bool) error) map[edge]bool {
	t.Helper()
	out := map[edge]bool{}
	if err := walk(func(e Event) bool {
		for _, v := range e.Values {
			out[edge{e.EntryPath, e.Field, v}] = true
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func testConfigs(t testing.TB) []string {
	t.Helper()
	g, err := filepath.Glob("../../testdata/config/*.xml")
	if err != nil || len(g) == 0 {
		t.Fatalf("no test configurations: %v", err)
	}
	return g
}

// WalkPaths must lose nothing Walk found. Walk sees one shape and WalkPaths sees
// every shape, so the old edge set is a subset of the new one — with the trailing
// "/member" trimmed, which is the only naming difference between them.
func TestWalkPathsLosesNothingWalkFound(t *testing.T) {
	for _, p := range testConfigs(t) {
		c, _, err := Load(p)
		if err != nil {
			continue // a fixture for an unsupported version
		}
		old := edgesFrom(t, c, c.Walk)
		got := edgesFrom(t, c, c.WalkPaths)
		for e := range old {
			if !got[e] {
				t.Errorf("%s: WalkPaths lost %s %s=%s",
					filepath.Base(p), e.entry, e.field, e.value)
			}
		}
	}
}

// A second implementation of the same question, sharing no code with the trie:
// index every reference leaf by its full schema path, then emit wherever a
// value-bearing element's SchemaPath is one of them. Any disagreement means the
// schema paths and the configuration paths have drifted apart.
func TestWalkPathsAgreesWithAFullPathOracle(t *testing.T) {
	for _, p := range testConfigs(t) {
		c, _, err := Load(p)
		if err != nil {
			continue
		}

		// Only leaves declaring a parseable OBJECT target count. A memberof can
		// also be a literal constraint — custom-url-category/entry/type declares
		// string('URL List') — and those name no object.
		leaves := map[string]bool{}
		c.schema.root.Walk(func(n *schema.Node) {
			if n.Name == "" {
				return
			}
			for _, raw := range n.MemberOf {
				if _, err := schema.ParseTarget(raw); err == nil {
					leaves[n.Path()] = true
					return
				}
			}
		})

		// An entry array is one the schema says is an entry array. An element
		// named entry proves nothing: prefix-list holds
		// <prefix><entry><network/></entry></prefix>, a bare sequence.
		arrays := map[string]bool{}
		for _, a := range schema.EntryTypes(c.schema.root) {
			arrays[a.Path()] = true
		}

		want := map[edge]bool{}
		var rec func(el *Element)
		rec = func(el *Element) {
			if v := strings.TrimSpace(el.Text); v != "" && !Keywords[v] && leaves[el.SchemaPath()] {
				// Attribute to the nearest enclosing entry, as emitPaths does.
				rel := []string{el.Name}
				cur := el.Parent
				for cur != nil && (cur.Name != "entry" || cur.Parent == nil || !arrays[cur.Parent.SchemaPath()]) {
					rel = append(rel, cur.Name)
					cur = cur.Parent
				}
				if cur != nil {
					for i, j := 0, len(rel)-1; i < j; i, j = i+1, j-1 {
						rel[i], rel[j] = rel[j], rel[i]
					}
					want[edge{cur.InstancePath(), fieldName(rel), v}] = true
				}
			}
			for _, k := range el.Children {
				rec(k)
			}
		}
		rec(c.root)

		got := edgesFrom(t, c, c.WalkPaths)
		for e := range want {
			if !got[e] {
				t.Errorf("%s: oracle found an edge WalkPaths missed: %s %s=%s",
					filepath.Base(p), e.entry, e.field, e.value)
			}
		}
		for e := range got {
			if !want[e] {
				t.Errorf("%s: WalkPaths emitted an edge the oracle does not: %s %s=%s",
					filepath.Base(p), e.entry, e.field, e.value)
			}
		}
	}
}

// The leaves a security rule declares. 16 of these 30 were reachable before
// WalkPaths: the three scalars and everything under profile-setting were not.
func TestSecurityRuleDeclaresThirtyReferenceLeaves(t *testing.T) {
	c, _, err := Load("../../testdata/config/firewall-refpaths.xml")
	if err != nil {
		t.Fatal(err)
	}
	trie := c.schema.paths["/config/devices/entry/vsys/entry/rulebase/security/rules"]
	if trie == nil {
		t.Fatal("no reference paths for the security rulebase")
	}
	var got []string
	var rec func(*pathNode)
	rec = func(n *pathNode) {
		if n.candidates != nil {
			got = append(got, strings.Join(n.path, "/"))
		}
		for _, k := range n.kids {
			rec(k)
		}
	}
	rec(trie)
	slices.Sort(got)

	if len(got) != 30 {
		t.Errorf("security rule reference leaves = %d, want 30:\n%s",
			len(got), strings.Join(got, "\n"))
	}
	for _, want := range []string{
		"log-setting", "schedule", "group-tag", // scalar leaves, not member lists
		"profile-setting/group/member",                  // below a named union
		"profile-setting/profiles/url-filtering/member", // four levels down
		"profile-setting/profiles/file-blocking/member",
	} {
		if !slicesContains(got, want) {
			t.Errorf("missing reference leaf %q", want)
		}
	}
}

// The edges those leaves actually yield, and where each one is attributed.
func TestWalkPathsFindsNestedAndScalarEdges(t *testing.T) {
	c, _, err := Load("../../testdata/config/firewall-refpaths.xml")
	if err != nil {
		t.Fatal(err)
	}
	got := edgesFrom(t, c, c.WalkPaths)

	const rules = "/config/devices/localhost.localdomain/vsys/vsys1/rulebase/security/rules/"
	for _, want := range []edge{
		{rules + "by-group", "profile-setting/group", "baseline"},
		{rules + "by-group", "log-setting", "to-siem"},
		{rules + "by-profiles", "profile-setting/profiles/url-filtering", "strict-url"},
		{rules + "by-profiles", "profile-setting/profiles/file-blocking", "no-exe"},
		{rules + "by-profiles", "schedule", "off-hours"},
		{rules + "by-profiles", "group-tag", "edge"},
		{rules + "by-profiles", "tag", "edge"}, // a plain member list, named as before
		// An element named entry is not always an entry list: this one is a bare
		// sequence, so the edge belongs to the ipv4-entry above it.
		{
			"/config/devices/localhost.localdomain/network/routing-profile/filters/prefix-list/reject-default/type/ipv4/ipv4-entry/10",
			"prefix/entry/network", "0.0.0.0/0",
		},
	} {
		if !got[want] {
			t.Errorf("missing edge %s %s=%s", want.entry, want.field, want.value)
		}
	}
}

func TestFieldNameDropsOnlyATrailingMember(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"source", "member"}, "source"},
		{[]string{"log-setting"}, "log-setting"},
		{[]string{"profile-setting", "group", "member"}, "profile-setting/group"},
		{[]string{"prefix", "entry", "network"}, "prefix/entry/network"},
	} {
		if got := fieldName(tc.in); got != tc.want {
			t.Errorf("fieldName(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func slicesContains(s []string, v string) bool {
	return slices.Contains(s, v)
}

// The callback stops the walk, and it must stop at once: the descent is
// recursive, so a stop has to unwind through the trie as well as the tree.
func TestWalkPathsStopsWhenTheCallbackSaysSo(t *testing.T) {
	c, _, err := Load("../../testdata/config/firewall-refpaths.xml")
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	_ = c.WalkPaths(func(Event) bool { total++; return true })
	if total < 3 {
		t.Fatalf("the fixture must yield several events, got %d", total)
	}

	for _, stopAfter := range []int{1, 2} {
		n := 0
		if err := c.WalkPaths(func(Event) bool { n++; return n < stopAfter }); err != nil {
			t.Fatal(err)
		}
		if n != stopAfter {
			t.Errorf("stopping after %d events yielded %d", stopAfter, n)
		}
	}
}

// A file whose version the schema does not cover still walks; it simply matches
// no entry array and yields nothing.
func TestWalkPathsOnAConfigWithNoKnownArrays(t *testing.T) {
	c, _, err := Load("../../testdata/config/firewall-shadow.xml")
	if err != nil {
		t.Skip(err)
	}
	if err := c.WalkPaths(func(Event) bool { return true }); err != nil {
		t.Fatal(err)
	}
}
