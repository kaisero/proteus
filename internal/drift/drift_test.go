package drift

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
)

func load(t *testing.T, name string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("../../testdata/config/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

var vsys1 = config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

func TestIdenticalConfigurationsDoNotDiffer(t *testing.T) {
	t.Parallel()
	if got := Compare(load(t, "firewall-lab.xml"), load(t, "firewall-lab.xml"), vsys1); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

// Shared objects and rules are compared under shared, not repeated per vsys.
func TestSharedIsItsOwnScope(t *testing.T) {
	t.Parallel()
	before := load(t, "firewall-lab.xml")
	after := load(t, "firewall-multivsys.xml")
	shared := config.Scope{Sort: config.ScopeShared}
	got := Compare(before, after, shared)
	var lines []string
	for _, c := range got {
		lines = append(lines, string(c.Op)+" "+c.Kind+" "+c.Name)
	}
	joined := strings.Join(lines, ",")
	for _, want := range []string{"removed address shared-dns", "removed security rule pushed-pre", "added address-group corp-location"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	vsysOnly := Compare(before, after, vsys1)
	for _, c := range vsysOnly {
		if c.Name == "shared-dns" || c.Name == "pushed-pre" {
			t.Errorf("a shared change leaked into the vsys comparison: %+v", c)
		}
	}
}

// pair loads a snapshot diff fixture pair from testdata/drift.
func pair(t *testing.T, before, after string) (*config.Config, *config.Config) {
	t.Helper()
	var out [2]*config.Config
	for i, name := range []string{before, after} {
		cfg, _, err := config.Load("../../testdata/drift/" + name)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = cfg
	}
	return out[0], out[1]
}

// loadXML loads a configuration written by the test.
func loadXML(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// The probes: each fixture changes one setting, and the diff names that entry
// once with that setting only.
func TestCompareNamesTheChangedSetting(t *testing.T) {
	t.Parallel()
	shared := config.Scope{Sort: config.ScopeShared}
	for _, tc := range []struct {
		after      string
		scope      config.Scope
		kind, name string
		want       []FieldChange
	}{
		{
			"negate.xml", vsys1, "security rule", "inside-out",
			[]FieldChange{{Path: "negate-destination", New: "yes"}},
		},
		{
			"nat.xml", vsys1, "nat rule", "dnat-web",
			[]FieldChange{{Path: "destination-translation/translated-address", Old: "srv-web", New: "10.88.2.11"}},
		},
		{
			"edl.xml", vsys1, "external-list", "edl-block",
			[]FieldChange{{Path: "type/ip/url", Old: "https://lists.example.com/block.txt", New: "https://lists.example.com/block-v2.txt"}},
		},
		{
			"pbf.xml", vsys1, "pbf rule", "pbf-out",
			[]FieldChange{{Path: "action/forward/egress-interface", Old: "ethernet1/2", New: "ethernet1/3"}},
		},
		{
			"profile.xml", vsys1, "virus", "av-strict",
			[]FieldChange{{Path: "decoder/smtp/action", Old: "alert", New: "reset-both"}},
		},
		{
			"pushed.xml", shared, "security rule", "pushed-post",
			[]FieldChange{{Path: "action", Old: "deny", New: "drop"}},
		},
	} {
		t.Run(tc.after, func(t *testing.T) {
			t.Parallel()
			before, after := pair(t, "before.xml", tc.after)
			got := Compare(before, after, tc.scope)
			want := []Change{{Op: Changed, Kind: tc.kind, Name: tc.name, Fields: tc.want}}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got  %+v\nwant %+v", got, want)
			}
			// The other scope holds none of it.
			other := shared
			if tc.scope == shared {
				other = vsys1
			}
			if got := Compare(before, after, other); len(got) != 0 {
				t.Errorf("%s: got %+v", other, got)
			}
		})
	}
}

// A member list is a set, and the bookkeeping attributes are not settings.
func TestCompareIgnoresOrderAndBookkeeping(t *testing.T) {
	t.Parallel()
	for _, after := range []string{"reorder.xml", "uuid.xml"} {
		before, now := pair(t, "before.xml", after)
		if got := Compare(before, now, vsys1); len(got) != 0 {
			t.Errorf("%s: got %+v", after, got)
		}
	}
	tmpl := `<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<address><entry name="a" %s><ip-netmask>10.88.0.1</ip-netmask></entry></address></entry></vsys></entry></devices></config>`
	before := loadXML(t, fmt.Sprintf(tmpl, `uuid="1"`))
	after := loadXML(t, fmt.Sprintf(tmpl, `uuid="2" admin="admin1" time="2026/10/10 10:00:00" dirtyId="7"`))
	if got := Compare(before, after, vsys1); len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}

// An added or removed entry keeps its short line; a changed one lists fields.
func TestCompareKeepsShortLines(t *testing.T) {
	t.Parallel()
	got := Compare(load(t, "firewall-lab.xml"), load(t, "firewall-lab-changed.xml"), vsys1)
	want := []Change{
		{Op: Changed, Kind: "address", Name: "net-home", Fields: []FieldChange{{Path: "ip-netmask", Old: "198.18.1.0/24", New: "198.18.2.0/24"}}},
		{Op: Removed, Kind: "address", Name: "net-labor", Old: "198.18.0.0/15"},
		{Op: Changed, Kind: "security rule", Name: "dc-to-home", Fields: []FieldChange{{Path: "disabled", New: "yes"}}},
		{Op: Added, Kind: "security rule", Name: "new-rule", New: "allow application=dns destination=any source=net-home"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// Every kind the scope holds counts, not only addresses and the security and
// NAT rulebases: here a zone and a PBF rule come and go.
func TestCompareReadsEveryKind(t *testing.T) {
	t.Parallel()
	before, after := pair(t, "before.xml", "before.xml")
	if got := Compare(before, after, vsys1); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
	empty := loadXML(t, `<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices></config>`)
	var lines []string
	for _, c := range Compare(before, empty, vsys1) {
		lines = append(lines, string(c.Op)+" "+c.Kind+" "+c.Name+" "+c.Old)
	}
	want := []string{
		"removed address net-inside 10.88.1.0/24",
		"removed address srv-web 10.88.2.10",
		"removed address-group g-inside net-inside, srv-web",
		"removed external-list edl-block ",
		"removed nat rule dnat-web destination=198.18.0.10 from=untrust source=any to=untrust",
		"removed pbf rule pbf-out destination=any service=any source=any",
		"removed security rule inside-out allow application=any destination=10.88.9.0/24 from=trust service=application-default source=net-inside,srv-web to=untrust",
		"removed virus av-strict ",
		"removed zone trust ",
		"removed zone untrust ",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// The device's predefined services are not configuration: a snapshot with
// them and one without do not differ.
func TestComparePassesOverPredefined(t *testing.T) {
	t.Parallel()
	with, _, err := config.Load("../../testdata/predefined/config.xml")
	if err != nil {
		t.Fatal(err)
	}
	if with.Predefined() == nil {
		t.Fatal("the fixture must hold predefined services")
	}
	body, err := os.ReadFile("../../testdata/predefined/config.xml")
	if err != nil {
		t.Fatal(err)
	}
	without := loadXML(t, string(body))
	for _, sc := range []config.Scope{{Sort: config.ScopeShared}, vsys1} {
		if got := Compare(with, without, sc); len(got) != 0 {
			t.Errorf("%s: got %+v", sc, got)
		}
	}
}

// An element the digest does not describe is compared whole, so its change
// shows; an empty element is set, which differs from absent.
func TestCompareKeepsWhatTheDigestDoesNotDescribe(t *testing.T) {
	t.Parallel()
	tmpl := `<config version="11.2.0"><shared><future-list><entry name="a"><x>%s</x><y/></entry><item>1</item><item>2</item></future-list></shared></config>`
	before := loadXML(t, fmt.Sprintf(tmpl, "1"))
	after := loadXML(t, fmt.Sprintf(tmpl, "2"))
	shared := config.Scope{Sort: config.ScopeShared}
	want := []Change{{Op: Changed, Kind: "future-list", Fields: []FieldChange{{Path: "a/x", Old: "1", New: "2"}}}}
	if got := Compare(before, after, shared); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	gone := loadXML(t, `<config version="11.2.0"><shared><future-list><entry name="a"><x>1</x></entry><item>2</item><item>1</item></future-list></shared></config>`)
	want = []Change{{Op: Changed, Kind: "future-list", Fields: []FieldChange{
		{Path: "a/y", Old: Set},
		{Path: "item", Old: "1, 2", New: "2, 1"},
	}}}
	if got := Compare(before, gone, shared); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// Attributes other than bookkeeping are settings, on an element and on a
// member; an element the digest does not place in a list still counts.
func TestCompareReadsAttributes(t *testing.T) {
	t.Parallel()
	tmpl := `<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<address-group><entry name="g"><static><member %s>a</member><member>b</member></static></entry></address-group>
<profiles><virus><entry name="av"><decoder><entry name="http"><action>alert</action></entry><stray>%s</stray></decoder><mlav-engine-filebased-enabled %s/></entry></virus></profiles>
</entry></vsys></entry></devices></config>`
	before := loadXML(t, fmt.Sprintf(tmpl, `uuid="1"`, "1", `mode="a"`))
	after := loadXML(t, fmt.Sprintf(tmpl, `loc="x"`, "2", `mode="b"`))
	want := []Change{
		{Op: Changed, Kind: "address-group", Name: "g", Fields: []FieldChange{{Path: "static", Old: "a, b", New: "a [loc=x], b"}}},
		{Op: Changed, Kind: "virus", Name: "av", Fields: []FieldChange{
			{Path: "decoder/stray", Old: "1", New: "2"},
			{Path: "mlav-engine-filebased-enabled/@mode", Old: "a", New: "b"},
		}},
	}
	if got := Compare(before, after, vsys1); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	// Neither the device level nor the predefined services is a scope here.
	for _, sc := range []config.Scope{{Sort: config.ScopeConfig}, {Sort: config.ScopePredefined}} {
		if got := Compare(before, after, sc); len(got) != 0 {
			t.Errorf("%s: got %+v", sc, got)
		}
	}
}
