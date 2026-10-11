package drift

import (
	"encoding/json"
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
	for _, want := range []string{"removed address shared-dns", "removed pre-rulebase security rule pushed-pre", "added address-group corp-location"} {
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
			"pushed.xml", shared, "post-rulebase security rule", "pushed-post",
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
		"removed certificate cert-web ",
		"removed external-list edl-block ",
		"removed ldap ldap-corp ",
		"removed nat rule dnat-web destination=198.18.0.10 from=untrust source=any to=untrust",
		"removed pbf rule pbf-out destination=any service=any source=any",
		"removed security rule inside-out allow application=any destination=10.88.9.0/24 from=trust service=application-default source=net-inside,srv-web to=untrust",
		"removed user user1 ",
		"removed virus av-strict ",
		"removed zone trust ",
		"removed zone untrust ",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// A setting of the scope, an element or a list that is not an entry, is one
// entry of kind setting, named by its path below the scope.
func TestCompareReadsScopeSettings(t *testing.T) {
	t.Parallel()
	shared := config.Scope{Sort: config.ScopeShared}
	for _, tc := range []struct {
		name          string
		scope         config.Scope
		before, after string
		want          []Change
	}{
		{
			"an interface moved into the vsys", vsys1,
			`<import><network><interface><member>ethernet1/1</member></interface></network></import>`,
			`<import><network><interface><member>ethernet1/3</member><member>ethernet1/1</member></interface></network></import>`,
			[]Change{{Op: Changed, Kind: "setting", Name: "import/network/interface", Fields: []FieldChange{
				{Path: "interface", Old: "ethernet1/1", New: "ethernet1/1, ethernet1/3"},
			}}},
		},
		{
			"captive portal turned on", vsys1,
			`<captive-portal><enable-captive-portal>no</enable-captive-portal></captive-portal>`,
			`<captive-portal><enable-captive-portal>yes</enable-captive-portal></captive-portal>`,
			[]Change{{Op: Changed, Kind: "setting", Name: "captive-portal/enable-captive-portal", Fields: []FieldChange{
				{Path: "enable-captive-portal", Old: "no", New: "yes"},
			}}},
		},
		{
			"a trusted root CA added", shared,
			`<ssl-decrypt><trusted-root-CA><member>ca1</member></trusted-root-CA></ssl-decrypt>`,
			`<ssl-decrypt><trusted-root-CA><member>ca1</member><member>ca2</member></trusted-root-CA></ssl-decrypt>`,
			[]Change{{Op: Changed, Kind: "setting", Name: "ssl-decrypt/trusted-root-CA", Fields: []FieldChange{
				{Path: "trusted-root-CA", Old: "ca1", New: "ca1, ca2"},
			}}},
		},
		{
			// The schema holds a vsys user-group as an array of arrays named
			// entry, each with a name: named entries, read as an entry list.
			"a user-group member changed", vsys1,
			`<user-group><entry name="g1"><member>u1</member></entry><entry name="g2"><member>u3</member></entry></user-group>`,
			`<user-group><entry name="g1"><member>u1</member><member>u2</member></entry><entry name="g2"><member>u3</member></entry></user-group>`,
			[]Change{{Op: Changed, Kind: "user-group", Name: "g1", Fields: []FieldChange{
				{Path: "member", Old: "u1", New: "u1, u2"},
			}}},
		},
		{
			// A choice that holds nothing is present or not: its presence is
			// the setting.
			"the captive portal mode switched", vsys1,
			`<captive-portal><mode><transparent/></mode></captive-portal>`,
			`<captive-portal><mode><redirect/></mode></captive-portal>`,
			[]Change{
				{Op: Added, Kind: "setting", Name: "captive-portal/mode/redirect", New: Set},
				{Op: Removed, Kind: "setting", Name: "captive-portal/mode/transparent", Old: Set},
			},
		},
		{
			// An element the digest does not describe is compared whole,
			// its own text too: a newer release can add such a setting.
			"an undescribed setting changed", vsys1,
			`<future-setting>DUMMYOLD</future-setting>`,
			`<future-setting>DUMMYNEW</future-setting>`,
			[]Change{{Op: Changed, Kind: "future-setting", Fields: []FieldChange{
				{Path: "future-setting", Undescribed: true},
			}}},
		},
		{
			"an undescribed leaf of a setting changed", vsys1,
			`<setting><ssl-decrypt><future-knob>yes</future-knob></ssl-decrypt></setting>`,
			`<setting><ssl-decrypt><future-knob>no</future-knob></ssl-decrypt></setting>`,
			[]Change{{Op: Changed, Kind: "setting/ssl-decrypt/future-knob", Fields: []FieldChange{
				{Path: "future-knob", Undescribed: true},
			}}},
		},
		{
			// A container the walk descends into keeps its own attributes,
			// but for bookkeeping ones.
			"an attribute of a setting's container changed", vsys1,
			`<captive-portal future="a" admin="u1"><enable-captive-portal>no</enable-captive-portal></captive-portal>`,
			`<captive-portal future="b" admin="u2"><enable-captive-portal>no</enable-captive-portal></captive-portal>`,
			[]Change{{Op: Changed, Kind: "setting", Name: "captive-portal", Fields: []FieldChange{
				{Path: "captive-portal/@future", Undescribed: true},
			}}},
		},
		{
			"a secret setting", vsys1,
			`<url-admin-override><password>DUMMYOVERRIDE0</password></url-admin-override>`,
			`<url-admin-override><password>DUMMYOVERRIDE1</password></url-admin-override>`,
			[]Change{{Op: Changed, Kind: "setting", Name: "url-admin-override/password", Fields: []FieldChange{
				{Path: "password", Old: Hidden, New: Hidden, Secret: true},
			}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			before := loadXML(t, inScope(tc.scope, tc.before))
			after := loadXML(t, inScope(tc.scope, tc.after))
			if got := Compare(before, after, tc.scope); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got  %+v\nwant %+v", got, tc.want)
			}
			if got := Compare(after, after, tc.scope); len(got) != 0 {
				t.Errorf("the same configuration: got %+v", got)
			}
		})
	}
	// An added or removed setting shows its value as its short line, unless
	// it holds a value that must not show.
	none := loadXML(t, inScope(vsys1, ""))
	set := loadXML(t, inScope(vsys1, `<import><network><interface><member>ethernet1/3</member></interface></network></import>
<url-admin-override><password>DUMMYOVERRIDE0</password></url-admin-override><future-setting>DUMMYFUTURE</future-setting>`))
	got := Compare(none, set, vsys1)
	want := []Change{
		{Op: Added, Kind: "future-setting"},
		{Op: Added, Kind: "setting", Name: "import/network/interface", New: "ethernet1/3"},
		{Op: Added, Kind: "setting", Name: "url-admin-override/password"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	assertAbsent(t, append(got, Compare(set, none, vsys1)...), "DUMMYOVERRIDE", "DUMMYFUTURE")
	// A container that holds nothing is no setting, and an empty list is
	// absent, as inside an entry. Only an empty element that picks an
	// alternative of a choice, or that has nothing to hold, is set by its
	// presence.
	empty := loadXML(t, inScope(vsys1, `<rulebase/><profiles/><import><network><interface/></network></import><captive-portal/><import><network/></import>`))
	if got := Compare(none, empty, vsys1); len(got) != 0 {
		t.Errorf("empty containers: got %+v", got)
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
// shows, but none of its values does: nothing says it holds no secret.
func TestCompareKeepsWhatTheDigestDoesNotDescribe(t *testing.T) {
	t.Parallel()
	tmpl := `<config version="11.2.0"><shared><future-list><entry name="a"><x>%s</x><y/></entry><item>1</item><item>2</item></future-list></shared></config>`
	before := loadXML(t, fmt.Sprintf(tmpl, "v1"))
	after := loadXML(t, fmt.Sprintf(tmpl, "v2"))
	shared := config.Scope{Sort: config.ScopeShared}
	want := []Change{{Op: Changed, Kind: "future-list", Fields: []FieldChange{{Path: "future-list/a/x", Undescribed: true}}}}
	if got := Compare(before, after, shared); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	gone := loadXML(t, `<config version="11.2.0"><shared><future-list><entry name="a"><x>v1</x></entry><item>2</item><item>1</item></future-list></shared></config>`)
	want = []Change{{Op: Changed, Kind: "future-list", Fields: []FieldChange{
		{Path: "future-list/a/y", Undescribed: true},
		{Path: "future-list/item", Undescribed: true},
	}}}
	got := Compare(before, gone, shared)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	empty := loadXML(t, `<config version="11.2.0"><shared/></config>`)
	got = append(got, Compare(before, empty, shared)...)
	got = append(got, Compare(empty, after, shared)...)
	assertAbsent(t, got, "v1", "v2")
}

// An unknown child of a known entry, as a newer release may add, is compared
// but never shown, in the field and in the entry's short line.
func TestCompareHidesAnUndescribedChild(t *testing.T) {
	t.Parallel()
	before, after := pair(t, "before.xml", "undescribed.xml")
	want := []Change{{Op: Changed, Kind: "ldap", Name: "ldap-corp", Fields: []FieldChange{{Path: "new-secret", Undescribed: true}}}}
	got := Compare(before, after, vsys1)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	empty := loadXML(t, `<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices></config>`)
	got = append(got, Compare(after, empty, vsys1)...)
	got = append(got, Compare(empty, after, vsys1)...)
	assertAbsent(t, got, "s3cr3t")
}

// assertAbsent fails when a value shows anywhere in the changes' JSON.
func assertAbsent(t *testing.T, changes []Change, values ...string) {
	t.Helper()
	b, err := json.Marshal(changes)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		if strings.Contains(string(b), v) {
			t.Errorf("%s shows in %s", v, b)
		}
	}
}

// The order of a nested entry list is configuration: swapping two servers
// is one change. Adding one is not a reorder as well.
func TestCompareReportsANestedReorder(t *testing.T) {
	t.Parallel()
	before, after := pair(t, "before.xml", "servers.xml")
	want := []Change{{Op: Changed, Kind: "ldap", Name: "ldap-corp", Fields: []FieldChange{
		{Path: "server order", Old: "ldap1, ldap2", New: "ldap2, ldap1"},
	}}}
	if got := Compare(before, after, vsys1); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	tmpl := `<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<profiles><virus><entry name="av"><decoder>%s</decoder></entry></virus></profiles></entry></vsys></entry></devices></config>`
	two := loadXML(t, fmt.Sprintf(tmpl, `<entry name="http"/><entry name="smtp"/>`))
	three := loadXML(t, fmt.Sprintf(tmpl, `<entry name="http"/><entry name="ftp"/><entry name="smtp"/>`))
	one := loadXML(t, fmt.Sprintf(tmpl, `<entry name="smtp"/>`))
	want = []Change{{Op: Changed, Kind: "virus", Name: "av", Fields: []FieldChange{{Path: "decoder/ftp", New: Set}}}}
	if got := Compare(two, three, vsys1); !reflect.DeepEqual(got, want) {
		t.Errorf("an added entry: got  %+v\nwant %+v", got, want)
	}
	want = []Change{{Op: Changed, Kind: "virus", Name: "av", Fields: []FieldChange{{Path: "decoder/http", Old: Set}}}}
	if got := Compare(two, one, vsys1); !reflect.DeepEqual(got, want) {
		t.Errorf("a removed entry: got  %+v\nwant %+v", got, want)
	}
}

// An attribute the schema declares is a setting like any other; one it does
// not declare, on an element or a member, and an unknown child are compared
// but not shown.
func TestCompareReadsAttributes(t *testing.T) {
	t.Parallel()
	tmpl := `<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<application-status><entry name="web-browsing" status="%s"/></application-status>
<address-group><entry name="g"><static><member %s>a</member><member>b</member></static></entry></address-group>
<profiles><virus><entry name="av"><decoder><entry name="http"><action>alert</action></entry><stray>%s</stray></decoder><mlav-engine-filebased-enabled %s/></entry></virus></profiles>
</entry></vsys></entry></devices></config>`
	before := loadXML(t, fmt.Sprintf(tmpl, "disabled", `uuid="1"`, "1", `mode="a"`))
	after := loadXML(t, fmt.Sprintf(tmpl, "enabled", `loc="x"`, "2", `mode="b"`))
	want := []Change{
		{Op: Changed, Kind: "address-group", Name: "g", Fields: []FieldChange{{Path: "static", Undescribed: true}}},
		{Op: Changed, Kind: "application-status", Name: "web-browsing", Fields: []FieldChange{{Path: "@status", Old: "disabled", New: "enabled"}}},
		{Op: Changed, Kind: "virus", Name: "av", Fields: []FieldChange{
			{Path: "decoder/stray", Undescribed: true},
			{Path: "mlav-engine-filebased-enabled/@mode", Undescribed: true},
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

// Two lists of one kind, a vsys's local users and its users, sort by their
// container, so a local user and a user of one name keep their order whatever
// the map order.
func TestCompareSortsByContainer(t *testing.T) {
	t.Parallel()
	local := `<local-user-database><user><entry name="u"><phash>%s</phash></entry></user></local-user-database>`
	before := loadXML(t, inScope(vsys1, fmt.Sprintf(local, "DUMMYHASHA")))
	after := loadXML(t, inScope(vsys1, fmt.Sprintf(local, "DUMMYHASHB")+`<user><entry name="u"/></user>`))
	want := []Change{
		{Op: Changed, Kind: "user", Name: "u", Fields: []FieldChange{{Path: "phash", Old: Hidden, New: Hidden, Secret: true}}},
		{Op: Added, Kind: "user", Name: "u"},
	}
	for range 20 {
		if got := Compare(before, after, vsys1); !reflect.DeepEqual(got, want) {
			t.Fatalf("got  %+v\nwant %+v", got, want)
		}
	}
}

// A pushed rule's kind names its rulebase, so two pushed rules of one name,
// before and after the firewall's own, tell apart, and their order does not
// depend on map order. The vsys's own rulebase keeps the plain kind.
func TestCompareNamesThePushedRulebase(t *testing.T) {
	t.Parallel()
	before := loadXML(t, `<config version="11.2.0"><shared/></config>`)
	after := loadXML(t, `<config version="11.2.0"><shared>
<post-rulebase><security><rules><entry name="r"><action>deny</action></entry></rules></security></post-rulebase>
<pre-rulebase><security><rules><entry name="r"><action>allow</action></entry></rules></security></pre-rulebase>
</shared></config>`)
	shared := config.Scope{Sort: config.ScopeShared}
	want := []Change{
		{Op: Added, Kind: "post-rulebase security rule", Name: "r", New: "deny"},
		{Op: Added, Kind: "pre-rulebase security rule", Name: "r", New: "allow"},
	}
	for range 20 {
		if got := Compare(before, after, shared); !reflect.DeepEqual(got, want) {
			t.Fatalf("got  %+v\nwant %+v", got, want)
		}
	}
	own := loadXML(t, inScope(vsys1, `<rulebase><security><rules><entry name="r"><action>allow</action></entry></rules></security></rulebase>`))
	want = []Change{{Op: Added, Kind: "security rule", Name: "r", New: "allow"}}
	if got := Compare(loadXML(t, inScope(vsys1, "")), own, vsys1); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// A secret is compared, but its value never shows: not in the field, not in
// an added or removed entry's line, not in JSON.
func TestCompareHidesSecrets(t *testing.T) {
	t.Parallel()
	raw := []string{"DUMMYKEYBEFORE0000", "DUMMYKEYAFTER00000", "DUMMYBINDBEFORE000", "DUMMYBINDAFTER0000", "DUMMYHASHBEFORE0000", "DUMMYHASHAFTER00000"}
	hidden := func(path string) []FieldChange {
		return []FieldChange{{Path: path, Old: Hidden, New: Hidden, Secret: true}}
	}
	empty := loadXML(t, `<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices></config>`)
	for _, tc := range []struct {
		after      string
		kind, name string
		want       []FieldChange
	}{
		{"cert.xml", "certificate", "cert-web", hidden("private-key")},
		{"ldap.xml", "ldap", "ldap-corp", hidden("bind-password")},
		{"phash.xml", "user", "user1", hidden("phash")},
	} {
		before, after := pair(t, "before.xml", tc.after)
		got := Compare(before, after, vsys1)
		want := []Change{{Op: Changed, Kind: tc.kind, Name: tc.name, Fields: tc.want}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got  %+v\nwant %+v", tc.after, got, want)
		}
		got = append(got, Compare(before, empty, vsys1)...)
		got = append(got, Compare(empty, after, vsys1)...)
		b, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range raw {
			if strings.Contains(string(b), v) {
				t.Errorf("%s: %s shows in %s", tc.after, v, b)
			}
		}
	}
	// Credentials the schema holds in clear text, registered by hand: the
	// same in shared and in a vsys.
	for _, tc := range []struct {
		body       string // one %s for the value
		kind, name string
		path       string
	}{
		{
			`<log-settings><snmptrap><entry name="trap1"><version><v2c><server><entry name="mgr1"><manager>10.88.6.1</manager><community>%s</community></entry></server></v2c></version></entry></snmptrap></log-settings>`,
			"snmptrap", "trap1", "version/v2c/server/mgr1/community",
		},
		{
			`<scep><entry name="scep1"><scep-url>https://scep.example.com/</scep-url><scep-challenge><fixed>%s</fixed></scep-challenge></entry></scep>`,
			"scep", "scep1", "scep-challenge/fixed",
		},
		{
			`<log-settings><http><entry name="http1"><format><traffic><headers><entry name="Authorization"><value>%s</value></entry></headers></traffic></format></entry></http></log-settings>`,
			"http", "http1", "format/traffic/headers/Authorization/value",
		},
		{
			`<log-settings><http><entry name="http1"><format><threat><params><entry name="token"><value>%s</value></entry></params></threat></format></entry></http></log-settings>`,
			"http", "http1", "format/threat/params/token/value",
		},
		{
			`<log-settings><http><entry name="http1"><format><system><url-format>/hook?token=%s</url-format></system></format></entry></http></log-settings>`,
			"http", "http1", "format/system/url-format",
		},
		{
			`<log-settings><http><entry name="http1"><format><system><payload>{"key":"%s"}</payload></system></format></entry></http></log-settings>`,
			"http", "http1", "format/system/payload",
		},
		{
			`<server-profile><mfa-server-profile><entry name="mfa1"><mfa-vendor-type>duo-security-v2</mfa-vendor-type><mfa-config><entry name="duo-secret-key"><value>%s</value></entry></mfa-config></entry></mfa-server-profile></server-profile>`,
			"mfa-server-profile", "mfa1", "mfa-config/duo-secret-key/value",
		},
	} {
		for _, sc := range []config.Scope{{Sort: config.ScopeShared}, vsys1} {
			before := loadXML(t, inScope(sc, fmt.Sprintf(tc.body, "DUMMYCLEARBEFORE00")))
			after := loadXML(t, inScope(sc, fmt.Sprintf(tc.body, "DUMMYCLEARAFTER000")))
			none := loadXML(t, inScope(sc, ""))
			got := Compare(before, after, sc)
			want := []Change{{Op: Changed, Kind: tc.kind, Name: tc.name, Fields: hidden(tc.path)}}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s: got  %+v\nwant %+v", sc, tc.path, got, want)
			}
			got = append(got, Compare(before, none, sc)...)
			got = append(got, Compare(none, after, sc)...)
			assertAbsent(t, got, "DUMMYCLEAR")
		}
	}
}

// inScope is a configuration that holds body in one scope: shared or vsys1.
func inScope(sc config.Scope, body string) string {
	if sc.Sort == config.ScopeShared {
		return `<config version="11.2.0"><shared>` + body + `</shared></config>`
	}
	return `<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">` +
		body + `</entry></vsys></entry></devices></config>`
}

// A secret set where there was none shows (secret) on the side that holds it.
func TestCompareShowsWhereASecretIsSet(t *testing.T) {
	t.Parallel()
	tmpl := `<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<certificate><entry name="c"><common-name>c.example.com</common-name>%s</entry></certificate></entry></vsys></entry></devices></config>`
	before := loadXML(t, fmt.Sprintf(tmpl, ""))
	after := loadXML(t, fmt.Sprintf(tmpl, "<private-key>-AQ==DUMMY</private-key>"))
	want := []Change{{Op: Changed, Kind: "certificate", Name: "c", Fields: []FieldChange{{Path: "private-key", New: Hidden, Secret: true}}}}
	if got := Compare(before, after, vsys1); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	want[0].Fields[0].Old, want[0].Fields[0].New = Hidden, ""
	if got := Compare(after, before, vsys1); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// A rule's short line reads only the member lists the schema describes, so a
// list it does not describe neither shows nor hides a described value of the
// same text.
func TestCompareRuleLineReadsDescribedLists(t *testing.T) {
	t.Parallel()
	none := loadXML(t, inScope(vsys1, ""))
	rule := loadXML(t, inScope(vsys1, `<rulebase><security><rules><entry name="r">
<from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination>
<future-list><member>any</member></future-list><action>allow</action>
</entry></rules></security></rulebase>`))
	want := []Change{{Op: Added, Kind: "security rule", Name: "r", New: "allow destination=any from=any source=any to=any"}}
	if got := Compare(none, rule, vsys1); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// An object's short line comes from resolve, which does not read the schema.
// An entry that holds a value the diff must not show has no short line: here
// a zone's tag list, which the schema does not describe.
func TestCompareObjectLineHoldsNoHiddenValue(t *testing.T) {
	t.Parallel()
	none := loadXML(t, inScope(vsys1, ""))
	zone := loadXML(t, inScope(vsys1, `<zone><entry name="dmz"><network><layer3><member>ethernet1/3</member></layer3></network>
<tag><member>DUMMYTAGA</member><member>DUMMYTAGB</member></tag></entry></zone>`))
	got := Compare(none, zone, vsys1)
	want := []Change{{Op: Added, Kind: "zone", Name: "dmz"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	got = append(got, Compare(zone, none, vsys1)...)
	assertAbsent(t, got, "DUMMYTAG")
	// An object without a hidden value keeps its line.
	addr := loadXML(t, inScope(vsys1, `<address><entry name="a"><ip-netmask>10.88.0.1</ip-netmask><tag><member>t1</member></tag></entry></address>`))
	want = []Change{{Op: Added, Kind: "address", Name: "a", New: "10.88.0.1 tags=t1"}}
	if got := Compare(none, addr, vsys1); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// An empty secret is still a secret, present or absent alike in both
// directions.
func TestCompareHidesAnEmptySecret(t *testing.T) {
	t.Parallel()
	tmpl := `<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<certificate><entry name="c"><common-name>c.example.com</common-name>%s</entry></certificate></entry></vsys></entry></devices></config>`
	absent := loadXML(t, fmt.Sprintf(tmpl, ""))
	empty := loadXML(t, fmt.Sprintf(tmpl, "<private-key/>"))
	want := []Change{{Op: Changed, Kind: "certificate", Name: "c", Fields: []FieldChange{{Path: "private-key", New: Hidden, Secret: true}}}}
	if got := Compare(absent, empty, vsys1); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	want[0].Fields[0].Old, want[0].Fields[0].New = Hidden, ""
	if got := Compare(empty, absent, vsys1); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}
