package card

import (
	"strings"
	"testing"

	"github.com/okaiser/panos-analyst/config"
	"github.com/okaiser/panos-analyst/index"
)

func find(t *testing.T, fixture, name, kind string) []Card {
	t.Helper()
	cfg, _, err := config.Load("../testdata/config/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.For(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := Find(cfg, idx, name, kind)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func one(t *testing.T, fixture, name string) Card {
	t.Helper()
	cs := find(t, fixture, name, "")
	if len(cs) != 1 {
		t.Fatalf("%s: %d cards", name, len(cs))
	}
	return cs[0]
}

func row(c Card, section, label string) Row {
	for _, s := range c.Sections {
		if s.Title == section {
			for _, r := range s.Rows {
				if r.Label == label {
					return r
				}
			}
		}
	}
	return Row{}
}

// flat renders items as name(value){children}, to compare whole trees at once.
func flat(items []Item) string {
	var out []string
	for _, it := range items {
		s := it.Name
		switch {
		case it.Literal:
			s += "[literal]"
		case it.Predefined:
			s += "[predefined]"
		case it.Value != "":
			s += "(" + it.Value + ")"
		}
		if len(it.Children) > 0 {
			s += "{" + flat(it.Children) + "}"
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

func TestASimpleRule(t *testing.T) {
	c := one(t, "firewall-lookup.xml", "dc-to-pve")
	if c.Kind != KindRule || c.Position != 1 || c.Of != 2 || c.Layer != "local" || c.UUID != "46ad9c77-e15c-4bab-8246-8cfb2b8b70bc" {
		t.Errorf("header = %+v", c)
	}
	for _, tc := range []struct{ section, label, want string }{
		{"source", "zones", "any"},
		{"source", "addresses", "dc01(10.1.10.100/32)"},
		{"destination", "addresses", "pve01(10.1.100.250/32)"},
		{"application", "", "ssl, web-browsing"},
		{"service", "", "pve-mgmt(tcp/8006)"},
		{"url category", "", "any"},
	} {
		if got := flat(row(c, tc.section, tc.label).Items); got != tc.want {
			t.Errorf("%s %s = %s, want %s", tc.section, tc.label, got, tc.want)
		}
	}
	if row(c, "action", "").Text != "allow" || row(c, "log", "").Text != "at session end" {
		t.Errorf("action %q, log %q", row(c, "action", "").Text, row(c, "log", "").Text)
	}
	for _, s := range c.Sections {
		if s.Title == "profile" || s.Title == "schedule" {
			t.Errorf("an unset %s must not show", s.Title)
		}
	}
}

func TestALargeRule(t *testing.T) {
	c := one(t, "firewall-lookup.xml", "branch-to-dc")
	if c.Description == "" || strings.Join(c.Tags, ",") != "branch" {
		t.Errorf("header = %+v", c)
	}
	for _, tc := range []struct{ section, label, want string }{
		{"source", "zones", "branch-vpn, sdwan"},
		{"source", "addresses", "branch-networks{net-vienna(10.20.0.0/16), net-graz(10.21.0.0/16), net-linz(10.22.0.0/16), " +
			"west-branches{net-salzburg(10.23.0.0/16)}}, tagged-laptops(dynamic, filter 'laptop' and 'managed'), 10.99.0.0/24[literal]"},
		{"source", "users", `acme\branch-staff`},
		{"destination", "addresses", "dc-mgmt{dc-mgmt-net(10.1.250.0/24), oob-net(10.1.251.0/24)}"},
		{"service", "", "svc-web{service-https[predefined], svc-rdp(tcp/3389)}"},
		{"url category", "", "corp-allowed(custom, 2 entries), business-and-economy[predefined]"},
		{"profile", "group", "strict-inspect{as-strict(spyware), url-strict(url-filtering), av-strict(virus)}"},
	} {
		if got := flat(row(c, tc.section, tc.label).Items); got != tc.want {
			t.Errorf("%s %s:\n got %s\nwant %s", tc.section, tc.label, got, tc.want)
		}
	}
	if !row(c, "destination", "addresses").Negated || row(c, "source", "addresses").Negated {
		t.Error("only the destination is negated")
	}
	if got := row(c, "log", "").Text; got != "at session start and end, forwarded to log-to-panorama" {
		t.Errorf("log = %q", got)
	}
	if row(c, "schedule", "").Text != "business-hours" {
		t.Error("the schedule must show")
	}
}

func TestObjectCards(t *testing.T) {
	a := one(t, "firewall-lookup.xml", "net-vienna")
	if a.Kind != "address" || row(a, "value", "").Text != "10.20.0.0/16" || a.Description != "Vienna office" ||
		strings.Join(a.Tags, ",") != "branch" || flat(row(a, "held by", "").Items) != "branch-networks" {
		t.Errorf("address card = %+v", a)
	}
	g := one(t, "firewall-lookup.xml", "branch-networks")
	if !strings.Contains(flat(row(g, "members", "").Items), "west-branches{net-salzburg(10.23.0.0/16)}") {
		t.Errorf("group members = %s", flat(row(g, "members", "").Items))
	}
	d := one(t, "firewall-lookup.xml", "tagged-laptops")
	if row(d, "members", "").Text != "dynamic, filter 'laptop' and 'managed'" {
		t.Errorf("dynamic group = %+v", d.Sections)
	}
	u := one(t, "firewall-lookup.xml", "corp-allowed")
	if row(u, "type", "").Text != "URL List" || flat(row(u, "entries", "").Items) != "intranet.example.com, *.corp.example.com" {
		t.Errorf("url category = %+v", u.Sections)
	}
	p := one(t, "firewall-lookup.xml", "strict-inspect")
	if flat(row(p, "profiles", "").Items) != "as-strict(spyware), url-strict(url-filtering), av-strict(virus)" {
		t.Errorf("profile group = %+v", p.Sections)
	}
	s := one(t, "firewall-lookup.xml", "svc-web")
	if flat(row(s, "members", "").Items) != "service-https[predefined], svc-rdp(tcp/3389)" {
		t.Errorf("service group = %+v", s.Sections)
	}
	f := one(t, "firewall-lookup.xml", "portal")
	if row(f, "value", "").Text != "fqdn portal.example.com" {
		t.Errorf("fqdn = %+v", f.Sections)
	}
	sh := one(t, "firewall-lookup.xml", "shared-dns")
	if sh.Scope.String() != "shared" {
		t.Errorf("a shared object's scope = %s", sh.Scope)
	}
}

func TestACycleIsCut(t *testing.T) {
	c := one(t, "firewall-cyclic-groups.xml", "g-outer")
	got := flat(row(c, "members", "").Items)
	if !strings.Contains(got, "g-outer(cycle)") {
		t.Errorf("the cycle must be cut and marked: %s", got)
	}
}

// One name can be a tag and an address group; the kind decides.
func TestFindInfersTheKind(t *testing.T) {
	cs := find(t, "firewall-lookup.xml", "dc-mgmt", "")
	if len(cs) != 2 || cs[0].Kind != "address-group" || cs[1].Kind != "tag" {
		t.Fatalf("cards = %v", cs)
	}
	if cs := find(t, "firewall-lookup.xml", "dc-mgmt", "tag"); len(cs) != 1 || cs[0].Kind != "tag" {
		t.Errorf("--kind tag = %v", cs)
	}
	if cs := find(t, "firewall-lookup.xml", "nothing-by-this-name", ""); len(cs) != 0 {
		t.Errorf("unknown name = %v", cs)
	}
	cfg, _, _ := config.Load("../testdata/config/firewall-lookup.xml")
	idx, _ := index.For(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"})
	if _, err := Find(cfg, idx, "x", "rule"); err == nil || !strings.Contains(err.Error(), "security-rule") {
		t.Errorf("an unknown kind must list the valid ones: %v", err)
	}
	if cs, _ := Find(cfg, idx, "dc-to-pve", KindRule); len(cs) != 1 {
		t.Error("--kind security-rule")
	}
}

func TestLogText(t *testing.T) {
	for _, tc := range []struct{ start, end, setting, want string }{
		{"", "", "", "at session end"},
		{"yes", "no", "", "at session start"},
		{"no", "no", "", "not logged"},
		{"yes", "yes", "fwd", "at session start and end, forwarded to fwd"},
	} {
		if got := logTextFor(tc.start, tc.end, tc.setting); got != tc.want {
			t.Errorf("%v = %q, want %q", tc, got, tc.want)
		}
	}
}

func TestAddressValue(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1": "10.0.0.1/32", "10.0.0.0/8": "10.0.0.0/8", "10.0.0.1-10.0.0.9": "range 10.0.0.1-10.0.0.9",
		"www.example.com": "fqdn www.example.com", "10.0.0.0/0.0.255.0": "wildcard 10.0.0.0/0.0.255.0",
	} {
		if got := addressValue(in); got != want {
			t.Errorf("addressValue(%s) = %s, want %s", in, got, want)
		}
	}
	if plural(1, "entry", "entries") != "1 entry" || plural(12, "entry", "entries") != "12 entries" || itoa(0) != "0" {
		t.Error("plural")
	}
}
