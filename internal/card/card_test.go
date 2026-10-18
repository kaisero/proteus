package card

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/testconfig"
)

func find(t *testing.T, fixture, name, kind string) []Card {
	t.Helper()
	cfg, _, err := config.Load("../../testdata/config/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := Find(cfg, idx, nil, name, kind)
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	c := one(t, "firewall-cyclic-groups.xml", "g-outer")
	got := flat(row(c, "members", "").Items)
	if !strings.Contains(got, "g-outer(cycle)") {
		t.Errorf("the cycle must be cut and marked: %s", got)
	}
}

// One name can be a tag and an address group; the kind decides.
func TestFindInfersTheKind(t *testing.T) {
	t.Parallel()
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
	cfg, _, _ := config.Load("../../testdata/config/firewall-lookup.xml")
	idx, _ := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if _, err := Find(cfg, idx, nil, "x", "rule"); err == nil || !strings.Contains(err.Error(), "security-rule") {
		t.Errorf("an unknown kind must list the valid ones: %v", err)
	}
	if cs, _ := Find(cfg, idx, nil, "dc-to-pve", KindRule); len(cs) != 1 {
		t.Error("--kind security-rule")
	}
}

func TestLogText(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// A dynamic group whose filter starts with a parenthesis shows its filter, not
// the filter text as a fake member (L1).
func TestDynamicGroupWithAParenthesisedFilter(t *testing.T) {
	t.Parallel()
	d := one(t, "firewall-dynamic-filter.xml", "dag-paren")
	if got := row(d, "members", "").Text; got != "dynamic, filter ('t-a' or 't-b')" {
		t.Errorf("members = %q, sections %+v", got, d.Sections)
	}
}

// A wildcard address object shows its address and mask (L2).
func TestWildcardAddressShowsItsValue(t *testing.T) {
	t.Parallel()
	a := one(t, "firewall-wildcard.xml", "wc")
	if got := row(a, "value", "").Text; got != "wildcard 10.88.2.1/0.0.255.0" {
		t.Errorf("value = %q, sections %+v", got, a.Sections)
	}
}

// lookup shows a predefined service stored next to the configuration (L4) with
// its ports and scope predefined, and a rule naming it with the ports. A
// configured service of the same name hides it (L7).
func TestAPredefinedServiceCard(t *testing.T) {
	t.Parallel()
	s := one(t, "../predefined/config.xml", "service-https")
	if s.Kind != "service" || s.Scope.String() != "predefined" || row(s, "value", "").Text != "tcp/443" || s.Shadows != "" {
		t.Errorf("service-https = %+v", s)
	}
	g := one(t, "../predefined/config.xml", "g-web")
	if flat(row(g, "members", "").Items) != "service-http(tcp/80,8080)" {
		t.Errorf("g-web = %+v", g.Sections)
	}
	r := one(t, "../predefined/config.xml", "web-https")
	if got := flat(row(r, "service", "").Items); got != "service-https(tcp/443)" {
		t.Errorf("web-https service = %s", got)
	}
	c := one(t, "../predefined-configured/config.xml", "service-https")
	if c.Scope.String() != "vsys:vsys1" || row(c, "value", "").Text != "tcp/8443" || c.Shadows != "predefined" {
		t.Errorf("configured service-https = %+v", c)
	}
}

// As observed on fw02, PAN-OS 12.2.3 (L9): a service name resolves by scope
// first, kind second. vsys1's service group service-https hides the predefined
// service, and vsys1's service web hides shared's service group web, so the
// cards and a rule's service show only the vsys objects.
func TestAServiceNameResolvesByScopeFirst(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{"service-https": "service-group vsys:vsys1", "web": "service vsys:vsys1"} {
		cs := find(t, "../predefined-cross-kind/config.xml", name, "")
		var got []string
		for _, c := range cs {
			got = append(got, c.Kind+" "+c.Scope.String())
		}
		if strings.Join(got, "; ") != want {
			t.Errorf("%s: cards %v, want %s", name, got, want)
		}
	}
	for rule, want := range map[string]string{"sec-https": "service-https{svc-8443(tcp/8443)}", "sec-web": "web(tcp/8081)"} {
		if got := flat(row(one(t, "../predefined-cross-kind/config.xml", rule), "service", "").Items); got != want {
			t.Errorf("%s service = %s, want %s", rule, got, want)
		}
	}
}

// A group opens at its shallowest place on a card. The rule's source names all
// and web, and all holds web as its seventh member, where a rendered card cuts
// the list; so web opens where the rule names it, and inside all it says its
// members are shown elsewhere.
func TestAGroupOpensAtItsShallowestPlace(t *testing.T) {
	t.Parallel()
	var addrs, members strings.Builder
	for i := range 6 {
		fmt.Fprintf(&addrs, `<entry name="a%d"><ip-netmask>10.88.0.%d</ip-netmask></entry>`, i, i+1)
		fmt.Fprintf(&members, `<member>a%d</member>`, i)
	}
	doc := `<config version="11.2.0" urldb="paloaltonetworks"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">` +
		`<address>` + addrs.String() + `<entry name="w1"><ip-netmask>10.88.1.1</ip-netmask></entry></address>` +
		`<address-group><entry name="all"><static>` + members.String() + `<member>web</member></static></entry>` +
		`<entry name="web"><static><member>w1</member></static></entry></address-group>` +
		`<rulebase><security><rules><entry name="r1"><from><member>any</member></from><to><member>any</member></to>` +
		`<source><member>all</member><member>web</member></source><destination><member>any</member></destination>` +
		`<application><member>any</member></application><service><member>any</member></service><action>allow</action>` +
		`</entry></rules></security></rulebase></entry></vsys></entry></devices></config>`
	path := filepath.Join(t.TempDir(), "firewall.xml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := Find(cfg, idx, nil, "r1", KindRule)
	if err != nil || len(cs) != 1 {
		t.Fatalf("Find: %d cards, %v", len(cs), err)
	}
	want := "all{a0(10.88.0.1/32), a1(10.88.0.2/32), a2(10.88.0.3/32), a3(10.88.0.4/32), a4(10.88.0.5/32), a5(10.88.0.6/32), " +
		"web(members shown elsewhere on this card)}, web{w1(10.88.1.1/32)}"
	if got := flat(row(cs[0], "source", "addresses").Items); got != want {
		t.Errorf("source = %s\nwant     %s", got, want)
	}
}

// As observed on fw02, PAN-OS 12.2.3 (L10): addresses resolve by scope first,
// kind second, as services do.
func TestAnAddressNameResolvesByScopeFirst(t *testing.T) {
	t.Parallel()
	for rule, want := range map[string]string{"sec-a": "rv-adr(10.88.8.8/32)", "sec-b": "rv-adr2{rv-a6(10.88.6.6/32)}"} {
		if got := flat(row(one(t, "firewall-address-cross-kind.xml", rule), "source", "addresses").Items); got != want {
			t.Errorf("%s source = %s, want %s", rule, got, want)
		}
	}
}

// An address and a service may share a name; each card lists only the groups of
// its own kind that hold it.
func TestHeldByKeepsToTheObjectsKind(t *testing.T) {
	t.Parallel()
	held := map[string]string{}
	for _, c := range find(t, "firewall-shared-names.xml", "dual", "") {
		held[c.Kind] = flat(row(c, "held by", "").Items)
	}
	if held["address"] != "g-dual-addr" || held["service"] != "g-dual-svc" {
		t.Errorf("held by = %v", held)
	}
	if got := flat(row(one(t, "firewall-shared-names.xml", "svc-web"), "held by", "").Items); got != "webgrp" {
		t.Errorf("svc-web held by %s", got)
	}
}

// A group that several groups hold opens once on a card: met again, it shows no
// members and says so. A group met inside itself is still a cycle. So the card of
// the first of 30 groups that each hold three others names each group's members
// once; before, it opened a group on every path to it, and grew exponentially.
func TestACardOpensEachGroupOnce(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load(testconfig.Write(t, testconfig.Groups{Addrs: 100, Dense: 30}))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := Find(cfg, idx, nil, "d-0", "address-group")
	if err != nil || len(cs) != 1 {
		t.Fatalf("Find: %d cards, %v", len(cs), err)
	}
	opened := map[string]int{"d-0": 1}
	marks := map[string]int{}
	items := 0
	var walk func([]Item)
	walk = func(its []Item) {
		for _, it := range its {
			items++
			if it.Kind != "address-group" {
				continue
			}
			if len(it.Children) > 0 {
				opened[it.Name]++
				walk(it.Children)
				continue
			}
			marks[it.Value]++
		}
	}
	walk(row(cs[0], "members", "").Items)
	for g, n := range opened {
		if n != 1 {
			t.Errorf("%s opened %d times, want once", g, n)
		}
	}
	// Each of the 30 groups opens once and names three groups and an address.
	if len(opened) != 30 || items != 30*4 || marks["cycle"] == 0 || marks["members shown elsewhere on this card"] == 0 ||
		marks["cycle"]+marks["members shown elsewhere on this card"] != 30*3-29 {
		t.Errorf("%d groups opened, %d items, marks %v", len(opened), items, marks)
	}
}

// An application group lists its members by name, and an external list says what
// it is: the configuration holds neither's contents.
func TestApplicationGroupAndExternalListCards(t *testing.T) {
	t.Parallel()
	g := one(t, "firewall-apps.xml", "erp-bundle")
	if g.Kind != "application-group" || flat(row(g, "members", "").Items) != "custom-erp, ssl" {
		t.Errorf("application group = %+v", g)
	}
	e := one(t, "firewall-opaque.xml", "edl-bad")
	if e.Kind != "external-list" || row(e, "value", "").Text != "external list, ip" {
		t.Errorf("external list = %+v", e)
	}
}

// findApps finds a name in vsys1 of firewall-appid.xml with the App-ID content
// data of testdata/appid/content.xml, or without it when apps is false.
func findApps(t *testing.T, name, kind string, apps bool) []Card {
	t.Helper()
	return findAppsIn(t, "../../testdata/config/firewall-appid.xml", name, kind, apps)
}

// findAppsIn is findApps on another configuration.
func findAppsIn(t *testing.T, path, name, kind string, apps bool) []Card {
	t.Helper()
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if err != nil {
		t.Fatal(err)
	}
	var data *appid.Data
	if apps {
		gz := filepath.Join(t.TempDir(), "apps.xml.gz")
		testconfig.Content(t, gz)
		if data, err = appid.Load(gz); err != nil {
			t.Fatal(err)
		}
	}
	cs, err := Find(cfg, idx, data, name, kind)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// oneApp is the one card of a name with the App-ID data.
func oneApp(t *testing.T, name string) Card {
	t.Helper()
	cs := findApps(t, name, "", true)
	if len(cs) != 1 {
		t.Fatalf("%s: %d cards", name, len(cs))
	}
	return cs[0]
}

// The application card shows the default ports and the applications the
// application uses and implies (spec 2026-10-16 §5.2).
func TestLookupAppCard(t *testing.T) {
	t.Parallel()
	c := oneApp(t, "app-remote")
	if c.Kind != KindApplication || c.Scope.String() != "predefined" {
		t.Fatalf("header = %+v", c)
	}
	for _, tc := range []struct{ section, want string }{
		{"category", "networking"},
		{"subcategory", "remote-access"},
		{"technology", "client-server"},
		{"risk", "4"},
		{"default", "tcp/80,443,8090"},
	} {
		if got := row(c, tc.section, "").Text; got != tc.want {
			t.Errorf("%s = %q, want %q", tc.section, got, tc.want)
		}
	}
	if got := flat(row(c, "implicit uses", "").Items); got != "ssl, web-browsing" {
		t.Errorf("implicit uses = %s", got)
	}
	if got := flat(row(c, "uses", "").Items); got != "dns" {
		t.Errorf("uses = %s", got)
	}
	// The flags hold ident-by-dport (F12); obsolete and the container show
	// when set; the tags count application-tag (S12).
	ssl := oneApp(t, "SSL")
	if ssl.Name != "ssl" || !strings.Contains(flat(row(ssl, "flags", "").Items), "ident-by-dport") || ssl.Description == "" {
		t.Errorf("ssl = %+v", ssl)
	}
	if old := oneApp(t, "app-old"); row(old, "obsolete", "").Text != "yes" {
		t.Errorf("app-old = %+v", old)
	}
	if docs := oneApp(t, "office-docs"); row(docs, "container", "").Text != "office-suite" {
		t.Errorf("office-docs = %+v", docs)
	}
	if media := oneApp(t, "app-media"); flat(row(media, "tags", "").Items) != "[Web App], [Streaming], t-sanctioned" {
		t.Errorf("app-media tags = %s", flat(row(media, "tags", "").Items))
	}
}

// parent and tunnels show the names as the content writes them: the parent is
// no application, and the tunnel name is unknown (spec 2026-10-16 F15).
func TestLookupAppCardShowsNamesAsWritten(t *testing.T) {
	t.Parallel()
	c := oneApp(t, "app-parent")
	if row(c, "parent", "").Text != "not-an-app" || flat(row(c, "tunnels", "").Items) != "unknown-tunnel" {
		t.Errorf("app-parent = %+v", c)
	}
}

// A custom application has its application card from the configuration, with
// or without data; a predefined application and a container need the data.
func TestLookupAppCardOfACustomApplication(t *testing.T) {
	t.Parallel()
	cs := findApps(t, "erp-custom", "", false)
	if len(cs) != 1 || cs[0].Kind != KindApplication || cs[0].Scope.String() != "vsys:vsys1" ||
		row(cs[0], "default", "").Text != "tcp/8443" || !strings.Contains(flat(row(cs[0], "flags", "").Items), "able-to-transfer-file") {
		t.Errorf("erp-custom = %+v", cs)
	}
	if cs := findApps(t, "erp-nodefault", "", false); len(cs) != 1 || row(cs[0], "default", "").Text != "any" {
		t.Errorf("erp-nodefault = %+v", cs)
	}
	for _, name := range []string{"ssl", "office-suite"} {
		if cs := findApps(t, name, "", false); len(cs) != 0 {
			t.Errorf("%s without data = %+v", name, cs)
		}
	}
	ct := oneApp(t, "office-suite")
	if ct.Kind != KindContainer || flat(row(ct, "functions", "").Items) != "office-docs, office-mail" {
		t.Errorf("office-suite = %+v", ct)
	}
	if cs := findApps(t, "office-suite", KindContainer, true); len(cs) != 1 {
		t.Errorf("--kind %s = %+v", KindContainer, cs)
	}
}

// The filter card shows the criteria and the applications the filter
// selects, by name, with their count: custom ones too (S5). Without data the
// applications are unknown (spec 2026-10-16 §5.2).
func TestLookupFilterCard(t *testing.T) {
	t.Parallel()
	c := oneApp(t, "f-media")
	if c.Kind != KindFilter || row(c, "criteria", "category").Text != "media" {
		t.Fatalf("f-media = %+v", c)
	}
	apps := c.Sections[slices.IndexFunc(c.Sections, func(s Section) bool { return s.Title == "applications" })]
	if len(apps.Rows) != 2 || apps.Rows[0].Text != "3 applications" || flat(apps.Rows[1].Items) != "app-media, app-old, shared-media" {
		t.Errorf("applications = %+v", apps)
	}
	if flat(row(c, "held by", "").Items) != "inner" {
		t.Errorf("held by = %+v", row(c, "held by", ""))
	}
	risky := oneApp(t, "f-risky")
	if row(risky, "criteria", "exclude").Text != "app-old, office-suite" || row(risky, "criteria", "tag").Text != "[Streaming]" {
		t.Errorf("f-risky = %+v", risky)
	}
	cs := findApps(t, "f-media", "", false)
	if len(cs) != 1 || row(cs[0], "applications", "").Text != "unknown: no application data" {
		t.Errorf("f-media without data = %+v", cs)
	}
}

// A vsys application and a vsys filter that hide shared ones of their name
// say so, as every object card does.
func TestAppCardsNameWhatTheyShadow(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../testdata/config/firewall-appid.xml")
	if err != nil {
		t.Fatal(err)
	}
	shared := `<application-filter><entry name="f-media"><risk><member>1</member></risk></entry></application-filter>` +
		`<application><entry name="erp-custom"><category>media</category><risk>1</risk></entry>`
	out := strings.Replace(string(raw), "<shared>\n    <application>", "<shared>"+shared, 1)
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"f-media", "erp-custom"} {
		if cs := findAppsIn(t, path, name, "", true); len(cs) != 1 || cs[0].Shadows != "shared" {
			t.Errorf("%s = %+v", name, cs)
		}
	}
}

// Lookup knows the container kind, which no configuration defines.
func TestKindsNameTheContainer(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-appid.xml")
	if err != nil {
		t.Fatal(err)
	}
	kinds := Kinds(cfg)
	if !slices.Contains(kinds, KindContainer) || !slices.IsSorted(kinds[1:]) || kinds[0] != KindRule {
		t.Errorf("kinds = %v", kinds)
	}
}
