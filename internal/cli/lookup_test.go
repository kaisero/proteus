package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/card"
)

const lookupFile = "../../testdata/config/firewall-lookup.xml"

func TestLookupASimpleRule(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	out := c.want(0, "lookup", "dc-to-pve", "--file", lookupFile)
	want := `security rule  dc-to-pve                    position 1 of 2, local, enabled
  uuid         46ad9c77-e15c-4bab-8246-8cfb2b8b70bc

  source       zones      any
               addresses  dc01
               users      any
  destination  zones      any
               addresses  pve01
  application  ssl, web-browsing
  service      pve-mgmt
  url category any
  action       allow
  log          at session end
`
	if !strings.Contains(out, want) {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
	out = c.want(0, "lookup", "dc-to-pve", "--file", lookupFile, "--expand")
	for _, want := range []string{
		"addresses  dc01 (10.1.10.100/32)\n", "addresses  pve01 (10.1.100.250/32)\n",
		"service      pve-mgmt (tcp/8006)\n", "1 with it, 0 without, 0 holes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--expand: missing %q in:\n%s", want, out)
		}
	}
}

func TestLookupALargeRule(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	out := c.want(0, "lookup", "branch-to-dc", "--file", lookupFile)
	for _, want := range []string{
		"tags         branch\n", "description  Branch offices",
		"addresses  branch-networks, tagged-laptops, 10.99.0.0/24\n",
		"addresses  NOT dc-mgmt\n",
		"application  ssl, web-browsing, ms-rdp, ssh, dns, … (+2 more)\n",
		"profile      group      strict-inspect (as-strict, url-strict, av-strict)\n",
		"log          at session start and end, forwarded to log-to-panorama\n",
		"schedule     business-hours\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	out = c.want(0, "lookup", "branch-to-dc", "--file", lookupFile, "--expand")
	want := `               addresses  branch-networks (group, 4 members)
                            net-vienna (10.20.0.0/16)
                            net-graz (10.21.0.0/16)
                            net-linz (10.22.0.0/16)
                            west-branches (group, 1 member)
                              net-salzburg (10.23.0.0/16)
                          tagged-laptops (dynamic, filter 'laptop' and 'managed')
                          10.99.0.0/24
`
	if !strings.Contains(out, want) {
		t.Errorf("source tree:\n%s", out)
	}
	for _, want := range []string{
		"addresses  NOT dc-mgmt (group, 2 members)\n                                dc-mgmt-net (10.1.250.0/24)\n",
		"service      svc-web (group, 2 members)\n                 service-https (predefined)\n                 svc-rdp (tcp/3389)\n",
		"url category corp-allowed (custom, 2 entries), business-and-economy (predefined)\n",
		"group      strict-inspect\n                            as-strict (spyware)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--expand: missing %q in:\n%s", want, out)
		}
	}
	if out := c.want(0, "lookup", "branch-to-dc", "--file", lookupFile, "--full"); !strings.Contains(out, "dns, ldap, kerberos\n") {
		t.Errorf("--full lists every application:\n%s", out)
	}
}

func TestLookupAnObject(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	out := c.want(0, "lookup", "net-vienna", "--file", lookupFile, "--expand")
	for _, want := range []string{
		"address        net-vienna                   vsys:vsys1\n", "tags         branch\n",
		"description  Vienna office\n", "value        10.20.0.0/16\n", "held by      branch-networks\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "where it is used") {
		t.Errorf("an object card has no pointer to search:\n%s", out)
	}
	// An object card shows a group's members as a tree without --expand.
	if out := c.want(0, "lookup", "branch-networks", "--file", lookupFile); !strings.Contains(out, "               west-branches\n                 net-salzburg\n") {
		t.Errorf("group card:\n%s", out)
	}
	if out := c.want(0, "lookup", "shared-dns", "--file", lookupFile); !strings.Contains(out, "shared") {
		t.Errorf("shared object:\n%s", out)
	}
}

func TestLookupExitCodes(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	_, errOut, code := c.run("lookup", "dc-mgmt", "--file", lookupFile)
	if code != 2 || !strings.Contains(errOut, "address-group on file/vsys1") || !strings.Contains(errOut, "tag on file/vsys1") {
		t.Errorf("ambiguous: exit %d\n%s", code, errOut)
	}
	if out := c.want(0, "lookup", "dc-mgmt", "--kind", "tag", "--file", lookupFile); !strings.Contains(out, "tag            dc-mgmt") {
		t.Errorf("--kind tag:\n%s", out)
	}
	c.want(2, "lookup", "dc-mgmt", "--kind", "rule", "--file", lookupFile)
	// A name found nowhere is an empty answer, exit 0 (spec §4.2).
	if out := c.want(0, "lookup", "nothing-by-this-name", "--file", lookupFile); !strings.Contains(out, `no element named "nothing-by-this-name"`) {
		t.Errorf("not found: %s", out)
	}
	c.want(0, "lookup", "nothing", "--file", "../../testdata/config/firewall-version-12.2.xml")
	c.want(2, "lookup")
}

func TestLookupAcrossTheEstate(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	other := lab(t)
	other.Config = read(t, lookupFile)
	c.inventory(inventoryFor(lab(t).Start(t), other.Start(t), "127.0.0.1:1"))
	c.want(0, "fetch", "fw01", "fw02")
	out := c.want(3, "lookup", "net-vienna")
	for _, want := range []string{
		"fw02 / vsys1   snapshot", "address        net-vienna",
		"hole: fw03:", "1 with it, 2 without, 1 holes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "fw01 / vsys1") {
		t.Errorf("a device without the name shows no card:\n%s", out)
	}

	out = c.want(0, "lookup", "branch-to-dc", "--device", "fw02", "--output", "json")
	var env struct {
		Format  int
		Command string
		Results []struct {
			Device, Vsys, Snapshot, Scope string
			Card                          card.Card
		}
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || env.Format != 2 || env.Command != "lookup" || len(env.Results) != 1 {
		t.Fatalf("json: %v %+v", err, env)
	}
	r := env.Results[0]
	if r.Device != "fw02" || r.Snapshot == "" || r.Scope != "vsys:vsys1" || r.Card.Name != "branch-to-dc" {
		t.Errorf("result = %+v", r)
	}
	// JSON is never cut: all seven applications are there.
	for _, s := range r.Card.Sections {
		if s.Title == "application" && len(s.Rows[0].Items) != 7 {
			t.Errorf("applications = %v", s.Rows[0].Items)
		}
	}
	// A name found nowhere is an empty answer, exit 0, like a search that finds
	// nothing (spec §4.2).
	var empty struct{ Results []any }
	out = c.want(0, "lookup", "nothing", "--device", "fw01", "--output", "json")
	if err := json.Unmarshal([]byte(out), &empty); err != nil || empty.Results == nil || len(empty.Results) != 0 {
		t.Errorf("not found is results: [], got %v %s", err, out)
	}
	if out := c.want(0, "lookup", "nothing", "--device", "fw01"); !strings.Contains(out, `no element named "nothing"`) {
		t.Errorf("the text must say the name was not found:\n%s", out)
	}
}

// Trees stop at three levels; lists stop at five items.
func TestRendererCuts(t *testing.T) {
	t.Parallel()
	leaf := func(n string) card.Item { return card.Item{Name: n, Value: "v"} }
	deep := card.Item{Name: "l1", Children: []card.Item{{Name: "l2", Children: []card.Item{
		{Name: "l3", Children: []card.Item{{Name: "l4", Children: []card.Item{leaf("l5")}}, leaf("l4b")}},
	}}}}
	var b bytes.Buffer
	r := renderer{w: &b}
	got := strings.Join(r.tree([]card.Item{deep}, 1), "\n")
	if got != "l1\n  l2\n    l3\n      … (+2 more)" {
		t.Errorf("depth cut:\n%s", got)
	}
	many := []card.Item{leaf("a"), leaf("b"), leaf("c"), leaf("d"), leaf("e"), leaf("f"), leaf("g")}
	if got := strings.Join(r.tree(many, 1), "|"); got != "a|b|c|d|e|… (+2 more)" {
		t.Errorf("list cut: %s", got)
	}
	r.full, r.expand = true, true
	if got := strings.Join(r.names(many), ", "); got != "a (v), b (v), c (v), d (v), e (v), f (v), g (v)" {
		t.Errorf("--full --expand: %s", got)
	}
	r.card(card.Card{Kind: card.KindRule, Name: "off", Disabled: true, Position: 1, Of: 1, Layer: "local"})
	if !strings.Contains(b.String(), "local, DISABLED") {
		t.Errorf("a disabled rule: %s", b.String())
	}
	if plural(1, "member") != "1 member" {
		t.Error("plural")
	}
}

// The text filter card shows the criteria, the count and the first 20
// applications; --full shows all (spec 2026-10-16 §5.2, C5). JSON always
// holds all.
func TestLookupFilterCardText(t *testing.T) {
	t.Parallel()
	path := appConfig(t)
	out := newCLI(t).want(0, "lookup", "f-media", "--file", path)
	for _, want := range []string{"criteria     category   media", "applications 3 applications", "app-media, app-old, shared-media", "held by      inner"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// f-wide selects every application of risk 1 to 4: more than 20.
	raw := read(t, path)
	wide := `<entry name="f-wide"><risk><member>1</member><member>2</member><member>3</member><member>4</member></risk></entry>`
	if err := os.WriteFile(path, []byte(strings.Replace(raw, "<application-filter>", "<application-filter>"+wide, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	listed := func(out string) []string {
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "  ") && strings.Contains(l, "app-collab") {
				return strings.Split(strings.TrimSpace(l), ", ")
			}
		}
		return nil
	}
	cut := listed(newCLI(t).want(0, "lookup", "f-wide", "--file", path))
	all := listed(newCLI(t).want(0, "lookup", "f-wide", "--file", path, "--full"))
	if len(cut) != maxFilterApps+1 || !strings.HasPrefix(cut[maxFilterApps], "… (+") || len(all) <= maxFilterApps ||
		slices.ContainsFunc(all, func(s string) bool { return strings.HasPrefix(s, "…") }) {
		t.Errorf("cut %d: %v\nfull %d: %v", len(cut), cut, len(all), all)
	}
	var env struct{ Results []struct{ Card card.Card } }
	if err := json.Unmarshal([]byte(newCLI(t).want(0, "lookup", "f-wide", "--file", path, "--output", "json")), &env); err != nil || len(env.Results) != 1 {
		t.Fatalf("json: %v", err)
	}
	for _, s := range env.Results[0].Card.Sections {
		if s.Title == "applications" && len(s.Rows[1].Items) != len(all) {
			t.Errorf("json holds %d applications, --full %d", len(s.Rows[1].Items), len(all))
		}
	}
}

// The text group card of the identity data shows the source, the count and
// the first 20 members, one per line; --full shows all (spec 2026-10-17 §6.2).
// The user card shows each section, a group with its source, and none for an
// empty section.
func TestLookupGroupCardText(t *testing.T) {
	t.Parallel()
	out := newCLI(t).want(0, "lookup", "cn=domain users,cn=users,dc=example,dc=com", "--file", userConfig(t))
	for _, want := range []string{
		"identity group  cn=domain users,cn=users,dc=example,dc=com vsys:vsys1\n",
		"  source           ldap:example.com\n",
		"  members          3 members\n                   example.com\\alice\n                   example.com\\bob\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	user := newCLI(t).want(0, "lookup", "alice@example.com", "--file", userConfig(t))
	for _, want := range []string{
		"  groups           cn=domain users,cn=users,dc=example,dc=com (ldap:example.com)\n",
		"  mapped addresses 198.51.100.11 (XMLAPI, timeout 14400 s)\n",
		"  tags             none\n",
	} {
		if !strings.Contains(user, want) {
			t.Errorf("missing %q in:\n%s", want, user)
		}
	}
	var items []card.Item
	for i := 1; i <= 25; i++ {
		items = append(items, card.Item{Name: fmt.Sprintf(`example.com\member-%02d`, i)})
	}
	big := card.Card{Kind: card.KindIdentityGroup, Name: "cn=big,ou=groups,dc=example,dc=com", Sections: []card.Section{
		{Title: "members", Rows: []card.Row{{Text: "25 members"}, {Items: items}}},
	}}
	lines := func(full bool) []string {
		var b bytes.Buffer
		renderer{w: &b, full: full}.card(big)
		return strings.Split(strings.TrimSpace(b.String()), "\n")
	}
	cut, all := lines(false), lines(true)
	// The head, a blank line, the count, the members, and the cut line.
	if len(cut) != 3+maxGroupMembers+1 || cut[len(cut)-1] != strings.Repeat(" ", 2+identityTitleWidth)+"… (+5 more)" {
		t.Errorf("cut:\n%s", strings.Join(cut, "\n"))
	}
	if len(all) != 3+25 || strings.Contains(strings.Join(all, "\n"), "more") {
		t.Errorf("--full:\n%s", strings.Join(all, "\n"))
	}
}
