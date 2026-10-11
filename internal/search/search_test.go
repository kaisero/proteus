package search

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
)

func run(t *testing.T, fixture, vsys string, q Query) []Finding {
	t.Helper()
	cfg, _, err := config.Load("../../testdata/config/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: vsys}, resolve.Security)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Run(cfg, idx, q)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// line renders a finding compactly, so a test can ask whether one is present.
func line(f Finding) string {
	return fmt.Sprintf("%s %s %s %s %s", f.Stage, f.Kind, f.Name, f.Field, f.Via)
}

func has(fs []Finding, want string) bool {
	for _, f := range fs {
		if strings.HasPrefix(line(f), want) {
			return true
		}
	}
	return false
}

func dump(fs []Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, line(f))
	}
	return strings.Join(out, "\n")
}

// An address finds the objects covering it, the groups holding them (a shared
// dynamic group by tag), and the rule naming the group.
func TestAnAddressFollowsEveryStage(t *testing.T) {
	t.Parallel()
	got := run(t, "firewall-multivsys.xml", "vsys1", Query{Term: "10.124.0.1"})
	for _, want := range []string{
		"object address corp-dc-vienna  10.124.0.1/32",
		"object address corp-location-vienna  10.124.0.0/16",
		"group address-group corp-location  holds corp-location-vienna",
		"group address-group corp-dc  holds corp-dc-vienna",
		"reference security rule Corp DC Access source corp-location",
		"reference security rule Corp DC Access destination corp-dc",
	} {
		if !has(got, want) {
			t.Errorf("missing %q in:\n%s", want, dump(got))
		}
	}
	// The tag corp-location shares a name with the group; a tag field naming the tag
	// does not name the group.
	for _, f := range got {
		if f.Stage == StageReference && f.Field == "tag" {
			t.Errorf("a tag reference was taken for a group reference: %s", line(f))
		}
	}
}

func TestGroupsAreTransitiveUnlessDirect(t *testing.T) {
	t.Parallel()
	got := run(t, "firewall-nested-groups.xml", "vsys1", Query{Term: "10.1.1.1"})
	for _, g := range []string{"g-inner", "g-middle", "g-outer"} {
		if !has(got, "group address-group "+g) {
			t.Errorf("transitive groups miss %s:\n%s", g, dump(got))
		}
	}
	if !has(got, "reference security rule allow-outer source g-outer") {
		t.Errorf("the rule three groups up is missing:\n%s", dump(got))
	}
	direct := run(t, "firewall-nested-groups.xml", "vsys1", Query{Term: "10.1.1.1", Direct: true})
	if has(direct, "group address-group g-middle") || !has(direct, "group address-group g-inner") {
		t.Errorf("--direct must stop one level up:\n%s", dump(direct))
	}
}

func TestLiteralsAreFound(t *testing.T) {
	t.Parallel()
	got := run(t, "firewall-literals.xml", "vsys1", Query{Term: "198.18.1.1"})
	for _, want := range []string{
		"literal security rule literal-host source 198.18.1.1/32",
		"literal security rule literal-net source 198.18.0.0/16",
		"object address named-host  198.18.1.1/32",
		"reference security rule named-rule source named-host",
	} {
		if !has(got, want) {
			t.Errorf("missing %q in:\n%s", want, dump(got))
		}
	}
}

// A prefix overlaps; --within keeps only what lies inside; --exact only the equal.
func TestAddressModes(t *testing.T) {
	t.Parallel()
	over := run(t, "firewall-multivsys.xml", "vsys1", Query{Term: "10.124.0.0/24"})
	if !has(over, "object address corp-location-vienna") || !has(over, "object address corp-dc-vienna") {
		t.Errorf("a prefix must overlap both:\n%s", dump(over))
	}
	within := run(t, "firewall-multivsys.xml", "vsys1", Query{Term: "10.124.0.0/24", Mode: Within})
	if has(within, "object address corp-location-vienna") || !has(within, "object address corp-dc-vienna") {
		t.Errorf("--within keeps only the host inside the /24:\n%s", dump(within))
	}
	exact := run(t, "firewall-multivsys.xml", "vsys1", Query{Term: "10.124.0.0/16", Mode: Exact})
	if !has(exact, "object address corp-location-vienna") || has(exact, "object address corp-dc-vienna") {
		t.Errorf("--exact keeps only the equal /16:\n%s", dump(exact))
	}
	rng := run(t, "firewall-multivsys.xml", "vsys1", Query{Term: "10.124.0.1-10.124.0.2"})
	if !has(rng, "object address corp-dc-vienna") {
		t.Errorf("a range must overlap the host:\n%s", dump(rng))
	}
}

// A wildcard object matches by mask (L2). One address decides it, so the object,
// its group and the rules naming either are found. A prefix, or a mode that
// compares values, cannot decide it: the object is unresolved (decision C1).
func TestWildcardObjects(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-wildcard.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		term       string
		mode       Mode
		kinds      []string
		found      bool
		unresolved bool
	}{
		{"10.88.7.1", Auto, nil, true, false},
		{"10.88.7.1/32", Auto, nil, true, false},
		{"10.88.7.1-10.88.7.1", Auto, nil, true, false},
		{"10.88.200.1", Auto, nil, true, false},
		{"10.88.7.2", Auto, nil, false, false},
		{"10.88.7.2/32", Auto, nil, false, false},
		{"10.89.7.1", Auto, nil, false, false},
		{"10.88.0.0/16", Auto, nil, false, true},
		{"10.88.0.0/16", Within, nil, false, true},
		{"10.88.7.1", Exact, nil, false, true},
		{"10.88.7.0-10.88.7.1", Auto, nil, false, true},
		{"10.89.0.0/16", Auto, nil, false, false},
		{"10.88.0.0/16", Auto, []string{"service"}, false, false},
		{"0.0.255", Contains, nil, true, false},
	} {
		fs, un, err := Run(cfg, idx, Query{Term: tc.term, Mode: tc.mode, Kinds: tc.kinds})
		if err != nil {
			t.Fatal(err)
		}
		if got := has(fs, "object address wc  10.88.2.1/0.0.255.0"); got != tc.found {
			t.Errorf("%s (%d): found %v, want %v:\n%s", tc.term, tc.mode, got, tc.found, dump(fs))
		}
		if tc.found && tc.mode == Auto {
			for _, want := range []string{"group address-group g-wc  holds wc", "reference security rule from-wc source", "reference security rule to-g-wc destination"} {
				if !has(fs, want) {
					t.Errorf("%s: %q missing:\n%s", tc.term, want, dump(fs))
				}
			}
		}
		// The reason names the prefix of the term the object may hold an address of.
		got := len(un) == 1 && un[0].Value == "wc" && un[0].Code == "gap.address-wildcard" &&
			strings.HasSuffix(un[0].Reason, " for "+index.PrefixesOf(tc.term)[0].String())
		if got != tc.unresolved || len(un) > 1 {
			t.Errorf("%s (%d): unresolved %v, want %v", tc.term, tc.mode, un, tc.unresolved)
		}
	}
}

func TestWithinNeedsAnAddress(t *testing.T) {
	t.Parallel()
	cfg, _, _ := config.Load("../../testdata/config/firewall-multivsys.xml")
	idx, _ := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if _, _, err := Run(cfg, idx, Query{Term: "web", Mode: Within}); !errors.Is(err, ErrWithinNeedsAddress) {
		t.Errorf("got %v", err)
	}
}

func TestContainsSearchesValuesAndNames(t *testing.T) {
	t.Parallel()
	got := run(t, "firewall-urlcat.xml", "vsys1", Query{Term: "azureapps", Mode: Contains})
	if !has(got, "object custom-url-category custom-azuresite-group  superlong.example.azureapps.microsoft.com") {
		t.Errorf("a value fragment must be found:\n%s", dump(got))
	}
	byName := run(t, "firewall-multivsys.xml", "vsys1", Query{Term: "VIENNA", Mode: Contains})
	if !has(byName, "object address corp-location-vienna  name") {
		t.Errorf("a name fragment must be found, ignoring case:\n%s", dump(byName))
	}
}

func TestExactValueWithoutAnAddress(t *testing.T) {
	t.Parallel()
	got := run(t, "firewall-urlcat.xml", "vsys1", Query{Term: "superlong.example.azureapps.microsoft.com", Mode: Exact})
	if !has(got, "object custom-url-category custom-azuresite-group") {
		t.Errorf("an equal value must be found:\n%s", dump(got))
	}
	if part := run(t, "firewall-urlcat.xml", "vsys1", Query{Term: "azureapps", Mode: Exact}); len(part) != 0 {
		t.Errorf("--exact must not match a fragment:\n%s", dump(part))
	}
}

// A URL reaches a rule through the category and through the rule's profiles.
func TestAURLFollowsProfiles(t *testing.T) {
	t.Parallel()
	got := run(t, "firewall-urlprofile.xml", "vsys1", Query{Term: "demo-category"})
	if !has(got, "object custom-url-category demo-category  name") {
		t.Errorf("the category by name is missing:\n%s", dump(got))
	}
	if !has(got, "reference security rule via-group profile-setting") ||
		!has(got, "reference security rule via-named-profile profile-setting") {
		t.Errorf("the rules reaching it through profiles are missing:\n%s", dump(got))
	}
}

// Any-rules reach every value, but search is not a simulation: they never appear.
func TestAnyRulesAreLeftOut(t *testing.T) {
	t.Parallel()
	got := run(t, "firewall-anyrule.xml", "vsys1", Query{Term: "10.0.0.1"})
	for _, f := range got {
		if f.Stage == StageLiteral || f.Stage == StageReference {
			if strings.Contains(f.Via, "any") {
				t.Errorf("an any-rule appeared: %s", line(f))
			}
		}
	}
}

func TestFilters(t *testing.T) {
	t.Parallel()
	kinds := run(t, "firewall-multivsys.xml", "vsys1", Query{Term: "10.124.0.1", Kinds: []string{"address"}})
	if has(kinds, "group ") {
		t.Errorf("--kind address must drop groups:\n%s", dump(kinds))
	}
	fields := run(t, "firewall-multivsys.xml", "vsys1", Query{Term: "10.124.0.1", Fields: []string{"destination"}})
	if has(fields, "reference security rule Corp DC Access source") || !has(fields, "reference security rule Corp DC Access destination") {
		t.Errorf("--field destination keeps only destination references:\n%s", dump(fields))
	}
	show := run(t, "firewall-multivsys.xml", "vsys1", Query{Term: "10.124.0.1", Show: []Stage{StageObject}})
	for _, f := range show {
		if f.Stage != StageObject {
			t.Errorf("--show object printed %s", line(f))
		}
	}
}

// A port or a service name finds services through the service value space.
func TestAPortFindsServices(t *testing.T) {
	t.Parallel()
	got := run(t, "firewall-urlcat.xml", "vsys1", Query{Term: "tcp/8006"})
	if !has(got, "object service svc-pve") || !has(got, "object service svc-range") {
		t.Errorf("tcp/8006 must find the exact port and the range covering it:\n%s", dump(got))
	}
	byName := run(t, "firewall-multivsys.xml", "vsys1", Query{Term: "corp-dc-vienna"})
	if !has(byName, "object address corp-dc-vienna  name") || !has(byName, "group address-group corp-dc") {
		t.Errorf("a name must find the object and its groups:\n%s", dump(byName))
	}
}

// A port finds a predefined service, stored next to the configuration (L4), in
// scope predefined, with the groups and rules that use it.
func TestAPortFindsAPredefinedService(t *testing.T) {
	t.Parallel()
	got := run(t, "../predefined/config.xml", "vsys1", Query{Term: "tcp/8080"})
	for _, want := range []string{
		"object service service-http  tcp/8080",
		"group service-group g-web",
		"reference nat rule dnat-http service service-http",
	} {
		if !has(got, want) {
			t.Errorf("missing %q:\n%s", want, dump(got))
		}
	}
	for _, f := range got {
		if f.Name == "service-http" && f.Scope.String() != "predefined" {
			t.Errorf("service-http in scope %s", f.Scope)
		}
	}
	if has(got, "object service service-https") {
		t.Errorf("tcp/8080 is not service-https:\n%s", dump(got))
	}
}

func TestReferrer(t *testing.T) {
	t.Parallel()
	for path, want := range map[string]string{
		"/config/devices/x/vsys/vsys1/rulebase/security/rules/r1": "security rule r1",
		"/config/devices/x/vsys/vsys1/rulebase/nat/rules/n1":      "nat rule n1",
		"/config/devices/x/vsys/vsys1/address-group/g":            "address-group g",
		"lonely": "entry lonely",
	} {
		k, n := referrer(path)
		if k+" "+n != want {
			t.Errorf("referrer(%s) = %s %s, want %s", path, k, n, want)
		}
	}
}

// A directory user reaches the rules naming its directory groups when a user
// snapshot supplies them.
func TestAUserSnapshotResolvesDirectoryGroups(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/users-snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	users, err := index.LoadUserSnapshot(f)
	if err != nil {
		t.Fatal(err)
	}
	without := run(t, "firewall-users.xml", "vsys1", Query{Term: `ACME\carol`})
	with := run(t, "firewall-users.xml", "vsys1", Query{Term: `ACME\carol`, Providers: index.Providers{Users: users}})
	if has(without, "reference security rule engineering-allowed") {
		t.Errorf("without a snapshot carol's directory group is unknown:\n%s", dump(without))
	}
	if !has(with, "reference security rule engineering-allowed source-user engineering") {
		t.Errorf("with a snapshot carol reaches engineering-allowed:\n%s", dump(with))
	}
}

// A name can be several kinds at once: tag web and address group web, address
// group webgrp and service group webgrp. Each kind finds its own groups and its
// own references, and a reference to a name found as several kinds says which
// kind its field names.
func TestANameWithSeveralKinds(t *testing.T) {
	t.Parallel()
	const fixture = "firewall-shared-names.xml"
	for _, tc := range []struct {
		term      string
		want, not []string
	}{
		{"web", []string{
			"object address-group web  name",
			"object tag web  name",
			"reference security rule to-web destination web (address-group)",
			"reference security rule by-tag tag web (tag)",
		}, nil},
		{"10.88.4.10", []string{
			"group address-group web  holds h-web",
			"reference security rule to-web destination web",
		}, []string{"reference security rule by-tag"}},
		{"webgrp", []string{
			"object address-group webgrp  name",
			"object service-group webgrp  name",
			"reference security rule src-webgrp source webgrp (address-group)",
			"reference security rule svc-webgrp service webgrp (service-group)",
		}, nil},
		{"tcp/8443", []string{
			"object service svc-web",
			"group service-group webgrp  holds svc-web",
			"reference security rule svc-webgrp service webgrp",
		}, []string{"group address-group webgrp", "reference security rule src-webgrp"}},
		{"10.88.4.20", []string{
			"group address-group webgrp  holds h-api",
			"reference security rule src-webgrp source webgrp",
		}, []string{"group service-group webgrp", "reference security rule svc-webgrp"}},
		{"10.88.4.30", []string{"group address-group g-dual-addr  holds dual"}, []string{"group service-group"}},
		{"tcp/9000", []string{"group service-group g-dual-svc  holds dual"}, []string{"group address-group"}},
	} {
		got := run(t, fixture, "vsys1", Query{Term: tc.term})
		for _, want := range tc.want {
			if !has(got, want) {
				t.Errorf("%s: missing %q in:\n%s", tc.term, want, dump(got))
			}
		}
		for _, not := range tc.not {
			if has(got, not) {
				t.Errorf("%s: unexpected %q in:\n%s", tc.term, not, dump(got))
			}
		}
		// A name found as one kind needs no kind in its reference.
		if tc.term != "web" && tc.term != "webgrp" && strings.Contains(dump(got), "(") {
			t.Errorf("%s: a kind named without need:\n%s", tc.term, dump(got))
		}
	}
	// A kind filter keeps the tag and drops the group of the same name, with its
	// references.
	got := run(t, fixture, "vsys1", Query{Term: "web", Kinds: []string{"tag"}})
	if !has(got, "object tag web") || has(got, "object address-group") || has(got, "reference security rule to-web") ||
		!has(got, "reference security rule by-tag tag web") {
		t.Errorf("kind tag:\n%s", dump(got))
	}
	// Direct asks one level up, by kind too.
	got = run(t, fixture, "vsys1", Query{Term: "tcp/8443", Direct: true})
	if !has(got, "group service-group webgrp  holds svc-web") || has(got, "group address-group") {
		t.Errorf("direct:\n%s", dump(got))
	}
	// The order is stable: stage, kind, name, field.
	a, b := dump(run(t, fixture, "vsys1", Query{Term: "webgrp"})), dump(run(t, fixture, "vsys1", Query{Term: "webgrp"}))
	if a != b {
		t.Errorf("two runs differ:\n%s\n--\n%s", a, b)
	}
}

// Exact and within compare an object's whole value. The range 10.0.0.2-10.0.0.9
// is stored as 10.0.0.2/31, 10.0.0.4/30 and 10.0.0.8/31: two of those lie inside
// 10.0.0.0/29 and one equals 10.0.0.4/30, but the range is neither within the
// first nor exactly the second. A wildcard stays unresolved in both modes.
func TestExactAndWithinTestTheWholeObject(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-range.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		term string
		mode Mode
		want []string
	}{
		{"10.0.0.0/29", Within, []string{"h-5 10.0.0.5/32", "n-29 10.0.0.0/29", "n-30 10.0.0.4/30", "r-4-7 10.0.0.4/30"}},
		{"10.0.0.4/30", Exact, []string{"n-30 10.0.0.4/30", "r-4-7 10.0.0.4/30"}},
		{"10.0.0.0/28", Within, []string{"h-5 10.0.0.5/32", "n-29 10.0.0.0/29", "n-30 10.0.0.4/30", "r-2-9 10.0.0.2-10.0.0.9", "r-4-7 10.0.0.4/30"}},
		{"10.0.0.2-10.0.0.9", Exact, []string{"r-2-9 10.0.0.2-10.0.0.9"}},
		{"10.0.0.2-10.0.0.9", Within, []string{"h-5 10.0.0.5/32", "n-30 10.0.0.4/30", "r-2-9 10.0.0.2-10.0.0.9", "r-4-7 10.0.0.4/30"}},
		{"10.0.0.5", Exact, []string{"h-5 10.0.0.5/32"}},
		{"10.0.0.6/31", Within, nil},
	} {
		fs, un, err := Run(cfg, idx, Query{Term: tc.term, Mode: tc.mode, Show: []Stage{StageObject}})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range fs {
			got = append(got, f.Name+" "+f.Via)
		}
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s %v: got %v, want %v", tc.term, tc.mode, got, tc.want)
		}
		if len(un) != 1 || un[0].Value != "wc" {
			t.Errorf("%s %v: unresolved %+v, want the wildcard", tc.term, tc.mode, un)
		}
	}
	// The rule on the range is not reached through an object the term does not hold.
	if fs := run(t, "firewall-range.xml", "vsys1", Query{Term: "10.0.0.0/29", Mode: Within}); has(fs, "reference security rule to-range") {
		t.Errorf("to-range reached:\n%s", dump(fs))
	}
}

// A value written into a rule counts as a whole in exact and within mode too:
// the literal range 10.0.0.2-10.0.0.9 is neither within 10.0.0.0/29 nor exactly
// 10.0.0.4/30, though it overlaps both.
func TestExactAndWithinTestTheWholeLiteral(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		term string
		mode Mode
		want []string
	}{
		{"10.0.0.0/29", Within, []string{"lit-30 destination", "lit-host source"}},
		{"10.0.0.4/30", Exact, []string{"lit-30 destination"}},
		{"10.0.0.2-10.0.0.9", Exact, []string{"lit-range destination"}},
		{"10.0.0.5", Exact, []string{"lit-host source"}},
		{"10.0.0.0/29", Auto, []string{"lit-30 destination", "lit-host source", "lit-range destination"}},
	} {
		var got []string
		for _, f := range run(t, "firewall-range.xml", "vsys1", Query{Term: tc.term, Mode: tc.mode, Show: []Stage{StageLiteral}}) {
			got = append(got, f.Name+" "+f.Field)
		}
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s %v: got %v, want %v", tc.term, tc.mode, got, tc.want)
		}
	}
}

// A static route and an IKE gateway that name objects are references too, from
// the scope config.
func TestDeviceLevelReferences(t *testing.T) {
	t.Parallel()
	got := run(t, "firewall-device-refs.xml", "vsys1", Query{Term: "10.88.5.1"})
	if !has(got, "reference static-route to-remote destination net-remote") ||
		!has(got, "reference security rule to-remote destination net-remote") {
		t.Errorf("10.88.5.1:\n%s", dump(got))
	}
	got = run(t, "firewall-device-refs.xml", "vsys1", Query{Term: "10.88.6.1"})
	if !has(got, "reference gateway gw-1 peer-address/ip peer-1") {
		t.Errorf("10.88.6.1:\n%s", dump(got))
	}
	for _, f := range got {
		if f.Stage == StageReference && f.Scope.String() != "config" {
			t.Errorf("scope %s for %s", f.Scope, line(f))
		}
	}
}
