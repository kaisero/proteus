package search

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
)

func run(t *testing.T, fixture, vsys string, q Query) []Finding {
	t.Helper()
	cfg, _, err := config.Load("../../testdata/config/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.For(cfg, config.Scope{Sort: config.ScopeVsys, Name: vsys})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Run(cfg, idx, q)
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

func TestWithinNeedsAnAddress(t *testing.T) {
	cfg, _, _ := config.Load("../../testdata/config/firewall-multivsys.xml")
	idx, _ := index.For(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"})
	if _, err := Run(cfg, idx, Query{Term: "web", Mode: Within}); !errors.Is(err, ErrWithinNeedsAddress) {
		t.Errorf("got %v", err)
	}
}

func TestContainsSearchesValuesAndNames(t *testing.T) {
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
	got := run(t, "firewall-urlcat.xml", "vsys1", Query{Term: "tcp/8006"})
	if !has(got, "object service svc-pve") || !has(got, "object service svc-range") {
		t.Errorf("tcp/8006 must find the exact port and the range covering it:\n%s", dump(got))
	}
	byName := run(t, "firewall-multivsys.xml", "vsys1", Query{Term: "corp-dc-vienna"})
	if !has(byName, "object address corp-dc-vienna  name") || !has(byName, "group address-group corp-dc") {
		t.Errorf("a name must find the object and its groups:\n%s", dump(byName))
	}
}

func TestReferrer(t *testing.T) {
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

// groupKind prefers a group kind, falls back to the first kind a name has, and
// to "group" for a name nothing defines.
func TestGroupKindPrefersAGroupKind(t *testing.T) {
	s := &searcher{byName: map[string][]string{
		"both": {"tag", "address-group"},
		"tag":  {"tag"},
	}}
	for name, want := range map[string]string{"both": "address-group", "tag": "tag", "nothing": "group"} {
		if got := s.groupKind(name); got != want {
			t.Errorf("groupKind(%q) = %q, want %q", name, got, want)
		}
	}
}
