package drift

import (
	"strings"
	"testing"

	"github.com/okaiser/panos-analyst/config"
)

func load(t *testing.T, name string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("../testdata/config/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

var vsys1 = config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

func TestCompareFindsEachChange(t *testing.T) {
	got, err := Compare(load(t, "firewall-lab.xml"), load(t, "firewall-lab-changed.xml"), vsys1)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, c := range got {
		lines = append(lines, string(c.Op)+" "+c.Kind+" "+c.Name)
	}
	want := "changed address net-home,removed address net-labor,changed security rule dc-to-home,added security rule new-rule"
	if strings.Join(lines, ",") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(lines, ","), want)
	}
	for _, c := range got {
		if c.Name == "net-home" && (c.Old != "198.18.1.0/24" || c.New != "198.18.2.0/24") {
			t.Errorf("net-home = %q -> %q", c.Old, c.New)
		}
		if c.Name == "dc-to-home" && !strings.Contains(c.New, "disabled") {
			t.Errorf("dc-to-home must show it is now disabled: %q", c.New)
		}
	}
}

func TestIdenticalConfigurationsDoNotDiffer(t *testing.T) {
	got, err := Compare(load(t, "firewall-lab.xml"), load(t, "firewall-lab.xml"), vsys1)
	if err != nil || len(got) != 0 {
		t.Errorf("got %v, %v", got, err)
	}
}

// Shared objects and rules are compared under shared, not repeated per vsys.
func TestSharedIsItsOwnScope(t *testing.T) {
	before := load(t, "firewall-lab.xml")
	after := load(t, "firewall-multivsys.xml")
	shared := config.Scope{Sort: config.ScopeShared}
	got, err := Compare(before, after, shared)
	if err != nil {
		t.Fatal(err)
	}
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
	vsysOnly, _ := Compare(before, after, vsys1)
	for _, c := range vsysOnly {
		if c.Name == "shared-dns" || c.Name == "pushed-pre" {
			t.Errorf("a shared change leaked into the vsys comparison: %+v", c)
		}
	}
}
