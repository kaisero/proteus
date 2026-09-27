package resolve

import (
	"strings"
	"testing"

	"github.com/okaiser/go-panos-schema/config"
)

func loadT(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load %s: %v", path, err)
	}
	return cfg
}

func shadowLab(t *testing.T) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("../testdata/config/panorama-shadow.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestScopedObjectsExcludeSiblings(t *testing.T) {
	tg, err := TargetFor(lab(t), "007900000000003", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	objs, err := tg.Objects("address")
	if err != nil {
		t.Fatalf("Objects: %v", err)
	}
	names := map[string]bool{}
	for _, o := range objs {
		names[o.Name] = true
	}
	if !names["corp-dc-vienna"] || !names["corp-location-vienna"] {
		t.Errorf("the target's own objects are missing: %v", names)
	}
	// corp-graz is a sibling device group, so its objects are invisible here.
	if names["corp-dc-graz"] || names["corp-location-graz"] {
		t.Errorf("sibling device-group objects leaked in: %v", names)
	}
}

func TestScopedObjectsCarryValueAndTags(t *testing.T) {
	tg, _ := TargetFor(lab(t), "007900000000003", "vsys1")
	objs, _ := tg.Objects("address")
	for _, o := range objs {
		if o.Name != "corp-location-vienna" {
			continue
		}
		if o.Value != "10.124.0.0/16" {
			t.Errorf("value = %q, want 10.124.0.0/16", o.Value)
		}
		if len(o.Tags) != 1 || o.Tags[0] != "corp-location" {
			t.Errorf("tags = %v, want [corp-location]", o.Tags)
		}
		if o.Scope.String() != "dg:host_1_directory" {
			t.Errorf("scope = %q, want dg:host_1_directory", o.Scope.String())
		}
		return
	}
	t.Error("corp-location-vienna not found")
}

func TestShadowingIsReported(t *testing.T) {
	tg, err := TargetFor(shadowLab(t), "001122334455", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	objs, err := tg.Objects("address")
	if err != nil {
		t.Fatalf("Objects: %v", err)
	}
	var shadowed *Object
	for i := range objs {
		if objs[i].Name == "web-server" {
			shadowed = &objs[i]
		}
	}
	if shadowed == nil {
		t.Fatal("web-server not found")
	}
	if shadowed.Scope.String() != "dg:leaf" {
		t.Errorf("the descendant definition must win, got scope %q", shadowed.Scope.String())
	}
	if shadowed.Value != "10.9.9.1" {
		t.Errorf("value = %q, want the leaf's 10.9.9.1", shadowed.Value)
	}
	if shadowed.ShadowedFrom == nil || shadowed.ShadowedFrom.String() != "dg:top" {
		t.Errorf("shadowing must name what it replaced, got %v", shadowed.ShadowedFrom)
	}
	// An ancestor-only object is still visible.
	var found bool
	for _, o := range objs {
		if o.Name == "only-in-top" {
			found = true
			if o.ShadowedFrom != nil {
				t.Error("only-in-top shadows nothing")
			}
		}
	}
	if !found {
		t.Error("only-in-top must be inherited from the ancestor")
	}
}

// A custom URL category does not sit directly under its scope; it lives under
// profiles/. Reading a kind as a direct child found none of them, so the objects
// were invisible and so was every security profile.
func TestObjectsFindsAKindNestedUnderProfiles(t *testing.T) {
	cfg := loadT(t, "../testdata/config/firewall-urlcat.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	objs, err := ObjectsInScope(cfg, sc, "custom-url-category")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 1 {
		t.Fatalf("got %d custom URL categories, want 1", len(objs))
	}
	if objs[0].Name != "custom-azuresite-group" {
		t.Errorf("name = %q", objs[0].Name)
	}
	// The members are the value, so a URL lookup has something to match against.
	for _, want := range []string{"superlong.example.azureapps.microsoft.com", "*.wildcard-example.com"} {
		if !strings.Contains(objs[0].Value, want) {
			t.Errorf("value %q does not contain %q", objs[0].Value, want)
		}
	}
}

// A service keeps its port one level below the entry, under the protocol. Reading
// only the top level reported every service as having no value at all.
func TestObjectsReadsAServicePort(t *testing.T) {
	cfg := loadT(t, "../testdata/config/firewall-urlcat.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	objs, err := ObjectsInScope(cfg, sc, "service")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, o := range objs {
		got[o.Name] = o.Value
	}
	for name, want := range map[string]string{"svc-pve": "tcp/8006", "svc-dns": "udp/53"} {
		if got[name] != want {
			t.Errorf("%s value = %q, want %q", name, got[name], want)
		}
	}
}

// PAN-OS writes an object's type two ways, and both have to be read. A custom URL
// category writes text; an external list writes a single child element naming the
// type. The type decides how the object may be used, because a URL external list and
// an IP external list share one container.
func TestObjectSubtypeReadsBothForms(t *testing.T) {
	cfg := loadT(t, "../testdata/config/firewall-urlcat-edge.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	cats, err := ObjectsInScope(cfg, sc, "custom-url-category")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, o := range cats {
		got[o.Name] = o.Subtype
	}
	if got["cat-match-group"] != "Category Match" {
		t.Errorf("cat-match-group subtype = %q, want %q", got["cat-match-group"], "Category Match")
	}
	if got["cat-bad-member"] != "URL List" {
		t.Errorf("cat-bad-member subtype = %q, want %q", got["cat-bad-member"], "URL List")
	}

	edls, err := ObjectsInScope(cfg, sc, "external-list")
	if err != nil {
		t.Fatal(err)
	}
	if len(edls) != 1 {
		t.Fatalf("got %d external lists, want 1", len(edls))
	}
	if edls[0].Subtype != "url" {
		t.Errorf("external list subtype = %q, want %q read from the child element", edls[0].Subtype, "url")
	}
}

// An object with no type element has no subtype, rather than a guess.
func TestObjectSubtypeIsEmptyWhenAbsent(t *testing.T) {
	cfg := loadT(t, "../testdata/config/firewall-urlcat.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	objs, err := ObjectsInScope(cfg, sc, "address")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range objs {
		if o.Subtype != "" {
			t.Errorf("%s subtype = %q, want empty", o.Name, o.Subtype)
		}
	}
}

// A service group spells its membership "members" where an address group says
// "static". Reading only "static" left every service group with no value, and so with
// no members in the group closure.
func TestObjectsReadsServiceGroupMembers(t *testing.T) {
	cfg := loadT(t, "../testdata/config/firewall-urlcat.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	objs, err := ObjectsInScope(cfg, sc, "service-group")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 1 {
		t.Fatalf("got %d service groups, want 1", len(objs))
	}
	for _, want := range []string{"svc-pve", "svc-range"} {
		if !strings.Contains(objs[0].Value, want) {
			t.Errorf("value %q does not contain %q", objs[0].Value, want)
		}
	}
}

// ObjectsAt names the container, for the kinds whose name is ambiguous. Reading "user"
// by name alone finds a different array from the local user database, and the mistake
// is invisible in the result.
func TestObjectsAtReadsAnExplicitContainer(t *testing.T) {
	cfg := loadT(t, "../testdata/config/firewall-users.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	local, err := ObjectsAt(cfg, sc, "user", []string{"local-user-database", "user"})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, o := range local {
		names[o.Name] = true
	}
	for _, want := range []string{"alice", "bob"} {
		if !names[want] {
			t.Errorf("%s not found in the local user database: %v", want, names)
		}
	}

	// The guessed container finds none of them, which is why the explicit form exists.
	guessed, err := ObjectsInScope(cfg, sc, "user")
	if err != nil {
		t.Fatal(err)
	}
	if len(guessed) != 0 {
		t.Errorf("the guessed container returned %d objects; the fixture no longer shows the problem", len(guessed))
	}
}

// A local user group spells its membership "user", where an address group says "static"
// and a service group says "members".
func TestObjectsReadsUserGroupMembers(t *testing.T) {
	cfg := loadT(t, "../testdata/config/firewall-users.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	groups, err := ObjectsInScope(cfg, sc, "user-group")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("got %d user groups, want 1", len(groups))
	}
	if !strings.Contains(groups[0].Value, "alice") {
		t.Errorf("value = %q, want it to hold the member", groups[0].Value)
	}
}

// One value identifies an object, and PAN-OS spells it differently for each kind. All
// the forms have to be read, or an object looks valueless and drops out of every
// lookup that works on values.
func TestObjectValueReadsEveryForm(t *testing.T) {
	cfg := loadT(t, "../testdata/config/firewall-urlcat-edge.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	addrs, err := ObjectsInScope(cfg, sc, "address")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, o := range addrs {
		got[o.Name] = o.Value
	}
	if got["wild-host"] != "10.0.0.0/0.0.255.255" {
		t.Errorf("ip-wildcard value = %q", got["wild-host"])
	}
	if got["tagged-host"] != "10.1.1.1/32" {
		t.Errorf("ip-netmask value = %q", got["tagged-host"])
	}

	groups, err := ObjectsInScope(cfg, sc, "address-group")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if g.Name == "dyn-grp" && g.Value != "'prod'" {
			t.Errorf("a dynamic group's value should be its filter, got %q", g.Value)
		}
	}
}

// A scope whose inheritance chain cannot be built is reported, by both readers.
func TestObjectReadersReportABrokenHierarchy(t *testing.T) {
	cfg := loadT(t, "../testdata/config/panorama-cycle.xml")
	sc := config.Scope{Sort: config.ScopeDeviceGroup, Name: "dg1"}

	if _, err := ObjectsInScope(cfg, sc, "address"); err == nil {
		t.Error("ObjectsInScope did not report a cyclic hierarchy")
	}
	if _, err := ObjectsAt(cfg, sc, "user", []string{"local-user-database", "user"}); err == nil {
		t.Error("ObjectsAt did not report a cyclic hierarchy")
	}
}
