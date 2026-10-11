package resolve

import (
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
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
	cfg, _, err := config.Load("../../testdata/config/firewall-shadow.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestScopedObjectsExcludeSiblings(t *testing.T) {
	t.Parallel()
	tg, err := TargetFor(vsysLab(t), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	objs := tg.Objects("address")
	names := map[string]bool{}
	for _, o := range objs {
		names[o.Name] = true
	}
	if !names["corp-dc-vienna"] || !names["corp-location-vienna"] {
		t.Errorf("the target's own objects are missing: %v", names)
	}
	// vsys2 is a sibling vsys, so its objects are invisible here.
	if names["corp-dc-graz"] || names["corp-location-graz"] {
		t.Errorf("sibling vsys objects leaked in: %v", names)
	}
}

func TestScopedObjectsCarryValueAndTags(t *testing.T) {
	t.Parallel()
	tg, _ := TargetFor(vsysLab(t), "localhost.localdomain", "vsys1")
	objs := tg.Objects("address")
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
		if o.Scope.String() != "vsys:vsys1" {
			t.Errorf("scope = %q, want vsys:vsys1", o.Scope.String())
		}
		return
	}
	t.Error("corp-location-vienna not found")
}

func TestShadowingIsReported(t *testing.T) {
	t.Parallel()
	tg, err := TargetFor(shadowLab(t), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	objs := tg.Objects("address")
	var shadowed *Object
	for i := range objs {
		if objs[i].Name == "web-server" {
			shadowed = &objs[i]
		}
	}
	if shadowed == nil {
		t.Fatal("web-server not found")
	}
	if shadowed.Scope.String() != "vsys:vsys1" {
		t.Errorf("the vsys definition must win, got scope %q", shadowed.Scope.String())
	}
	if shadowed.Value != "10.9.9.1" {
		t.Errorf("value = %q, want the vsys's 10.9.9.1", shadowed.Value)
	}
	if shadowed.ShadowedFrom == nil || shadowed.ShadowedFrom.String() != "shared" {
		t.Errorf("shadowing must name what it replaced, got %v", shadowed.ShadowedFrom)
	}
	// A shared-only object is still visible.
	var found bool
	for _, o := range objs {
		if o.Name == "only-in-shared" {
			found = true
			if o.ShadowedFrom != nil {
				t.Error("only-in-shared shadows nothing")
			}
		}
	}
	if !found {
		t.Error("only-in-shared must be inherited from shared")
	}
}

// A custom URL category does not sit directly under its scope; it lives under
// profiles/. Reading a kind as a direct child found none of them, so the objects
// were invisible and so was every security profile.
func TestObjectsFindsAKindNestedUnderProfiles(t *testing.T) {
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-urlcat.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	objs := ObjectsInScope(cfg, sc, "custom-url-category")
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
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-urlcat.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	objs := ObjectsInScope(cfg, sc, "service")
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
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-urlcat-edge.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	cats := ObjectsInScope(cfg, sc, "custom-url-category")
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

	edls := ObjectsInScope(cfg, sc, "external-list")
	if len(edls) != 1 {
		t.Fatalf("got %d external lists, want 1", len(edls))
	}
	if edls[0].Subtype != "url" {
		t.Errorf("external list subtype = %q, want %q read from the child element", edls[0].Subtype, "url")
	}
}

// An object with no type element has no subtype, rather than a guess.
func TestObjectSubtypeIsEmptyWhenAbsent(t *testing.T) {
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-urlcat.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	objs := ObjectsInScope(cfg, sc, "address")
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
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-urlcat.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	objs := ObjectsInScope(cfg, sc, "service-group")
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
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-users.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	local := ObjectsAt(cfg, sc, "user", []string{"local-user-database", "user"})
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
	guessed := ObjectsInScope(cfg, sc, "user")
	if len(guessed) != 0 {
		t.Errorf("the guessed container returned %d objects; the fixture no longer shows the problem", len(guessed))
	}
}

// A local user group spells its membership "user", where an address group says "static"
// and a service group says "members".
func TestObjectsReadsUserGroupMembers(t *testing.T) {
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-users.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	groups := ObjectsInScope(cfg, sc, "user-group")
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
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-urlcat-edge.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	addrs := ObjectsInScope(cfg, sc, "address")
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

	groups := ObjectsInScope(cfg, sc, "address-group")
	for _, g := range groups {
		if g.Name == "dyn-grp" && g.Value != "'prod'" {
			t.Errorf("a dynamic group's value should be its filter, got %q", g.Value)
		}
	}
}

// The config scope sits outside shared and every vsys, so it holds no objects of
// its own; readers see only shared from it.
func TestConfigScopeHoldsNoObjectsOfItsOwn(t *testing.T) {
	t.Parallel()
	cfg := fwLab(t)
	sc := config.Scope{Sort: config.ScopeConfig}
	objs := ObjectsInScope(cfg, sc, "address")
	for _, o := range objs {
		if o.Scope.Sort != config.ScopeShared {
			t.Errorf("%s came from %s, want shared only", o.Name, o.Scope)
		}
	}
	if len(objs) == 0 {
		t.Error("shared-dns is in shared and must still be visible")
	}
	zones := ZonesInScope(cfg, sc)
	if len(zones) != 0 {
		t.Errorf("zones = %v, want none", zones)
	}
}

// serviceList is each service as name=value@scope, with the scope it hides.
func serviceList(objs []Object) string {
	var out []string
	for _, o := range objs {
		s := o.Name + "=" + o.Value + "@" + o.Scope.String()
		if o.ShadowedFrom != nil {
			s += " hides " + o.ShadowedFrom.String()
		}
		out = append(out, s)
	}
	return strings.Join(out, "; ")
}

// Every scope sees the device's predefined services below shared. As observed on
// fw02, PAN-OS 12.2.3: the device defines service-http as tcp/80,8080 and
// service-https as tcp/443 (L4), and a configured service of the same name wins,
// vsys, then shared, then predefined (L7).
func TestPredefinedServicesSitBelowShared(t *testing.T) {
	t.Parallel()
	vsys1 := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	shared := config.Scope{Sort: config.ScopeShared}
	plain := loadT(t, "../../testdata/predefined/config.xml")
	for _, sc := range []config.Scope{shared, vsys1} {
		if got := serviceList(ObjectsInScope(plain, sc, "service")); got != "service-http=tcp/80,8080@predefined; service-https=tcp/443@predefined" {
			t.Errorf("%s: %s", sc, got)
		}
	}
	configured := loadT(t, "../../testdata/predefined-configured/config.xml")
	if got := serviceList(ObjectsInScope(configured, vsys1, "service")); got != "service-http=tcp/8081@shared hides predefined; service-https=tcp/8443@vsys:vsys1 hides predefined" {
		t.Errorf("vsys1: %s", got)
	}
	if got := serviceList(ObjectsInScope(configured, shared, "service")); got != "service-http=tcp/8081@shared hides predefined; service-https=tcp/443@predefined" {
		t.Errorf("shared: %s", got)
	}
	// Only services are predefined; other kinds see nothing new.
	if got := ObjectsInScope(plain, vsys1, "address"); len(got) != 0 {
		t.Errorf("addresses: %+v", got)
	}
	// Without the file, the names are not defined.
	if got := ObjectsInScope(loadT(t, "../../testdata/config/firewall-nat-cases.xml"), vsys1, "service"); strings.Contains(serviceList(got), "predefined") {
		t.Errorf("no predefined.xml: %s", serviceList(got))
	}
}

// A name resolves by scope first and kind second. As observed on fw02, PAN-OS
// 12.2.3 (L9): vsys1's service group service-https hides the predefined service
// of that name, and vsys1's service web hides shared's service group web. Shared
// sees its own group and the predefined service.
func TestANameResolvesByScopeFirstAcrossKinds(t *testing.T) {
	t.Parallel()
	cfg := loadT(t, "../../testdata/predefined-cross-kind/config.xml")
	for _, tc := range []struct {
		sc             config.Scope
		service, group string
	}{
		{
			config.Scope{Sort: config.ScopeVsys, Name: "vsys1"},
			"service-http=tcp/80,8080@predefined; svc-9080=tcp/9080@shared; svc-8443=tcp/8443@vsys:vsys1; web=tcp/8081@vsys:vsys1",
			"service-https=svc-8443@vsys:vsys1",
		},
		{
			config.Scope{Sort: config.ScopeShared},
			"service-http=tcp/80,8080@predefined; service-https=tcp/443@predefined; svc-9080=tcp/9080@shared",
			"web=svc-9080@shared",
		},
	} {
		got := ObjectsOfKindsInScope(cfg, tc.sc, "service", "service-group")
		if s := serviceList(got["service"]); s != tc.service {
			t.Errorf("%s services: %s", tc.sc, s)
		}
		if s := serviceList(got["service-group"]); s != tc.group {
			t.Errorf("%s groups: %s", tc.sc, s)
		}
	}
}

// A dynamic group is known by its dynamic element, not by the first character of
// its filter. As observed on fw02, PAN-OS 12.2.3, a filter may start with "("
// (L1); read as a member list it held one fake member and no address.
func TestDynamicGroupIsKnownByItsElement(t *testing.T) {
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-dynamic-filter.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	groups := ObjectsInScope(cfg, sc, "address-group")
	if len(groups) == 0 {
		t.Fatal("no address group")
	}
	for _, o := range groups {
		if !o.Dynamic {
			t.Errorf("%s: Dynamic = false", o.Name)
		}
		if o.Name == "dag-paren" && o.Value != "('t-a' or 't-b')" {
			t.Errorf("dag-paren: Value = %q, want its filter", o.Value)
		}
	}
	for _, o := range ObjectsInScope(cfg, sc, "address") {
		if o.Dynamic {
			t.Errorf("address %s: Dynamic = true", o.Name)
		}
	}
	static := false
	for _, o := range ObjectsInScope(fwLab(t), sc, "address-group") {
		if o.Name == "g-servers" {
			static = !o.Dynamic && o.Value == "dc01"
		}
	}
	if !static {
		t.Error("g-servers: want a static group holding dc01")
	}
}
