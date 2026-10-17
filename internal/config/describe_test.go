package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeConfig writes a configuration document to a temporary file.
func writeConfig(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// R3. An element the digest does not describe, such as a field a newer release
// added, is counted once at its top, with its path. What the digest describes is not counted: the pushed rulebases
// are read as a vsys rulebase, a member list's members are its own, and a vsys
// user-group's entry, an array rather than an entry sequence, is a field.
func TestLoadCountsUndescribedElements(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `<config version="12.2.0" detail-version="12.2.1">
  <shared>
    <address><entry name="a"><ip-netmask>10.88.0.1</ip-netmask><new-field><x>1</x><y>2</y></new-field></entry></address>
    <new-container><entry name="n"/></new-container>
    <post-rulebase><security><rules><entry name="p"><action>deny</action>
      <source><member>any</member></source></entry></rules></security></post-rulebase>
  </shared>
  <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
    <user-group><entry name="ug"><member>cn=staff</member></entry></user-group>
    <rulebase><security><rules><entry name="r"><action>allow</action>
      <source><member>a</member></source><new-match>yes</new-match></entry></rules></security></rulebase>
  </entry></vsys></entry></devices>
</config>`)
	cfg, rep, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, u := range rep.Untyped {
		got = append(got, u.XPath)
	}
	want := []string{
		"/config/shared/address/a/new-field",
		"/config/shared/new-container",
		"/config/devices/localhost.localdomain/vsys/vsys1/rulebase/security/rules/r/new-match",
	}
	if !slices.Equal(got, want) {
		t.Errorf("untyped = %q, want %q", got, want)
	}
	if n := cfg.SchemaNode(cfg.Root().Find("shared", "post-rulebase", "security")[0]); n == nil || n.Path() !=
		"/config/devices/entry/vsys/entry/rulebase/security" {
		t.Errorf("a pushed rulebase reads as a vsys rulebase, got %v", n)
	}
	if n := cfg.SchemaNode(cfg.Root().Find("shared", "new-container", "entry")[0]); n != nil {
		t.Errorf("below an undescribed element nothing is described, got %s", n.Path())
	}
}

// One undescribed element is counted, whatever the configuration's version.
func TestLoadCountsOneUndescribedElement(t *testing.T) {
	t.Parallel()
	var rep Report
	for _, v := range []string{"11.2.0", "12.2.0"} {
		var err error
		_, rep, err = Load(writeConfig(t, `<config version="`+v+`"><shared><new-field>x</new-field></shared></config>`))
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Untyped) != 1 {
			t.Errorf("%s: untyped %v", v, rep.Untyped)
		}
	}
	if !strings.Contains(rep.String(), "1 untyped elements, first at /config/shared/new-field") {
		t.Errorf("String = %q", rep.String())
	}
}

// Every configuration fixture the digest describes loads with nothing untyped,
// and the few that hold a deliberate unknown name it.
func TestLoadFixturesUntyped(t *testing.T) {
	t.Parallel()
	known := map[string][]string{
		"firewall-apps.xml":             {"/config/devices/localhost.localdomain/vsys/vsys1/application-container"},
		"firewall-nat-shapes.xml":       {"/config/devices/localhost.localdomain/vsys/vsys1/rulebase/nat/rules/future/source-translation/magic-ip"},
		"firewall-nat-translations.xml": {"/config/devices/localhost.localdomain/vsys/vsys1/rulebase/nat/rules/magic/source-translation/magic-ip"},
		"firewall-version-newfield.xml": {
			"/config/devices/localhost.localdomain/vsys/vsys1/address/dc01/new-field",
			"/config/devices/localhost.localdomain/vsys/vsys1/rulebase/security/rules/dc-out/new-match",
		},
	}
	files, err := filepath.Glob("../../testdata/config/firewall-*.xml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, f := range files {
		_, rep, err := Load(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var got []string
		for _, u := range rep.Untyped {
			got = append(got, u.XPath)
		}
		if want := known[filepath.Base(f)]; !slices.Equal(got, want) {
			t.Errorf("%s: untyped %q, want %q", filepath.Base(f), got, want)
		}
	}
}
