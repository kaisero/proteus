package testconfig

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/identity"
	"github.com/kaisero/proteus/internal/resolve"
)

// The generated file loads, and holds the shape the benchmarks name.
func TestWriteGivesTheShape(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load(Write(t, Groups{Addrs: 2000, Rules: 1000, Ring: 3, Dense: 4}))
	if err != nil {
		t.Fatal(err)
	}
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	if got := len(resolve.ObjectsInScope(cfg, sc, "address")); got != 2000 {
		t.Errorf("%d addresses, want 2000", got)
	}
	groups := map[string]resolve.Object{}
	for _, g := range resolve.ObjectsInScope(cfg, sc, "address-group") {
		groups[g.Name] = g
	}
	if len(groups) != TreeGroups+3+4 {
		t.Errorf("%d groups, want %d", len(groups), TreeGroups+7)
	}
	if !groups["g-0"].Dynamic || groups["g-1"].Dynamic || groups["c-2"].Value != "c-0, a-2" {
		t.Errorf("g-0 %+v, g-1 %+v, c-2 %+v", groups["g-0"], groups["g-1"], groups["c-2"])
	}
	// The tree under the top rule's group: 1 + 3 + 9 + 27 + 81 + 243 groups.
	tg, err := resolve.TargetFor(cfg, "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatal(err)
	}
	var src string
	for _, r := range tg.Rules(resolve.Security) {
		if r.Name == TopRule {
			src = r.Fields["source"][0]
		}
	}
	nodes := 0
	var walk func(string)
	walk = func(g string) {
		o, ok := groups[g]
		if !ok {
			return
		}
		nodes++
		if !o.Dynamic {
			for _, m := range strings.Split(o.Value, ", ") {
				walk(m)
			}
		}
	}
	walk(src)
	if src != "g-1999" || nodes != 364 {
		t.Errorf("%s holds a tree of %d groups, want g-1999 and 364", src, nodes)
	}
}

// Content writes the trimmed App-ID fixture, gzipped, so the tests of every
// package read one file.
func TestContentWritesTheFixture(t *testing.T) {
	t.Parallel()
	dst := filepath.Join(t.TempDir(), "8000-1000.v1.xml.gz")
	Content(t, dst)
	f, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../testdata/appid/content.xml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("the file does not unzip to testdata/appid/content.xml")
	}
}

// Identity writes the identity fixture, gzipped and mode 0600 as a snapshot
// holds it, so the tests of every package read one file (spec 2026-10-17 §4.1,
// §7).
func TestIdentityWritesTheFixture(t *testing.T) {
	t.Parallel()
	dst := filepath.Join(t.TempDir(), "identity.json.gz")
	Identity(t, dst)
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
	f, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../testdata/identity/identity.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("the file does not unzip to testdata/identity/identity.json")
	}
}

// fatalTB records a failure instead of stopping the test.
type fatalTB struct {
	testing.TB
	failed bool
}

func (f *fatalTB) Fatal(...any) { f.failed = true }

// A destination that Content cannot write fails the test.
func TestContentFailsOnABadDestination(t *testing.T) {
	t.Parallel()
	tb := &fatalTB{TB: t}
	Content(tb, filepath.Join(t.TempDir(), "missing", "file.xml.gz"))
	if !tb.failed {
		t.Error("Content did not fail")
	}
}

// AppContent parses with the count asked, every 50th application in a
// container. Its size is about that of a real file: content 9159 has 5552
// applications in a trimmed file of about 6 MB (spec 2026-10-16 F4).
func TestAppContentHasTheCount(t *testing.T) {
	t.Parallel()
	d, err := appid.Parse(bytes.NewReader(AppContent(t, 10)))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(d.Apps()); got != 10 || d.Version() != "8000-1000" {
		t.Errorf("%d applications of %s, want 10 of 8000-1000", got, d.Version())
	}
	if a, ok := d.App("app-0"); !ok || a.Container != "c-0" || a.Default.None || !a.Flags["evasive-behavior"] {
		t.Errorf("app-0 %+v", a)
	}
	if c, ok := d.Container("c-0"); !ok || len(c.Functions) != 1 || c.Functions[0] != "app-0" {
		t.Errorf("c-0 %+v", c)
	}
	zr, err := gzip.NewReader(bytes.NewReader(AppContent(t, 5552)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(raw); n < 5<<20 || n > 7<<20 {
		t.Errorf("5552 applications take %d bytes, not about 6 MB", n)
	}
}

// IdentityFile reads as an identity file with the counts asked: groupsPerUser
// groups and one tag entry per user, every part complete (spec 2026-10-17
// §8). A mapping keeps its user in the NetBIOS form, as a device stores it
// (M2), and each user holds distinct groups.
func TestIdentityFileHasTheCounts(t *testing.T) {
	t.Parallel()
	d, err := identity.Read(bytes.NewReader(IdentityFile(t, 10, 3, 100)))
	if err != nil {
		t.Fatal(err)
	}
	if c := d.Counts(); c.Users != 10 || c.Memberships != 30 || c.Tags != 10 || c.TagPairs != 10 || c.Mappings != 100 || c.Groups < 3 {
		t.Errorf("counts %+v, want 10 users, 30 memberships, 10 tag entries, 100 mappings", c)
	}
	for _, p := range []string{identity.PartLDAP, identity.PartGroups, identity.PartUserGroups, identity.PartTags, identity.PartMappings} {
		if !d.Complete(p) {
			t.Errorf("the part %s is not complete", p)
		}
	}
	groups := d.GroupsOf(`example.com\member-00009`)
	if len(groups) != 3 || groups[0] == groups[1] || groups[1] == groups[2] || groups[0] == groups[2] {
		t.Errorf("groups of member-00009: %q", groups)
	}
	if m, ok := d.Mapping(netip.MustParseAddr("2001:db8::64")); !ok || m.User != `example\member-00009` {
		t.Errorf("the mapping of the 100th address: %+v, %v", m, ok)
	}
	if got := d.TagsOf(`example.com\member-00009`); len(got) != 1 {
		t.Errorf("tags of member-00009: %q", got)
	}
}
