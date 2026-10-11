package drift

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
)

// longLists is a vsys with two long lists of n items: an LDAP server
// profile's servers, a nested entry list whose order is a setting, and an
// element the schema does not describe, with n repeated children. With swap,
// the first two servers trade places and the last child changes.
func longLists(n int, swap bool) string {
	names := serverNames(n, swap)
	var b strings.Builder
	b.WriteString(`<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">`)
	b.WriteString(`<server-profile><ldap><entry name="ldap-big"><server>`)
	for _, s := range names {
		fmt.Fprintf(&b, `<entry name="%s"><address>10.88.5.1</address></entry>`, s)
	}
	b.WriteString(`</server></entry></ldap></server-profile><future-list>`)
	for _, v := range items(n, swap) {
		fmt.Fprintf(&b, `<item>%s</item>`, v)
	}
	b.WriteString(`</future-list></entry></vsys></entry></devices></config>`)
	return b.String()
}

func serverNames(n int, swap bool) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("s%d", i)
	}
	if swap {
		out[0], out[1] = out[1], out[0]
	}
	return out
}

func items(n int, swap bool) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("v%d", i)
	}
	if swap {
		out[n-1] = "changed"
	}
	return out
}

// Long lists compare as short ones do: the repeated children are one value in
// document order, and the servers' order is one change.
func TestCompareLongLists(t *testing.T) {
	t.Parallel()
	const n = 20000
	before, after := loadXML(t, longLists(n, false)), loadXML(t, longLists(n, true))
	got := Compare(before, after, vsys1)
	if len(got) != 2 || got[0].Kind != "future-list" || len(got[0].Fields) != 1 || got[0].Fields[0] != (FieldChange{Path: "item", Undescribed: true}) {
		t.Fatalf("got %d changes, first %+v", len(got), got[0])
	}
	order := got[1]
	if order.Kind != "ldap" || len(order.Fields) != 1 || order.Fields[0].Path != "server order" ||
		order.Fields[0].Old != strings.Join(serverNames(n, false), ", ") || order.Fields[0].New != strings.Join(serverNames(n, true), ", ") {
		t.Errorf("the order change: %d fields, path %q", len(order.Fields), order.Fields[0].Path)
	}
	el := before.Root().Find("devices", "entry", "vsys", "entry", "future-list")[0]
	if f := canonical(el, nil, ""); f.values["item"] != strings.Join(items(n, false), ", ") {
		t.Error("the repeated children are not one value in document order")
	}
}

// Compare on lists of 20,000 items. Joining each repeated value onto the last
// and searching one order list for each name of the other took time in the
// square of the length: 1.0 s and 3.0 GB per Compare. Joined once and looked
// up in a set: 14 ms and 22 MB (Apple M3 Pro, go1.26.9).
func BenchmarkCompareLongLists(b *testing.B) {
	var cfgs [2]*config.Config
	for i, swap := range []bool{false, true} {
		path := filepath.Join(b.TempDir(), "config.xml")
		if err := os.WriteFile(path, []byte(longLists(20000, swap)), 0o600); err != nil {
			b.Fatal(err)
		}
		cfg, _, err := config.Load(path)
		if err != nil {
			b.Fatal(err)
		}
		cfgs[i] = cfg
	}
	for b.Loop() {
		if got := Compare(cfgs[0], cfgs[1], vsys1); len(got) != 2 {
			b.Fatalf("got %d changes", len(got))
		}
	}
}
