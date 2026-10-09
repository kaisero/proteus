package query

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/store"
)

// clock is when the lab's snapshots are taken; the queries run an hour later.
var clock = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)

// labEnv is the path lab as a store and an inventory of fw01 and fw02, with a
// snapshot of each device in fetched.
func labEnv(t *testing.T, fetched ...string) Env {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st = st.WithClock(func() time.Time { return clock })
	for _, d := range fetched {
		docs := map[string][]byte{
			store.ConfigDoc:     pathlab.Read(t, pathlab.ConfigFile(d)),
			store.InterfacesDoc: pathlab.Read(t, pathlab.OpdataFile(d+"-interface-all.xml")),
			store.FIBDoc:        pathlab.Read(t, pathlab.OpdataFile(d+"-advanced-routing-fib.xml")),
		}
		if _, err := st.Write(store.Meta{Device: d, Host: d + ".example.test"}, docs, 20); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := inventory.Parse(strings.NewReader("version: 1\ndevices:\n" +
		"  - name: fw01\n    host: fw01.example.test\n    labels: {site: s1}\n" +
		"  - name: fw02\n    host: fw02.example.test\n    labels: {site: s2}\n"))
	if err != nil {
		t.Fatal(err)
	}
	return Env{
		Store: st, Inventory: inv, Now: func() time.Time { return clock.Add(time.Hour) }, MaxAge: 24 * time.Hour,
		Resolve: resolver(map[string][]string{}),
	}
}

// resolver answers from a table; a name it does not hold fails.
func resolver(names map[string][]string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, name string) ([]netip.Addr, error) {
		as, ok := names[name]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []netip.Addr
		for _, a := range as {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

// fixture is a configuration file of the repository's test data.
func fixture(name string) string { return "../../testdata/config/" + name }

// usageOK checks a usage error: its text, and a tool text without a flag where
// the text names one.
func usageOK(t *testing.T, err error, want string) {
	t.Helper()
	u, ok := errors.AsType[*UsageError](err)
	if !ok {
		t.Fatalf("want a usage error, got %v (%T)", err, err)
	}
	if !strings.Contains(u.Text, want) || u.Code != "call.usage" {
		t.Errorf("text %q, code %s; want %q", u.Text, u.Code, want)
	}
	if strings.Contains(u.Text, "--") != (u.ToolText != "") || strings.Contains(u.ToolText, "--") {
		t.Errorf("text %q, tool text %q", u.Text, u.ToolText)
	}
}
