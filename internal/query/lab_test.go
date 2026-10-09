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

// lab is a store and an inventory of fw01 and fw02. Each fetch stores a
// snapshot a minute after the one before.
type lab struct {
	t   *testing.T
	st  *store.Store
	now time.Time
}

func newLab(t *testing.T) *lab {
	t.Helper()
	l := &lab{t: t, now: clock}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l.st = st.WithClock(func() time.Time { return l.now })
	return l
}

// fetch stores a snapshot of a device with a configuration file and the device's
// interfaces and forwarding table.
func (l *lab) fetch(device, config string) {
	l.t.Helper()
	docs := map[string][]byte{
		store.ConfigDoc:     pathlab.Read(l.t, config),
		store.InterfacesDoc: pathlab.Read(l.t, pathlab.OpdataFile(device+"-interface-all.xml")),
		store.FIBDoc:        pathlab.Read(l.t, pathlab.OpdataFile(device+"-advanced-routing-fib.xml")),
	}
	if _, err := l.st.Write(store.Meta{Device: device, Host: device + ".example.test"}, docs, 20); err != nil {
		l.t.Fatal(err)
	}
	l.now = l.now.Add(time.Minute)
}

// env asks the lab an hour after its first snapshot.
func (l *lab) env() Env {
	l.t.Helper()
	inv, err := inventory.Parse(strings.NewReader("version: 1\ndevices:\n" +
		"  - name: fw01\n    host: fw01.example.test\n    labels: {site: s1}\n" +
		"  - name: fw02\n    host: fw02.example.test\n    labels: {site: s2}\n"))
	if err != nil {
		l.t.Fatal(err)
	}
	return Env{
		Store: l.st, Inventory: inv, Now: func() time.Time { return clock.Add(time.Hour) }, MaxAge: 24 * time.Hour,
		Resolve: resolver(map[string][]string{}),
	}
}

// labEnv is the path lab with a snapshot of each device in fetched.
func labEnv(t *testing.T, fetched ...string) Env {
	t.Helper()
	l := newLab(t)
	for _, d := range fetched {
		l.fetch(d, pathlab.ConfigFile(d))
	}
	return l.env()
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
