package mcp

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/store"
	"github.com/kaisero/proteus/internal/testconfig"
)

// retained loads a snapshot through a new cache, builds the three rulebase
// indexes of each vsys, and returns the bytes that stay live while the cache
// holds them. The schema digest is loaded once per process before, so it is
// not counted here: the cache sizes it apart, as digestBytes, and
// digestRetained measures it.
func retained(tb testing.TB, sn store.Snapshot) uint64 {
	tb.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	c := newCache(1<<40, 1, 1, true)
	ld, err := c.bind(context.Background()).Config(sn)
	if err != nil {
		tb.Fatal(err)
	}
	for _, v := range resolve.Vsyses(ld.Config) {
		for _, rb := range []resolve.Rulebase{resolve.Security, resolve.NAT, resolve.PBF} {
			if _, err := ld.Indexes.Index(config.Scope{Sort: config.ScopeVsys, Name: v}, rb); err != nil {
				tb.Fatal(err)
			}
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(c)
	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return after.HeapAlloc - before.HeapAlloc
}

// contentApps is the application count of the content file the benchmark
// measures: content 9159 has 5552 applications (spec 2026-10-16 F4).
const contentApps = 5552

// contentRetained loads a content file through a new cache and returns the
// bytes that stay live while the cache holds it.
func contentRetained(tb testing.TB, path string) uint64 {
	tb.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	c := newCache(1<<40, 1, 1, true)
	if _, err := c.bind(context.Background()).Apps(path); err != nil {
		tb.Fatal(err)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(c)
	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return after.HeapAlloc - before.HeapAlloc
}

// snapshotOf stores a configuration file as a device's snapshot.
func snapshotOf(tb testing.TB, st *store.Store, device, path string) (store.Snapshot, int64) {
	tb.Helper()
	doc, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	sn, err := st.Write(store.Meta{Device: device, Host: device + ".example.test", Serial: "000000000001"},
		map[string][]byte{store.ConfigDoc: doc}, 1)
	if err != nil {
		tb.Fatal(err)
	}
	return sn, int64(len(doc))
}

// writeMultiVsys generates a firewall configuration of four vsys. Each holds
// addrs addresses, three levels of nested static address groups over them (a
// group of the lowest level holds ten addresses, every other group three of
// the level below), rules security rules naming a group of the upper two
// levels, and a NAT and a PBF rule for every tenth security rule.
func writeMultiVsys(tb testing.TB, addrs, rules int) string {
	tb.Helper()
	var b strings.Builder
	b.WriteString(`<config version="11.2.0" urldb="paloaltonetworks"><devices>` +
		`<entry name="localhost.localdomain"><vsys>`)
	leaf := addrs / 10
	for v := range 4 {
		fmt.Fprintf(&b, `<entry name="vsys%d"><address>`, v+1)
		for i := range addrs {
			fmt.Fprintf(&b, `<entry name="a-%d-%d"><ip-netmask>10.%d.%d.%d</ip-netmask></entry>`,
				v, i, 88+v, i/256%256, i%256)
		}
		b.WriteString(`</address><address-group>`)
		group := func(name string, members []string) {
			fmt.Fprintf(&b, `<entry name="%s"><static>`, name)
			for _, m := range members {
				fmt.Fprintf(&b, `<member>%s</member>`, m)
			}
			b.WriteString(`</static></entry>`)
		}
		for i := range leaf {
			var m []string
			for j := range 10 {
				m = append(m, fmt.Sprintf("a-%d-%d", v, i*10+j))
			}
			group(fmt.Sprintf("l-%d-%d", v, i), m)
		}
		for i := range leaf / 3 {
			group(fmt.Sprintf("m-%d-%d", v, i), []string{
				fmt.Sprintf("l-%d-%d", v, 3*i), fmt.Sprintf("l-%d-%d", v, 3*i+1), fmt.Sprintf("l-%d-%d", v, 3*i+2),
			})
		}
		for i := range leaf / 9 {
			group(fmt.Sprintf("t-%d-%d", v, i), []string{
				fmt.Sprintf("m-%d-%d", v, 3*i), fmt.Sprintf("m-%d-%d", v, 3*i+1), fmt.Sprintf("m-%d-%d", v, 3*i+2),
			})
		}
		src := func(i int) string {
			if i%2 == 0 {
				return fmt.Sprintf("t-%d-%d", v, i%(leaf/9))
			}
			return fmt.Sprintf("m-%d-%d", v, i%(leaf/3))
		}
		b.WriteString(`</address-group><rulebase><security><rules>`)
		for i := range rules {
			fmt.Fprintf(&b, `<entry name="r-%d"><from><member>any</member></from><to><member>any</member></to>`+
				`<source><member>%s</member></source><destination><member>a-%d-%d</member></destination>`+
				`<application><member>any</member></application><service><member>application-default</member></service>`+
				`<action>allow</action></entry>`, i, src(i), v, (i*7)%addrs)
		}
		b.WriteString(`</rules></security><nat><rules>`)
		for i := 0; i < rules; i += 10 {
			fmt.Fprintf(&b, `<entry name="n-%d"><from><member>any</member></from><to><member>any</member></to>`+
				`<source><member>%s</member></source><destination><member>any</member></destination>`+
				`<service>any</service><source-translation><dynamic-ip-and-port><interface-address>`+
				`<interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation></entry>`,
				i, src(i))
		}
		b.WriteString(`</rules></nat><pbf><rules>`)
		for i := 0; i < rules; i += 10 {
			fmt.Fprintf(&b, `<entry name="p-%d"><from><zone><member>any</member></zone></from>`+
				`<source><member>%s</member></source><destination><member>any</member></destination>`+
				`<application><member>any</member></application><service><member>any</member></service>`+
				`<action><no-pbf/></action></entry>`, i, src(i))
		}
		b.WriteString(`</rules></pbf></rulebase></entry>`)
	}
	b.WriteString(`</vsys></entry></devices></config>`)
	path := filepath.Join(tb.TempDir(), "multivsys.xml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// retentionShape is one generated configuration shape at two sizes.
type retentionShape struct {
	name         string
	small, large func(testing.TB) string
}

var retentionShapes = []retentionShape{
	{
		// One vsys: testconfig's tree of 2,000 nested address groups.
		name:  "single",
		small: func(tb testing.TB) string { return testconfig.Write(tb, testconfig.Groups{Addrs: 20000, Rules: 6000}) },
		large: func(tb testing.TB) string { return testconfig.Write(tb, testconfig.Groups{Addrs: 40000, Rules: 12000}) },
	},
	{
		name:  "multi",
		small: func(tb testing.TB) string { return writeMultiVsys(tb, 5000, 1500) },
		large: func(tb testing.TB) string { return writeMultiVsys(tb, 10000, 3000) },
	},
}

// retentionSample is the bytes one file retains.
type retentionSample struct {
	what      string
	fileBytes int64
	retained  uint64
}

// R7. The cache sizes a snapshot's configuration at configFixedBytes plus
// configPerByte times its file's bytes, and docs/commands/mcp.md gives that
// model for max_cache. This measures it: each shape at two sizes, the
// configuration with the security, NAT and PBF index of every vsys, live after
// a garbage collection. A straight line through the two sizes gives a shape's
// fixed part and its part per file byte, reported as <shape>-fixed-B and
// <shape>-B/file-B.
//
// It also measures what the schema digest keeps, once per process, reported
// as digest-B, and what one App-ID content version of 5552 applications
// keeps, reported as content-B (spec 2026-10-16 §7).
//
// It fails when the cache's estimate falls short of what any sample retains,
// the multi-vsys fixture included, when the digest keeps more than
// digestBytes, or when the content keeps more than contentBytes, so
// bench-check catches a figure that no longer holds.
func BenchmarkCacheRetention(b *testing.B) {
	digest := digestRetained(b)
	if digest > digestBytes {
		b.Errorf("the schema digest retains %d, above the estimate digestBytes %d", digest, digestBytes)
	}

	st, err := store.Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	apps := filepath.Join(b.TempDir(), "8000-1000.v1.xml.gz")
	if err := os.WriteFile(apps, testconfig.AppContent(b, contentApps), 0o600); err != nil {
		b.Fatal(err)
	}
	tiny, tinyBytes := snapshotOf(b, st, "fixture", multiVsysFixture)
	retained(b, tiny) // warm the process-wide digest and schema tables

	type shapeSnaps struct {
		name         string
		small, large store.Snapshot
		sb, lb       int64
	}
	var shapes []shapeSnaps
	for _, s := range retentionShapes {
		sm, sb := snapshotOf(b, st, s.name+"-small", s.small(b))
		lg, lb := snapshotOf(b, st, s.name+"-large", s.large(b))
		shapes = append(shapes, shapeSnaps{s.name, sm, lg, sb, lb})
	}

	var samples []retentionSample
	var content uint64
	fixed, perByte := map[string]float64{}, map[string]float64{}
	for b.Loop() {
		content = contentRetained(b, apps)
		samples = []retentionSample{{"multi-vsys fixture", tinyBytes, retained(b, tiny)}}
		for _, s := range shapes {
			rs, rl := retained(b, s.small), retained(b, s.large)
			samples = append(samples,
				retentionSample{s.name + " small", s.sb, rs}, retentionSample{s.name + " large", s.lb, rl})
			pb := (float64(rl) - float64(rs)) / float64(s.lb-s.sb)
			perByte[s.name], fixed[s.name] = pb, float64(rs)-pb*float64(s.sb)
		}
	}
	b.ReportMetric(float64(digest), "digest-B") // after the loop, which clears metrics reported before
	b.ReportMetric(float64(content), "content-B")
	if content > contentBytes {
		b.Errorf("a content version of %d applications retains %d, above the estimate contentBytes %d",
			contentApps, content, contentBytes)
	}
	for _, s := range shapes {
		b.ReportMetric(fixed[s.name], s.name+"-fixed-B")
		b.ReportMetric(perByte[s.name], s.name+"-B/file-B")
	}
	for _, s := range samples {
		if est := configBytes(s.fileBytes); uint64(est) < s.retained {
			b.Errorf("%s: %d file bytes retain %d, above the estimate %d (%d + %d per byte); measured %s",
				s.what, s.fileBytes, s.retained, est, configFixedBytes, configPerByte, fitted(fixed, perByte))
		}
	}
}

// multiVsysFixture is the committed configuration that the retention checks
// load as is.
const multiVsysFixture = "../../testdata/config/firewall-multivsys.xml"

// digestProbeEnv makes TestDigestRetained measure: digestRetained sets it in
// the process it starts.
const digestProbeEnv = "PROTEUS_DIGEST_PROBE"

// digestRetained returns the bytes that the first configuration load of a
// process keeps beyond the configuration: the decoded schema digest and its
// tables. It measures in a new process of this test binary, because the
// digest loads once per process, and any load before in this one (a test, or
// an earlier -count) hides it.
func digestRetained(tb testing.TB) uint64 {
	tb.Helper()
	cmd := exec.CommandContext(tb.Context(), os.Args[0], "-test.run=^TestDigestRetained$")
	cmd.Env = append(os.Environ(), digestProbeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		tb.Fatalf("digest probe: %v\n%s", err, out)
	}
	for line := range strings.Lines(string(out)) {
		if n, ok := strings.CutPrefix(strings.TrimSpace(line), "digest-retained "); ok {
			v, err := strconv.ParseUint(n, 10, 64)
			if err != nil {
				tb.Fatalf("digest probe: %v", err)
			}
			return v
		}
	}
	tb.Fatalf("digest probe printed no measurement:\n%s", out)
	return 0
}

// TestDigestRetained is the process that digestRetained starts. It loads the
// multi-vsys fixture twice: the first load also decodes the schema digest
// and builds its tables, which stay for the process; the second does not.
// It prints the difference.
//
//nolint:paralleltest // it measures the heap
func TestDigestRetained(t *testing.T) {
	if os.Getenv(digestProbeEnv) == "" {
		t.Skip("runs only in the process that BenchmarkCacheRetention starts")
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sn, _ := snapshotOf(t, st, "fixture", multiVsysFixture)
	first, second := retained(t, sn), retained(t, sn)
	if first < second {
		t.Fatalf("the first load retains %d, less than the second's %d", first, second)
	}
	fmt.Printf("digest-retained %d\n", first-second)
}

// fitted lists the measured parts of each shape.
func fitted(fixed, perByte map[string]float64) string {
	var parts []string
	for _, s := range retentionShapes {
		parts = append(parts, fmt.Sprintf("%s: %.0f fixed + %.2f per byte", s.name,
			math.Round(fixed[s.name]), perByte[s.name]))
	}
	return strings.Join(parts, ", ")
}

// The cache's estimate holds the last measurements of BenchmarkCacheRetention
// (Apple M3 Pro), and covers what the multi-vsys fixture retains. The
// benchmark itself fails in bench-check when a new measurement exceeds it.
//
// It does not run in parallel: the heap it measures must hold no other
// test's allocations.
//
//nolint:paralleltest // it measures the heap
func TestCacheEstimateCoversTheMeasurements(t *testing.T) {
	for _, m := range []struct {
		shape   string
		fixed   float64
		perByte float64
	}{
		{"single", 29_292_043, 12.81},
		{"multi", 350_081, 12.74},
	} {
		if configFixedBytes < m.fixed || configPerByte < m.perByte {
			t.Errorf("%s: measured %.0f fixed + %.2f per byte, above the estimate %d + %d",
				m.shape, m.fixed, m.perByte, configFixedBytes, configPerByte)
		}
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sn, n := snapshotOf(t, st, "fixture", multiVsysFixture)
	if got := retained(t, sn); uint64(configBytes(n)) < got {
		t.Errorf("the fixture's %d bytes retain %d, above the estimate %d", n, got, configBytes(n))
	}
}
