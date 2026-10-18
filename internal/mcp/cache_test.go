package mcp

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"github.com/okaiser/proteus/internal/appid"
	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/store"
	"github.com/okaiser/proteus/internal/testconfig"
)

// cacheLab is the lab's two snapshots and a cache over them whose loads are
// counted.
type cacheLab struct {
	st       *store.Store
	fw01     store.Snapshot
	fw02     store.Snapshot
	cache    *Cache
	loads    atomic.Int32
	appLoads atomic.Int32 // of content files
	idLoads  atomic.Int32 // of identity files
}

func newCacheLab(t *testing.T, maxBytes int64) *cacheLab {
	t.Helper()
	return cacheLabOf(t, "", maxBytes)
}

// cacheLabOf is a cache lab whose snapshots name the content version apps,
// "" for none.
func cacheLabOf(t *testing.T, apps string, maxBytes int64) *cacheLab {
	t.Helper()
	return cacheLabWith(t, apps, nil, maxBytes)
}

// identityLab is a cache lab whose snapshots each hold the identity fixture.
func identityLab(t *testing.T, maxBytes int64) *cacheLab {
	t.Helper()
	return cacheLabWith(t, "", pathlab.Read(t, identityFixture(t)), maxBytes)
}

// cacheLabWith is cacheLabOf whose snapshots each hold the identity file ids;
// nil for none.
func cacheLabWith(t *testing.T, apps string, ids []byte, maxBytes int64) *cacheLab {
	t.Helper()
	env := labEnvWith(t, apps, ids, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)}, snap{pathlab.FW02, pathlab.ConfigFile(pathlab.FW02)})
	l := &cacheLab{st: env.Store, cache: newCache(maxBytes, 2, 4, true)}
	l.cache.loadApps = func(path string) (*appid.Data, error) {
		l.appLoads.Add(1)
		return appid.Load(path)
	}
	l.cache.loadIdentity = func(path string) (*identity.Data, error) {
		l.idLoads.Add(1)
		return identity.Load(path)
	}
	var err error
	if l.fw01, err = env.Store.Latest(pathlab.FW01); err != nil {
		t.Fatal(err)
	}
	if l.fw02, err = env.Store.Latest(pathlab.FW02); err != nil {
		t.Fatal(err)
	}
	l.cache.load = func(path string) (*config.Config, config.Report, error) {
		l.loads.Add(1)
		return config.Load(path)
	}
	return l
}

// eventually waits for cond, or fails the test after a few seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 500 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("never: %s", what)
}

// Concurrent misses of one snapshot share one load, and its indexes are
// built once for all callers.
func TestConcurrentMissesLoadOnce(t *testing.T) {
	t.Parallel()
	l := newCacheLab(t, 1<<30)
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	var wg sync.WaitGroup
	got := make([]estate.Loaded, 16)
	for i := range got {
		wg.Go(func() {
			ld, err := l.cache.bind(context.Background()).Config(l.fw01)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := ld.Indexes.Index(sc, resolve.Security); err != nil {
				t.Error(err)
			}
			got[i] = ld
		})
	}
	wg.Wait()
	if n := l.loads.Load(); n != 1 {
		t.Errorf("%d loads, want 1", n)
	}
	first, _ := got[0].Indexes.Index(sc, resolve.Security)
	for _, ld := range got {
		if ld.Config != got[0].Config {
			t.Fatal("callers got different configurations")
		}
		if idx, _ := ld.Indexes.Index(sc, resolve.Security); idx != first {
			t.Fatal("callers got different indexes")
		}
	}
}

// Past its limit the cache drops the least recently used snapshot. The
// garbage collector frees it once no call reads it, and the next call loads
// it again.
func TestEvictionFrees(t *testing.T) {
	t.Parallel()
	l := newCacheLab(t, 0)
	// Room for the digest and the larger of the two snapshots, not both.
	one := configBytes(max(fileBytes(l.fw01.Path(store.ConfigDoc)), fileBytes(l.fw02.Path(store.ConfigDoc))))
	l.cache.max = digestBytes + one
	ref := func(sn store.Snapshot) weak.Pointer[config.Config] {
		ld, err := l.cache.bind(context.Background()).Config(sn)
		if err != nil {
			t.Fatal(err)
		}
		return weak.Make(ld.Config)
	}
	w := ref(l.fw01)
	ref(l.fw02)
	l.cache.mu.Lock()
	n, size, fixed := l.cache.order.Len(), l.cache.size, l.cache.fixed
	l.cache.mu.Unlock()
	if n != 1 || size+fixed > l.cache.max || fixed != digestBytes {
		t.Errorf("after two loads: %d items, %d + %d bytes, limit %d", n, size, fixed, l.cache.max)
	}
	eventually(t, "the dropped configuration is freed", func() bool {
		runtime.GC()
		return w.Value() == nil
	})
	ref(l.fw01)
	if got := l.loads.Load(); got != 3 {
		t.Errorf("%d loads, want 3: the dropped snapshot loads again", got)
	}
	// One item larger than the limit is not kept, and its caller still has it.
	l.cache.max = digestBytes
	if ld, err := l.cache.bind(context.Background()).Config(l.fw02); err != nil || ld.Config == nil {
		t.Errorf("an item past the limit: %v", err)
	}
	if l.cache.order.Len() != 0 || l.cache.size != 0 {
		t.Errorf("the cache kept %d items of %d bytes", l.cache.order.Len(), l.cache.size)
	}
}

// The stale note is built per call: a snapshot read from the cache ages
// between two calls, and the second call notes it.
func TestTheStaleNoteIsPerCall(t *testing.T) {
	t.Parallel()
	l := newCacheLab(t, 1<<30)
	at := func(now time.Time) []string {
		ts, holes := estate.Open(l.st, []string{pathlab.FW01}, nil, estate.When{
			Now: now, MaxAge: 2 * time.Hour, Configs: l.cache.bind(context.Background()), Ops: l.cache,
		})
		if len(ts) == 0 || len(holes) != 0 {
			t.Fatalf("%v %v", ts, holes)
		}
		if ts[0].Indexes == nil {
			t.Error("a cached target carries no indexes")
		}
		var codes []string
		for _, n := range ts[0].Notes {
			codes = append(codes, string(n.Code))
		}
		return codes
	}
	if got := at(l.fw01.Meta.TakenAt.Add(time.Hour)); len(got) != 0 {
		t.Errorf("fresh: %v", got)
	}
	if got := at(l.fw01.Meta.TakenAt.Add(3 * time.Hour)); len(got) != 1 || got[0] != "note.snapshot-stale" {
		t.Errorf("aged: %v", got)
	}
	if n := l.loads.Load(); n != 1 {
		t.Errorf("%d loads, want 1", n)
	}
}

// A load whose caller stops waiting finishes and fills the cache: the next
// call takes it without a load.
func TestALoadOutlivesItsCaller(t *testing.T) {
	t.Parallel()
	l := newCacheLab(t, 1<<30)
	release := make(chan struct{})
	l.cache.load = func(path string) (*config.Config, config.Report, error) {
		<-release
		l.loads.Add(1)
		return config.Load(path)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	cc := l.cache.bind(ctx)
	go func() {
		_, err := cc.Config(l.fw01)
		done <- err
	}()
	eventually(t, "the load starts", func() bool { return len(l.cache.loads.slots) == 1 })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || !errors.Is(cc.settle(nil), context.Canceled) {
		t.Errorf("the caller that left: %v, call %v", err, cc.settle(nil))
	}
	close(release)
	eventually(t, "the load fills the cache", func() bool {
		_, ok := l.cache.get(itemKey{kind: "config", member: l.fw01.Device, id: l.fw01.ID})
		return ok
	})
	if _, err := l.cache.bind(context.Background()).Config(l.fw01); err != nil || l.loads.Load() != 1 {
		t.Errorf("after: %v, %d loads", err, l.loads.Load())
	}
}

// A load that waits for a slot is dropped when its last caller leaves; a
// load past the queue is refused at once.
func TestTheLoadQueue(t *testing.T) {
	t.Parallel()
	ld := newLoader(1, 1, true)
	block := make(chan struct{})
	go func() {
		_, _ = ld.do(context.Background(), "a", func() (any, error) { <-block; return nil, nil })
	}()
	eventually(t, "a runs", func() bool { return len(ld.slots) == 1 })

	ctx, cancel := context.WithCancel(context.Background())
	var ran atomic.Bool
	done := make(chan error, 1)
	go func() {
		_, err := ld.do(ctx, "b", func() (any, error) { ran.Store(true); return nil, nil })
		done <- err
	}()
	queued := func() int {
		ld.mu.Lock()
		defer ld.mu.Unlock()
		return ld.queued
	}
	eventually(t, "b waits", func() bool { return queued() == 1 })
	// The queue is full: another load is refused.
	if _, err := ld.do(context.Background(), "c", func() (any, error) { return nil, nil }); !errors.Is(err, errLoadsBusy) {
		t.Errorf("c: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("b's caller: %v", err)
	}
	eventually(t, "b is dropped", func() bool { return queued() == 0 })
	close(block)
	// b's slot goes to the next load; b itself never ran.
	if v, err := ld.do(context.Background(), "d", func() (any, error) { return "d", nil }); err != nil || v != "d" {
		t.Errorf("d: %v %v", v, err)
	}
	if ran.Load() {
		t.Error("the dropped load ran")
	}
}

// A load joined just as its callers left starts again for the new caller.
func TestADroppedLoadStartsAgain(t *testing.T) {
	t.Parallel()
	ld := newLoader(1, 1, true)
	// The flight has no waiter: it is dropped, and do runs it again.
	ld.mu.Lock()
	ld.slots <- struct{}{}
	ld.mu.Unlock()
	if _, err := ld.run("x", func() (any, error) { return nil, nil }); !errors.Is(err, errDropped) {
		t.Errorf("run without a waiter: %v", err)
	}
	<-ld.slots
	var n atomic.Int32
	fn := func() (any, error) { n.Add(1); return "x", nil }
	if v, err := ld.do(context.Background(), "x", fn); err != nil || v != "x" || n.Load() != 1 {
		t.Errorf("do: %v %v %d", v, err, n.Load())
	}
	// A caller that returns to a queued load before it wakes keeps it.
	ld.slots <- struct{}{}
	ld.mu.Lock()
	ld.waiters["y"] = 1
	ld.mu.Unlock()
	res := make(chan error, 1)
	go func() {
		_, err := ld.run("y", func() (any, error) { return nil, nil })
		res <- err
	}()
	var gone chan struct{}
	eventually(t, "y waits", func() bool {
		ld.mu.Lock()
		defer ld.mu.Unlock()
		gone = ld.gone["y"]
		return gone != nil
	})
	ld.mu.Lock()
	close(gone)
	delete(ld.gone, "y")
	ld.mu.Unlock()
	eventually(t, "y waits again", func() bool {
		ld.mu.Lock()
		defer ld.mu.Unlock()
		return ld.gone["y"] != nil
	})
	<-ld.slots
	if err := <-res; err != nil {
		t.Errorf("y: %v", err)
	}
}

// A load that panics gives the call call.internal with the stack; the slot
// is free again.
func TestAPanickingLoadIsRecovered(t *testing.T) {
	t.Parallel()
	l := newCacheLab(t, 1<<30)
	l.cache.loads.strict = false
	l.cache.load = func(string) (*config.Config, config.Report, error) { panic("loader bug") }
	cc := l.cache.bind(context.Background())
	if _, err := cc.Config(l.fw01); err == nil || !strings.Contains(err.Error(), "loader bug") {
		t.Fatalf("err = %v", err)
	}
	err := cc.settle(errors.New("a hole"))
	p, ok := errors.AsType[*panicError](err)
	if !ok || !strings.Contains(string(p.stack), "goroutine") {
		t.Fatalf("settle = %v", err)
	}
	if te := errorOf(err); te.Code != "call.internal" || te.Text != internalText {
		t.Errorf("tool error %+v", te)
	}
	if len(l.cache.loads.slots) != 0 {
		t.Error("the panicked load kept its slot")
	}
	// In a test binary the load panics on.
	ld := newLoader(1, 1, true)
	ld.waiters["z"] = 1
	func() {
		defer func() {
			if p := recover(); p != "strict" {
				t.Errorf("strict: %v", p)
			}
		}()
		_, _ = ld.run("z", func() (any, error) { panic("strict") })
	}()
}

// A full load queue is the call's error, call.busy, whatever hole the answer
// made of it. A snapshot's own load error stays a hole.
func TestAFullQueueIsBusy(t *testing.T) {
	t.Parallel()
	l := newCacheLab(t, 1<<30)
	cc := l.cache.bind(context.Background())
	if err := cc.fail(errors.New("unreadable")); !errors.Is(cc.settle(err), err) {
		t.Error("a snapshot's error became the call's")
	}
	_ = cc.fail(errLoadsBusy)
	_ = cc.fail(context.Canceled)
	if err := cc.settle(nil); !errors.Is(err, errLoadsBusy) {
		t.Errorf("settle = %v", err)
	}
	if te := errorOf(cc.settle(nil)); te.Code != "call.busy" {
		t.Errorf("tool error %+v", te)
	}
	var none *callCache
	if err := none.settle(context.Canceled); !errors.Is(err, context.Canceled) {
		t.Errorf("no view: %v", err)
	}
	// A file that does not open is not kept.
	l.cache.load = func(path string) (*config.Config, config.Report, error) {
		return nil, config.Report{}, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	if _, err := cc.Config(l.fw01); err == nil {
		t.Error("a failed load answered")
	}
	if _, ok := l.cache.get(itemKey{kind: "config", member: l.fw01.Device, id: l.fw01.ID}); ok {
		t.Error("a file that did not open was kept")
	}
}

// A configuration that does not parse is parsed once per snapshot: its error
// is cached as a small item, and goes out with the least recently used. A
// file that cannot be opened is tried again, as it may appear.
func TestAFailedLoadIsNotParsedAgain(t *testing.T) {
	t.Parallel()
	l := newCacheLab(t, 1<<30)
	k := itemKey{kind: "config", member: l.fw01.Device, id: l.fw01.ID}
	// fw01's configuration file does not parse.
	if err := os.WriteFile(l.fw01.Path(store.ConfigDoc), []byte("<config"), 0o600); err != nil {
		t.Fatal(err)
	}
	cc := l.cache.bind(context.Background())
	first, err := cc.Config(l.fw01)
	if err == nil || first.Config != nil {
		t.Fatalf("a broken configuration loaded: %v", err)
	}
	again, err2 := cc.Config(l.fw01)
	if err2 == nil || err2.Error() != err.Error() || again.Config != nil || l.loads.Load() != 1 {
		t.Errorf("second call: %v, %d loads", err2, l.loads.Load())
	}
	if v, ok := l.cache.get(k); !ok {
		t.Error("the parse error was not kept")
	} else if _, failed := v.(failedLoad); !failed {
		t.Errorf("kept %T", v)
	}
	l.cache.mu.Lock()
	size := l.cache.size
	l.cache.mu.Unlock()
	if size != failedBytes {
		t.Errorf("size %d, want %d", size, failedBytes)
	}
	if errors.Is(cc.settle(nil), err) {
		t.Error("a snapshot's parse error became the call's")
	}
	// The error item goes out like any item.
	small := newCacheLab(t, failedBytes)
	small.cache.load = func(string) (*config.Config, config.Report, error) {
		small.loads.Add(1)
		return nil, config.Report{}, errors.New("config: no version")
	}
	scc := small.cache.bind(context.Background())
	for _, sn := range []store.Snapshot{small.fw01, small.fw02, small.fw01, small.fw01} {
		if _, err := scc.Config(sn); err == nil {
			t.Fatal("a broken configuration loaded")
		}
	}
	if small.loads.Load() != 3 {
		t.Errorf("%d loads, want 3: fw02's error drops fw01's, which then stays", small.loads.Load())
	}
	// A file that does not open is tried again.
	gone := l.fw02
	gone.Dir = t.TempDir()
	for range 2 {
		if _, err := cc.Config(gone); err == nil {
			t.Fatal("a missing configuration loaded")
		}
	}
	if l.loads.Load() != 3 {
		t.Errorf("%d loads, want 3: a missing file is opened each time", l.loads.Load())
	}
	if _, ok := l.cache.get(itemKey{kind: "config", member: gone.Device, id: gone.ID}); ok {
		t.Error("a missing file was kept")
	}
}

// A failed index build is not kept, and the call keeps it as the target's.
func TestAFailedIndexBuild(t *testing.T) {
	t.Parallel()
	l := newCacheLab(t, 1<<30)
	ld, err := l.cache.bind(context.Background()).Config(l.fw01)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ld.Indexes.Index(config.Scope{Sort: config.ScopeVsys, Name: "vsys9"}, resolve.Security); err == nil {
		t.Error("an unknown vsys built")
	}
}

// The operational data of a snapshot is read once; a failed read is not
// kept.
func TestOperationalDataIsReadOnce(t *testing.T) {
	t.Parallel()
	l := newCacheLab(t, 1<<30)
	a, err := l.cache.Tables(l.fw01)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := l.cache.Tables(l.fw01)
	if len(a.Interfaces) == 0 || &a.Interfaces[0] != &b.Interfaces[0] {
		t.Error("the tables were read twice")
	}
	if _, err := l.cache.HA(l.fw01); err != nil {
		t.Error(err)
	}
	if _, ok := l.cache.get(itemKey{kind: "ha", member: l.fw01.Device, id: l.fw01.ID}); !ok {
		t.Error("the HA state was not kept")
	}
	gone := l.fw02
	gone.Dir = t.TempDir()
	if _, err := l.cache.Tables(gone); err == nil {
		t.Error("tables of an empty snapshot")
	}
	if _, ok := l.cache.get(itemKey{kind: "tables", member: gone.Device, id: gone.ID}); ok {
		t.Error("a failed read was kept")
	}
	if err := os.WriteFile(gone.Path(store.HADoc), []byte("<response><result>bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.cache.HA(gone); err == nil {
		t.Error("an unreadable HA state")
	}
}

// contentKey8000 is the cache key of the fixture's content version.
var contentKey8000 = itemKey{kind: "content", id: "8000-1000.v1.xml.gz"}

// appsThrough is a snapshot's content data as a call reads it: through the
// configuration entry.
func appsThrough(t *testing.T, cc *callCache, sn store.Snapshot) *appid.Data {
	t.Helper()
	ld, err := cc.Config(sn)
	if err != nil || ld.Apps == nil {
		t.Fatalf("%s: %v, loader %v", sn.Device, err, ld.Apps != nil)
	}
	d, err := ld.Apps()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// cached is the value of a key, or nil.
func (l *cacheLab) cached(k itemKey) any {
	v, _ := l.cache.get(k)
	return v
}

// Two snapshots of one content version load its file once: the content is
// one cache item, keyed by the file name, and both calls get one value. A
// snapshot without a content version has no loader, and a file that does not
// exist is not kept (spec 2026-10-16 §7).
func TestContentIsOneItemPerVersion(t *testing.T) {
	t.Parallel()
	l := cacheLabOf(t, "8000-1000", 1<<30)
	cc := l.cache.bind(context.Background())
	a, b := appsThrough(t, cc, l.fw01), appsThrough(t, cc, l.fw02)
	if a != b || l.appLoads.Load() != 1 || a.Version() != "8000-1000" {
		t.Errorf("%d loads; the same value %v", l.appLoads.Load(), a == b)
	}
	if v := l.cached(contentKey8000); v != a {
		t.Errorf("the item under %+v is %v", contentKey8000, v)
	}
	if d, err := cc.Apps(l.fw01.ContentPath()); d != a || err != nil || l.appLoads.Load() != 1 {
		t.Errorf("Apps: %v, %d loads", err, l.appLoads.Load())
	}
	plain := newCacheLab(t, 1<<30)
	if ld, err := plain.cache.bind(context.Background()).Config(plain.fw01); err != nil || ld.Apps != nil {
		t.Errorf("a snapshot without a content version: %v, loader %v", err, ld.Apps != nil)
	}
	gone := filepath.Join(t.TempDir(), "8000-0999.v1.xml.gz")
	if _, err := cc.Apps(gone); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
	if l.cached(itemKey{kind: "content", id: filepath.Base(gone)}) != nil {
		t.Error("a missing file was kept")
	}
}

// configSizes is the estimated size of each lab snapshot's configuration.
func (l *cacheLab) configSizes() (int64, int64) {
	return configBytes(fileBytes(l.fw01.Path(store.ConfigDoc))), configBytes(fileBytes(l.fw02.Path(store.ConfigDoc)))
}

// The content item counts in the size, not in the fixed part: past the
// limit, the least recently used content goes before a newer configuration
// (spec 2026-10-16 §7).
func TestContentGoesFirstWhenOld(t *testing.T) {
	t.Parallel()
	l := cacheLabOf(t, "8000-1000", 0)
	one, two := l.configSizes()
	l.cache.max = digestBytes + one + two + contentBytes - 1
	cc := l.cache.bind(context.Background())
	appsThrough(t, cc, l.fw01)
	if _, err := cc.Config(l.fw01); err != nil { // fw01 is now used after its content
		t.Fatal(err)
	}
	if _, err := cc.Config(l.fw02); err != nil {
		t.Fatal(err)
	}
	if l.cached(contentKey8000) != nil {
		t.Error("the old content stayed")
	}
	for _, sn := range []store.Snapshot{l.fw01, l.fw02} {
		if l.cached(itemKey{kind: "config", member: sn.Device, id: sn.ID}) == nil {
			t.Errorf("%s: the configuration went", sn.Device)
		}
	}
	l.cache.mu.Lock()
	size, fixed := l.cache.size, l.cache.fixed
	l.cache.mu.Unlock()
	if size != one+two || fixed != digestBytes {
		t.Errorf("size %d + fixed %d, want %d + %d", size, fixed, one+two, digestBytes)
	}
}

// After the cache drops the content item, a call through the configuration
// entry puts the same value back with its size: the file loads once (spec
// 2026-10-16 §7). A call through the entry while the item is cached uses it.
func TestAnEntryPutsItsContentBack(t *testing.T) {
	t.Parallel()
	l := cacheLabOf(t, "8000-1000", 0)
	one, two := l.configSizes()
	l.cache.max = digestBytes + one + two + contentBytes - 1
	cc := l.cache.bind(context.Background())
	first := appsThrough(t, cc, l.fw01)
	if appsThrough(t, cc, l.fw01) != first {
		t.Error("a second call through the entry got another value")
	}
	if _, err := cc.Config(l.fw01); err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Config(l.fw02); err != nil {
		t.Fatal(err)
	}
	if l.cached(contentKey8000) != nil {
		t.Fatal("the content was not dropped")
	}
	if got := appsThrough(t, cc, l.fw01); got != first || l.appLoads.Load() != 1 {
		t.Errorf("the same value %v, %d loads", got == first, l.appLoads.Load())
	}
	if l.cached(contentKey8000) != first {
		t.Error("the entry did not put its content back")
	}
	l.cache.mu.Lock()
	size := l.cache.size
	l.cache.mu.Unlock()
	if size > l.cache.max || size < contentBytes {
		t.Errorf("size %d: the content does not count", size)
	}
	// fw02's entry has no content yet: it takes the cached one.
	if got := appsThrough(t, cc, l.fw02); got != first || l.appLoads.Load() != 1 {
		t.Errorf("fw02: the same value %v, %d loads", got == first, l.appLoads.Load())
	}
	// Another call loads the version again after the item went: the entry
	// then takes that value, so one value stays.
	l.drop(contentKey8000)
	again, err := cc.Apps(l.fw01.ContentPath())
	if err != nil || again == first || l.appLoads.Load() != 2 {
		t.Fatalf("a new load: %v, %d loads", err, l.appLoads.Load())
	}
	if got := appsThrough(t, cc, l.fw01); got != again {
		t.Error("the entry kept its old value")
	}
}

// drop removes an item, as the cache does past its limit.
func (l *cacheLab) drop(k itemKey) {
	l.cache.mu.Lock()
	defer l.cache.mu.Unlock()
	el := l.cache.items[k]
	l.cache.order.Remove(el)
	delete(l.cache.items, k)
	l.cache.size -= el.Value.(*item).size
}

// A snapshot whose content file is gone gives the error through the entry,
// and the entry keeps nothing: the next call tries the file again.
// Concurrent first reads of one version share one load.
func TestAMissingContentFileThroughTheEntry(t *testing.T) {
	t.Parallel()
	l := cacheLabOf(t, "8000-1000", 1<<30)
	path := l.fw01.ContentPath()
	saved := pathlab.Read(t, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	cc := l.cache.bind(context.Background())
	ld, err := cc.Config(l.fw01)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ld.Apps(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
	if err := l.st.WriteContent("8000-1000", saved); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	got := make([]*appid.Data, 8)
	for i := range got {
		wg.Go(func() {
			d, err := ld.Apps()
			if err != nil {
				t.Error(err)
			}
			got[i] = d
		})
	}
	wg.Wait()
	for _, d := range got {
		if d == nil || d != got[0] {
			t.Fatal("the callers got different values")
		}
	}
	if n := l.appLoads.Load(); n != 2 {
		t.Errorf("%d loads, want 2: the failed one and one for all callers", n)
	}
}

// identityOf is a snapshot's identity data as a call reads it: through the
// loader of its configuration.
func identityOf(t *testing.T, cc *callCache, sn store.Snapshot) *identity.Data {
	t.Helper()
	ld, err := cc.Config(sn)
	if err != nil || ld.Identity == nil {
		t.Fatalf("%s: %v, loader %v", sn.Device, err, ld.Identity != nil)
	}
	d, err := ld.Identity()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// identityItem is the cache key of a snapshot's identity file.
func identityItem(sn store.Snapshot) itemKey {
	return itemKey{kind: "identity", member: sn.Device, id: sn.ID}
}

// Two calls on one snapshot load its identity file once: the file is one
// cache item, keyed by the device and the snapshot id, and both calls get one
// value. Another snapshot is another item. A snapshot without the file has no
// loader, and a file that does not exist is not kept (spec 2026-10-17 §4.2,
// §8).
func TestIdentityIsOneItemPerSnapshot(t *testing.T) {
	t.Parallel()
	l := identityLab(t, 1<<30)
	k := identityItem(l.fw01)
	if got := identityKey(l.fw01.IdentityPath()); got != k {
		t.Errorf("identityKey = %+v, want %+v", got, k)
	}
	a := identityOf(t, l.cache.bind(context.Background()), l.fw01)
	b := identityOf(t, l.cache.bind(context.Background()), l.fw01)
	if a != b || l.idLoads.Load() != 1 || a.Counts().Users != 4 {
		t.Errorf("%d loads; the same value %v", l.idLoads.Load(), a == b)
	}
	if v := l.cached(k); v != a {
		t.Errorf("the item under %+v is %v", k, v)
	}
	cc := l.cache.bind(context.Background())
	if d, err := cc.Identity(l.fw01.IdentityPath()); d != a || err != nil || l.idLoads.Load() != 1 {
		t.Errorf("Identity: %v, %d loads", err, l.idLoads.Load())
	}
	if d := identityOf(t, cc, l.fw02); d == a || l.idLoads.Load() != 2 || l.cached(identityItem(l.fw02)) != d {
		t.Errorf("fw02: the same value %v, %d loads", d == a, l.idLoads.Load())
	}
	plain := newCacheLab(t, 1<<30)
	if ld, err := plain.cache.bind(context.Background()).Config(plain.fw01); err != nil || ld.Identity != nil {
		t.Errorf("a snapshot without an identity file: %v, loader %v", err, ld.Identity != nil)
	}
	gone := filepath.Join(t.TempDir(), "fw01", "20261018T000000Z", identity.FileName)
	if _, err := cc.Identity(gone); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
	if l.cached(identityKey(gone)) != nil {
		t.Error("a missing file was kept")
	}
}

// The identity item counts in the size with its estimate: past the limit,
// the least recently used identity item goes first, before a newer one and
// before newer configurations (spec 2026-10-17 §8).
func TestIdentityGoesWhenOld(t *testing.T) {
	t.Parallel()
	l := identityLab(t, 0)
	one, two := l.configSizes()
	fix, err := identity.Load(identityFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	ids := identityBytes(fix.Counts())
	l.cache.max = digestBytes + one + two + 2*ids - 1
	cc := l.cache.bind(context.Background())
	old := identityOf(t, cc, l.fw01)
	for _, sn := range []store.Snapshot{l.fw01, l.fw02} { // the configurations are now used after it
		if _, err := cc.Config(sn); err != nil {
			t.Fatal(err)
		}
	}
	newer := identityOf(t, cc, l.fw02)
	if l.cached(identityItem(l.fw01)) != nil {
		t.Error("the old identity item stayed")
	}
	if l.cached(identityItem(l.fw02)) != newer || newer == old {
		t.Error("the newer identity item went")
	}
	for _, sn := range []store.Snapshot{l.fw01, l.fw02} {
		if l.cached(itemKey{kind: "config", member: sn.Device, id: sn.ID}) == nil {
			t.Errorf("%s: the configuration went", sn.Device)
		}
	}
	l.cache.mu.Lock()
	size := l.cache.size
	l.cache.mu.Unlock()
	if size != one+two+ids {
		t.Errorf("size %d, want %d", size, one+two+ids)
	}
}

// identityFixture is the path of a copy of the identity fixture, gzipped.
func identityFixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), identity.FileName)
	testconfig.Identity(t, p)
	return p
}
