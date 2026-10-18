package mcp

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/okaiser/proteus/internal/appid"
	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/store"
)

// The size estimates of the cache (spec §12 C18).
//
// A snapshot's configuration with its edges and the security, NAT and PBF
// index of every vsys retains a fixed part plus a part per byte of its file
// (configBytes). BenchmarkCacheRetention measures both on two generated
// shapes at two sizes each, about 4 and 8 MB, and fails when this estimate
// falls short of any of them. Measured on an Apple M3 Pro:
//
//   - one vsys with a tree of 2,000 nested address groups: 29.3 MB fixed
//     (the group tree's closure, which does not grow with the file) and
//     12.81 bytes per file byte;
//   - four vsys with three levels of nested groups and NAT and PBF rules:
//     0.35 MB fixed and 12.74 bytes per file byte.
//
// Each part takes the larger shape's value, rounded up: the fixed part to a
// multiple of 4 MiB, the part per byte to a whole number. The schema digest
// takes about 9 MB once per process: the benchmark measures
// 8.8 MiB and fails above digestBytes, which leaves about 1 MiB to spare.
//
// One App-ID content version is one item of contentBytes, apart from the
// configurations that read it (spec 2026-10-16 §7). The benchmark measures
// a generated file of 5552 applications, as many as content 9159 has (F4):
// 9.0 MiB. contentBytes is that value rounded up to a multiple of 4 MiB, and
// the benchmark fails above it.
//
// One snapshot's identity data is one item of identityBytes (spec 2026-10-17
// §8): a fixed part, and parts per mapping, per user and group, and per
// membership. The benchmark measures the two generated files of §8 and
// fails when the estimate falls short of either. Four files of each shape
// fit the parts: an empty file, the mappings alone, the users and groups
// alone with one tag per user, and the whole file. Measured on an Apple M3
// Pro, the largest value of 13 runs:
//
//   - 1,000 users with 20 groups each and 10,000 mappings: 2.01 MB, of it
//     9.8 KB fixed, 74.7 bytes per mapping, 452.2 per user and group and
//     36.1 per membership;
//   - 10,000 users with 50 groups each and 100,000 mappings: 24.95 MB, of it
//     9.2 KB fixed, 72.9 bytes per mapping, 416.3 per user and group and
//     25.3 per membership.
//
// Each part takes the larger shape's value, rounded up: the fixed part to a
// multiple of 4 KiB, each other part to a multiple of 8 bytes. A user and a
// group take one part, and a tag of a user counts as a membership.
const (
	configFixedBytes = 32 << 20
	configPerByte    = 13
	digestBytes      = 10 << 20
	// opFactor sizes a snapshot's operational tables by their files' bytes.
	// It is an estimate, not a measurement: the parsed tables keep less text
	// than the XML they come from.
	opFactor = 2
	// failedBytes sizes a configuration that did not load: its error and the
	// item. An estimate.
	failedBytes = 1 << 10
	// contentBytes sizes one App-ID content version: the parsed applications
	// and containers of its file. The benchmark checks it.
	contentBytes = 12 << 20
	// The parts of identityBytes. The benchmark checks them.
	identityFixedBytes    = 12 << 10
	identityPerMapping    = 80
	identityPerUser       = 456
	identityPerMembership = 40
)

// configBytes estimates what a loaded configuration of a file's size retains
// with its indexes.
func configBytes(fileBytes int64) int64 { return configFixedBytes + configPerByte*fileBytes }

// identityBytes estimates what a snapshot's identity data retains, by its
// counts. Each user-tag pair counts as a membership (spec 2026-10-17 §8).
func identityBytes(c identity.Counts) int64 {
	return identityFixedBytes + identityPerMapping*int64(c.Mappings) +
		identityPerUser*int64(c.Users+c.Groups) + identityPerMembership*int64(c.Memberships+c.TagPairs)
}

// itemKey names a cached item: a kind and a snapshot, or the content file of
// a content version.
type itemKey struct {
	kind   string // "config", "ha", "tables", "identity" or "content"
	member string // the device; "" for content
	id     string // the snapshot id, or the content file's base name
}

// contentKey is the key of a content file: its base name,
// <version>.v<trim>.xml.gz, names the content version (spec 2026-10-16 §3.1).
func contentKey(path string) itemKey { return itemKey{kind: "content", id: filepath.Base(path)} }

// identityKey is the key of a snapshot's identity file,
// <store>/<device>/<id>/identity.json.gz: the device and the snapshot id
// (spec 2026-10-17 §4.1, §8).
func identityKey(path string) itemKey {
	dir := filepath.Dir(path)
	return itemKey{kind: "identity", member: filepath.Base(filepath.Dir(dir)), id: filepath.Base(dir)}
}

// item is one cached value and its estimated size.
type item struct {
	key  itemKey
	size int64
	val  any
}

// Cache keeps what the calls read of the store, per (member, snapshot id):
// each snapshot's configuration with its indexes, its operational tables
// (spec §4.8) and its identity data (spec 2026-10-17 §8), and each App-ID
// content version's data (spec 2026-10-16 §7). Which snapshot latest or at
// means is read from the store on each call; a snapshot's content never
// changes, so what the cache holds for it stays true. Notes are never cached: each call builds them from the
// snapshot meta and its clock.
//
// The least recently used items go when the estimated size passes the limit.
// An item that goes is only dropped from the cache: a call that still reads
// it keeps it, and the garbage collector frees it after the last one.
//
// It is safe for concurrent use.
type Cache struct {
	loads *loader
	ops   singleflight.Group
	// load reads a configuration file; config.Load, or a test's stand-in.
	load func(path string) (*config.Config, config.Report, error)
	// loadApps reads a content file; appid.Load, or a test's stand-in.
	loadApps func(path string) (*appid.Data, error)
	// loadIdentity reads an identity file; identity.Load, or a test's
	// stand-in.
	loadIdentity func(path string) (*identity.Data, error)

	mu    sync.Mutex
	max   int64      // bytes
	size  int64      // the items' estimated bytes
	fixed int64      // the schema digest's estimated bytes once a configuration loaded, never freed
	order *list.List // of *item, the most recently used first
	items map[itemKey]*list.Element
}

// newCache is a cache of at most maxBytes, whose loads run at most maxLoads at
// once with at most maxQueue waiting.
func newCache(maxBytes int64, maxLoads, maxQueue int, strict bool) *Cache {
	return &Cache{
		loads: newLoader(maxLoads, maxQueue, strict), load: config.Load, loadApps: appid.Load, loadIdentity: identity.Load,
		max: maxBytes, order: list.New(), items: map[itemKey]*list.Element{},
	}
}

// get is a cached value, now the most recently used.
func (c *Cache) get(k itemKey) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[k]
	if !ok {
		return nil, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*item).val, true
}

// put caches a value of an estimated size and drops the least recently used
// items while the cache is past its limit. schema is true when the value was
// read with the schema digest, which then counts once.
func (c *Cache) put(k itemKey, v any, size int64, schema bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.insert(k, v, size, schema)
}

// insert is put with the lock held.
func (c *Cache) insert(k itemKey, v any, size int64, schema bool) {
	if schema {
		c.fixed = digestBytes
	}
	if el, ok := c.items[k]; ok {
		c.size -= el.Value.(*item).size
		c.order.Remove(el)
	}
	c.items[k] = c.order.PushFront(&item{key: k, size: size, val: v})
	c.size += size
	for c.size+c.fixed > c.max && c.order.Len() > 0 {
		el := c.order.Back()
		it := el.Value.(*item)
		c.order.Remove(el)
		delete(c.items, it.key)
		c.size -= it.size
	}
}

// adopt is the value cached under k, now the most recently used. When k
// holds none, it caches v of an estimated size and returns it.
func (c *Cache) adopt(k itemKey, v any, size int64) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[k]; ok {
		c.order.MoveToFront(el)
		return el.Value.(*item).val
	}
	c.insert(k, v, size, false)
	return v
}

// fileBytes is a file's size, or 0 when it cannot be read.
func fileBytes(paths ...string) int64 {
	var n int64
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// configEntry is a loaded configuration and the indexes built from it so far.
type configEntry struct {
	cfg *config.Config
	rep config.Report
	set *index.Set

	mu    sync.Mutex
	built map[indexKey]*index.Index
	// content is the snapshot's App-ID content data once a call read it
	// through the entry, and contentKey its cache item.
	content    *appid.Data
	contentKey itemKey
}

type indexKey struct {
	scope config.Scope
	rb    resolve.Rulebase
}

// index is an index the entry has built, if any.
func (e *configEntry) index(k indexKey) (*index.Index, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	idx, ok := e.built[k]
	return idx, ok
}

// keep records a built index, so a later call takes no load slot for it.
func (e *configEntry) keep(k indexKey, idx *index.Index) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.built[k] = idx
}

// apps is the content data the entry holds and its key; nil before a call
// read it.
func (e *configEntry) apps() (*appid.Data, itemKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.content, e.contentKey
}

// keepApps records the content data of the entry's snapshot.
func (e *configEntry) keepApps(d *appid.Data, k itemKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.content, e.contentKey = d, k
}

// failedLoad is a configuration that did not load, cached under its
// snapshot's key.
type failedLoad struct{ err error }

// entryOf is a cached configuration value: the entry, or the load's error.
func entryOf(v any) (*configEntry, error) {
	if f, ok := v.(failedLoad); ok {
		return nil, f.err
	}
	return v.(*configEntry), nil
}

// config is a snapshot's configuration: cached, or loaded once for every
// caller that asks while it loads. The load runs apart from ctx; ctx bounds
// only the wait.
//
// A configuration that does not load keeps its error in the cache: a
// snapshot never changes, so it would fail the same way again. A file that
// cannot be opened or read is not kept: it may be readable later.
func (c *Cache) config(ctx context.Context, sn store.Snapshot) (*configEntry, error) {
	k := itemKey{kind: "config", member: sn.Device, id: sn.ID}
	if v, ok := c.get(k); ok {
		return entryOf(v)
	}
	v, err := c.loads.do(ctx, "config|"+sn.Device+"|"+sn.ID, func() (any, error) {
		// A load that finished just before this one began has filled it.
		if v, ok := c.get(k); ok {
			return v, nil
		}
		path := sn.Path(store.ConfigDoc)
		cfg, rep, err := c.load(path)
		if err != nil {
			if _, ioErr := errors.AsType[*fs.PathError](err); !ioErr {
				c.put(k, failedLoad{err}, failedBytes, false)
			}
			return nil, err
		}
		e := &configEntry{cfg: cfg, rep: rep, set: index.NewSet(cfg), built: map[indexKey]*index.Index{}}
		c.put(k, e, configBytes(fileBytes(path)), true)
		return e, nil
	})
	if err != nil {
		return nil, err
	}
	return entryOf(v)
}

// HA implements estate.OpSource: the snapshot's HA state, read once.
// Concurrent asks share one read. A failed read is not kept.
func (c *Cache) HA(sn store.Snapshot) (resolve.HAState, error) {
	v, err := c.op(itemKey{kind: "ha", member: sn.Device, id: sn.ID}, func() (any, int64, error) {
		ha, err := estate.DiskOps{}.HA(sn)
		return ha, opFactor * fileBytes(sn.Path(store.HADoc)), err
	})
	if err != nil {
		return resolve.HAState{}, err
	}
	return v.(resolve.HAState), nil
}

// Tables implements estate.OpSource: the snapshot's interface state and
// forwarding and routing tables, read once. A failed read is not kept.
func (c *Cache) Tables(sn store.Snapshot) (estate.OpTables, error) {
	v, err := c.op(itemKey{kind: "tables", member: sn.Device, id: sn.ID}, func() (any, int64, error) {
		t, err := estate.DiskOps{}.Tables(sn)
		return t, opFactor * fileBytes(sn.Path(store.InterfacesDoc), sn.Path(store.FIBDoc), sn.Path(store.RIBDoc)), err
	})
	if err != nil {
		return estate.OpTables{}, err
	}
	return v.(estate.OpTables), nil
}

// op is a cached operational value, or read concurrently once. The reads are
// small files: they take no load slot.
func (c *Cache) op(k itemKey, read func() (any, int64, error)) (any, error) {
	if v, ok := c.get(k); ok {
		return v, nil
	}
	v, err, _ := c.ops.Do(k.kind+"|"+k.member+"|"+k.id, func() (any, error) {
		if v, ok := c.get(k); ok {
			return v, nil
		}
		v, size, err := read()
		if err != nil {
			return nil, err
		}
		c.put(k, v, size, false)
		return v, nil
	})
	return v, err
}

// bind is the cache as one call reads it: its loads wait no longer than ctx.
func (c *Cache) bind(ctx context.Context) *callCache {
	return &callCache{c: c, ctx: ctx}
}

// callCache is a call's view of the cache, an estate.ConfigSource. It keeps
// the first failure that is the server's, not the snapshot's: a full load
// queue, a load that panicked, the call's end. The answer the query builds
// then turns it into a hole, so the handler answers with this error instead.
type callCache struct {
	c   *Cache
	ctx context.Context

	mu  sync.Mutex
	err error
}

// fail keeps err when it is the server's and the first.
func (v *callCache) fail(err error) error {
	var p *panicError
	if errors.Is(err, errLoadsBusy) || errors.As(err, &p) || v.ctx.Err() != nil {
		v.mu.Lock()
		if v.err == nil {
			v.err = err
		}
		v.mu.Unlock()
	}
	return err
}

// settle is the call's error: its first server failure, which the answer
// hides as a hole, or else err. A nil view keeps err.
func (v *callCache) settle(err error) error {
	if v == nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.err != nil {
		return v.err
	}
	return err
}

// Config implements estate.ConfigSource. A snapshot that names a content
// version reads its content data through the entry. A snapshot that holds an
// identity file reads it through the cache (Identity).
func (v *callCache) Config(sn store.Snapshot) (estate.Loaded, error) {
	e, err := v.c.config(v.ctx, sn)
	if err != nil {
		return estate.Loaded{}, v.fail(err)
	}
	l := estate.Loaded{Config: e.cfg, Report: e.rep, Indexes: callIndexes{v: v, e: e, member: sn.Device, id: sn.ID}}
	if path := sn.ContentPath(); path != "" {
		l.Apps = func() (*appid.Data, error) { return v.entryApps(e, path) }
	}
	if path := sn.IdentityPath(); path != "" {
		l.Identity = func() (*identity.Data, error) { return v.Identity(path) }
	}
	return l, nil
}

// entryApps is the content data of an entry's snapshot. The entry keeps the
// data it read. A later read gets the cache item, so the item counts as
// used. When the cache dropped the item, the entry puts its data back with
// its size and loads nothing: the data is in memory while the entry holds it
// (spec 2026-10-16 §7). When another call loaded the version again since,
// the entry takes that value, so one value stays.
func (v *callCache) entryApps(e *configEntry, path string) (*appid.Data, error) {
	if d, k := e.apps(); d != nil {
		d = v.c.adopt(k, d, contentBytes).(*appid.Data)
		e.keepApps(d, k)
		return d, nil
	}
	d, err := v.Apps(path)
	if err != nil {
		return nil, err
	}
	e.keepApps(d, contentKey(path))
	return d, nil
}

// Apps implements estate.AppSource: a content file's data, cached as one item
// per content version, or loaded once for every caller that asks while it
// loads. The load takes a load slot. A file that does not load is not kept:
// a later fetch can write it.
func (v *callCache) Apps(path string) (*appid.Data, error) {
	k := contentKey(path)
	if d, ok := v.c.get(k); ok {
		return d.(*appid.Data), nil
	}
	d, err := v.c.loads.do(v.ctx, "content|"+k.id, func() (any, error) {
		if d, ok := v.c.get(k); ok {
			return d, nil
		}
		d, err := v.c.loadApps(path)
		if err != nil {
			return nil, err
		}
		v.c.put(k, d, contentBytes, false)
		return d, nil
	})
	if err != nil {
		return nil, v.fail(err)
	}
	return d.(*appid.Data), nil
}

// Identity implements estate.IdentitySource: a snapshot's identity file,
// cached as one item of identityBytes, or loaded once for every caller that
// asks while it loads (spec 2026-10-17 §4.2, §8). The load takes a load slot.
// A file that does not load is not kept, as Apps keeps none: the next call
// reads it again, and the answer names the cause (gap.no-user-directory).
func (v *callCache) Identity(path string) (*identity.Data, error) {
	k := identityKey(path)
	if d, ok := v.c.get(k); ok {
		return d.(*identity.Data), nil
	}
	d, err := v.c.loads.do(v.ctx, "identity|"+k.member+"|"+k.id, func() (any, error) {
		if d, ok := v.c.get(k); ok {
			return d, nil
		}
		d, err := v.c.loadIdentity(path)
		if err != nil {
			return nil, err
		}
		v.c.put(k, d, identityBytes(d.Counts()), false)
		return d, nil
	})
	if err != nil {
		return nil, v.fail(err)
	}
	return d.(*identity.Data), nil
}

// callIndexes is a cached configuration's indexes as one call builds them:
// each build takes a load slot, once for every caller.
type callIndexes struct {
	v          *callCache
	e          *configEntry
	member, id string
}

// Index implements estate.Indexes.
func (x callIndexes) Index(sc config.Scope, rb resolve.Rulebase) (*index.Index, error) {
	k := indexKey{scope: sc, rb: rb}
	if idx, ok := x.e.index(k); ok {
		return idx, nil
	}
	// The key names the entry: an entry dropped and loaded again is another
	// configuration value, and an index serves only the one it was built from.
	key := fmt.Sprintf("index|%s|%s|%p|%s|%s", x.member, x.id, x.e, sc, rb)
	v, err := x.v.c.loads.do(x.v.ctx, key, func() (any, error) {
		idx, err := x.e.set.Index(sc, rb)
		if err != nil {
			return nil, err
		}
		x.e.keep(k, idx)
		return idx, nil
	})
	if err != nil {
		return nil, x.v.fail(err)
	}
	return v.(*index.Index), nil
}
