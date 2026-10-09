package mcp

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/store"
)

// The size estimates of the cache (spec §12 C18, measured in the plan's
// survey): a snapshot's configuration with its edge list and three rulebase
// indexes per vsys retains about 13 times the configuration file's bytes, and
// the schema digest of each PAN-OS version about 9 MB once per process.
const (
	configFactor = 13
	digestBytes  = 9 << 20
	// opFactor sizes a snapshot's operational tables by their files' bytes.
	// It is an estimate, not a measurement: the parsed tables keep less text
	// than the XML they come from.
	opFactor = 2
)

// itemKey names a cached item: a kind and a snapshot.
type itemKey struct {
	kind   string // "config", "ha" or "tables"
	member string
	id     string
}

// item is one cached value and its estimated size.
type item struct {
	key  itemKey
	size int64
	val  any
}

// Cache keeps what the calls read of the store, per (member, snapshot id):
// each snapshot's configuration with its indexes, and its operational
// tables (spec §4.8). Which snapshot latest or at means is read from the store
// on each call; a snapshot's content never changes, so what the cache holds
// for it stays true. Notes are never cached: each call builds them from the
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

	mu      sync.Mutex
	max     int64 // bytes
	size    int64 // the items' estimated bytes
	fixed   int64 // the schema digests' estimated bytes, never freed
	digests map[string]bool
	order   *list.List // of *item, the most recently used first
	items   map[itemKey]*list.Element
}

// newCache is a cache of at most maxBytes, whose loads run at most maxLoads at
// once with at most maxQueue waiting.
func newCache(maxBytes int64, maxLoads, maxQueue int, strict bool) *Cache {
	return &Cache{
		loads: newLoader(maxLoads, maxQueue, strict), load: config.Load,
		max: maxBytes, digests: map[string]bool{}, order: list.New(), items: map[itemKey]*list.Element{},
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
// items while the cache is past its limit. digest, when not empty, is the
// schema digest version the value was read with; each version counts once.
func (c *Cache) put(k itemKey, v any, size int64, digest string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if digest != "" && !c.digests[digest] {
		c.digests[digest] = true
		c.fixed += digestBytes
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

// config is a snapshot's configuration: cached, or loaded once for every
// caller that asks while it loads. The load runs apart from ctx; ctx bounds
// only the wait.
func (c *Cache) config(ctx context.Context, sn store.Snapshot) (*configEntry, error) {
	k := itemKey{kind: "config", member: sn.Device, id: sn.ID}
	if v, ok := c.get(k); ok {
		return v.(*configEntry), nil
	}
	v, err := c.loads.do(ctx, "config|"+sn.Device+"|"+sn.ID, func() (any, error) {
		// A load that finished just before this one began has filled it.
		if v, ok := c.get(k); ok {
			return v, nil
		}
		path := sn.Path(store.ConfigDoc)
		cfg, rep, err := c.load(path)
		if err != nil {
			return nil, err
		}
		e := &configEntry{cfg: cfg, rep: rep, set: index.NewSet(cfg), built: map[indexKey]*index.Index{}}
		c.put(k, e, configFactor*fileBytes(path), cfg.DigestVersion())
		return e, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*configEntry), nil
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
		c.put(k, v, size, "")
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

// Config implements estate.ConfigSource.
func (v *callCache) Config(sn store.Snapshot) (estate.Loaded, error) {
	e, err := v.c.config(v.ctx, sn)
	if err != nil {
		return estate.Loaded{}, v.fail(err)
	}
	return estate.Loaded{Config: e.cfg, Report: e.rep, Indexes: callIndexes{v: v, e: e, member: sn.Device, id: sn.ID}}, nil
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
