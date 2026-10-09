package mcp

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"

	"golang.org/x/sync/singleflight"
)

// errLoadsBusy is a load refused because max_queue loads already wait for a
// slot (spec §4.7).
var errLoadsBusy = &busyError{"the server is busy: too many snapshot loads wait; ask again later"}

// errDropped is a queued load no caller waited for any more. It never reaches
// a caller that still waits: that caller starts the load again.
var errDropped = errors.New("mcp: load dropped: no caller waits for it")

// panicError is a load that panicked: its value and stack, for the run log.
type panicError struct {
	value any
	stack []byte
}

func (e *panicError) Error() string { return fmt.Sprintf("a load failed: %v", e.value) }

// loader runs the configuration loads and index builds (spec §4.7). Concurrent
// asks for one key share one load. At most cap(slots) loads run at once, and
// at most maxQueue wait for a slot; one more is refused. A load runs in its own
// goroutine, apart from its callers: a caller that stops waiting leaves it to
// finish and fill the cache. A load that still waits for a slot when its last
// caller left is dropped before it starts. Each load recovers its own panic.
type loader struct {
	slots    chan struct{}
	maxQueue int
	// strict panics on in a load, as a test binary does: there a bug fails the
	// test instead of hiding as call.internal.
	strict bool

	flight singleflight.Group

	mu      sync.Mutex
	queued  int                      // loads that wait for a slot
	waiters map[string]int           // callers that wait, per key
	gone    map[string]chan struct{} // closed when a queued load's last caller leaves
}

func newLoader(maxLoads, maxQueue int, strict bool) *loader {
	return &loader{
		slots: make(chan struct{}, maxLoads), maxQueue: maxQueue, strict: strict,
		waiters: map[string]int{}, gone: map[string]chan struct{}{},
	}
}

// do waits for key's load, starting it when none runs, until ctx ends.
func (l *loader) do(ctx context.Context, key string, fn func() (any, error)) (any, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l.mu.Lock()
		l.waiters[key]++
		l.mu.Unlock()
		ch := l.flight.DoChan(key, func() (any, error) { return l.run(key, fn) })
		select {
		case r := <-ch:
			l.leave(key)
			if errors.Is(r.Err, errDropped) {
				// The load this call joined lost its callers just before:
				// start it again.
				continue
			}
			return r.Val, r.Err
		case <-ctx.Done():
			l.leave(key)
			return nil, ctx.Err()
		}
	}
}

// leave counts a caller of key out. The last one tells a queued load.
func (l *loader) leave(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.waiters[key]--; l.waiters[key] > 0 {
		return
	}
	delete(l.waiters, key)
	if g, ok := l.gone[key]; ok {
		close(g)
		delete(l.gone, key)
	}
}

// run is key's load: it takes a slot, or waits for one in the queue, then
// runs fn with a recover.
func (l *loader) run(key string, fn func() (any, error)) (v any, err error) {
	select {
	case l.slots <- struct{}{}:
	default:
		if err := l.wait(key); err != nil {
			return nil, err
		}
	}
	defer func() { <-l.slots }()
	defer func() {
		if p := recover(); p != nil {
			if l.strict {
				panic(p)
			}
			v, err = nil, &panicError{value: p, stack: debug.Stack()}
		}
	}()
	return fn()
}

// wait queues key's load until a slot is free. It refuses the load when the
// queue is full and drops it when its last caller leaves first.
func (l *loader) wait(key string) error {
	l.mu.Lock()
	if l.waiters[key] == 0 {
		l.mu.Unlock()
		return errDropped
	}
	if l.queued >= l.maxQueue {
		l.mu.Unlock()
		return errLoadsBusy
	}
	l.queued++
	gone := make(chan struct{})
	l.gone[key] = gone
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.queued--
		if l.gone[key] == gone {
			delete(l.gone, key)
		}
		l.mu.Unlock()
	}()
	for {
		select {
		case l.slots <- struct{}{}:
			return nil
		case <-gone:
			l.mu.Lock()
			if l.waiters[key] == 0 {
				l.mu.Unlock()
				return errDropped
			}
			// A caller came back between the close and now.
			gone = make(chan struct{})
			l.gone[key] = gone
			l.mu.Unlock()
		}
	}
}
