package mcp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// busyError is a call the server refused at once: the queue was full, the
// call waited too long for a slot, or the server stops (spec §4.7).
type busyError struct{ text string }

func (e *busyError) Error() string { return e.text }

var (
	errQueueFull = &busyError{"the server is busy: too many calls wait; ask again later"}
	errStopping  = &busyError{"the server is stopping; ask again later"}
)

// limiter bounds the tool calls (spec §4.7): at most cap(slots) run at once,
// at most maxQueue wait for a slot, and none waits longer than maxWait. A call
// holds its slot until its work returns, also after its caller got the
// timeout, so the slots bound the real work.
type limiter struct {
	slots    chan struct{}
	maxQueue int
	maxWait  time.Duration
	timeout  time.Duration

	mu      sync.Mutex
	waiting int
	calls   int    // calls that have not returned their answer yet
	arrived uint64 // calls that arrived, ever

	stopping chan struct{}
	stopOnce sync.Once
}

func newLimiter(maxConcurrent, maxQueue int, maxWait, timeout time.Duration) *limiter {
	return &limiter{
		slots: make(chan struct{}, maxConcurrent), maxQueue: maxQueue, maxWait: maxWait, timeout: timeout,
		stopping: make(chan struct{}),
	}
}

// enter takes a slot for a call, or says why the call is busy. The caller
// gives the slot back with leave once its work returned. Slots are not
// handed out in order: a call that arrives as a slot frees can take it
// before one that waits, so a waiting call can wait up to max_wait.
func (l *limiter) enter(ctx context.Context) error {
	select {
	case <-l.stopping:
		return errStopping
	default:
	}
	l.mu.Lock()
	select {
	case l.slots <- struct{}{}:
		l.mu.Unlock()
		return nil
	default:
	}
	if l.waiting >= l.maxQueue {
		l.mu.Unlock()
		return errQueueFull
	}
	l.waiting++
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.waiting--
		l.mu.Unlock()
	}()
	t := time.NewTimer(l.maxWait)
	defer t.Stop()
	select {
	case l.slots <- struct{}{}:
		return nil
	case <-t.C:
		return &busyError{fmt.Sprintf("the server is busy: the call waited %s for a free slot; ask again later", l.maxWait)}
	case <-l.stopping:
		return errStopping
	case <-ctx.Done():
		return ctx.Err()
	}
}

// leave gives a slot back.
func (l *limiter) leave() { <-l.slots }

// begin and end count a call from its arrival to its answer, also one that
// is refused or past its time.
func (l *limiter) begin() {
	l.mu.Lock()
	l.calls++
	l.arrived++
	l.mu.Unlock()
}

// begun is how many calls arrived so far.
func (l *limiter) begun() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.arrived
}

func (l *limiter) end() {
	l.mu.Lock()
	l.calls--
	l.mu.Unlock()
}

// answering is how many calls have not returned their answer yet.
func (l *limiter) answering() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// stop refuses every new or waiting call, then waits for the running calls'
// work to return, at most the call timeout. It reports whether all returned.
func (l *limiter) stop() bool {
	ctx, cancel := context.WithTimeout(context.Background(), l.timeout)
	defer cancel()
	return l.stopBy(ctx)
}

// stopBy is stop, waiting until ctx ends at most.
func (l *limiter) stopBy(ctx context.Context) bool {
	l.stopOnce.Do(func() { close(l.stopping) })
	// Every slot taken here is one no call holds: all of them, and the work
	// has returned.
	for range cap(l.slots) {
		select {
		case l.slots <- struct{}{}:
		case <-ctx.Done():
			return false
		}
	}
	// A call whose work returned may not have returned its answer yet.
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for l.answering() > 0 {
		select {
		case <-tick.C:
		case <-ctx.Done():
			return false
		}
	}
	return true
}

// isBusy reports whether err is a call the limiter refused.
func isBusy(err error) bool {
	_, ok := errors.AsType[*busyError](err)
	return ok
}
