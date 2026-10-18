package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// WithSignals returns a context that SIGINT and SIGTERM cancel, with the signal as
// the cause. After the first signal it restores the default action, so a second
// signal kills the process at once. stop releases the signal handler.
func WithSignals(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case s := <-sigs:
			signal.Stop(sigs)
			cancel(signalCause{s})
		case <-ctx.Done():
		}
	}()
	return ctx, func() { signal.Stop(sigs); cancel(nil) }
}

// signalCause is why a context ended: a signal. signal.NotifyContext also records a
// cause, but its type is unexported, so the exit code could not be read from it.
type signalCause struct{ sig os.Signal }

func (s signalCause) Error() string { return "interrupted" }

// code is the shell convention: 128 plus the signal number.
func (s signalCause) code() int {
	if s.sig == syscall.SIGTERM {
		return 143
	}
	return 130
}
