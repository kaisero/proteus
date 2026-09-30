package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestASignalSetsTheExitCode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		sig  os.Signal
		want int
	}{{os.Interrupt, 130}, {syscall.SIGTERM, 143}} {
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(signalCause{tc.sig})
		a := newApp(&bytes.Buffer{}, &bytes.Buffer{}, func(string) string { return "" }, time.Now)
		if got, _ := a.exitCode(ctx, errors.New("context canceled")); got != tc.want {
			t.Errorf("%v: exit %d, want %d", tc.sig, got, tc.want)
		}
		if got, _ := a.exitCode(ctx, nil); got != exitOK {
			t.Errorf("%v: a command that finished exits 0, got %d", tc.sig, got)
		}
	}
}

// A first SIGINT cancels the context with the signal as the cause, and does not
// kill the process: WithSignals catches it.
func TestWithSignalsCancelsOnSIGINT(t *testing.T) {
	t.Parallel()
	ctx, stop := WithSignals(context.Background())
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the context was not canceled")
	}
	c, ok := errors.AsType[signalCause](context.Cause(ctx))
	if !ok {
		t.Fatalf("context.Cause(ctx) = %v, want a signalCause", context.Cause(ctx))
	}
	if c.code() != 130 {
		t.Errorf("code() = %d, want 130", c.code())
	}
	if c.Error() != "interrupted" {
		t.Errorf("Error() = %q, want %q", c.Error(), "interrupted")
	}
}

// The second signal kills the process: WithSignals restored the default action.
func TestASecondSignalKills(t *testing.T) {
	if os.Getenv("PROTEUS_SIGNAL_CHILD") == "1" {
		ctx, stop := WithSignals(context.Background())
		defer stop()
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		<-ctx.Done()
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		time.Sleep(2 * time.Second)
		os.Exit(0) //nolint:gocritic // not reached when the second signal kills; cleanup does not matter
	}
	t.Parallel()
	cmd := exec.Command(os.Args[0], "-test.run=^TestASecondSignalKills$")
	cmd.Env = append(os.Environ(), "PROTEUS_SIGNAL_CHILD=1")
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGINT {
		t.Errorf("the second SIGINT must kill the process, got %v", err)
	}
}
