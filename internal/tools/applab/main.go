// Command applab compares proteus with a lab device, flow by flow (spec
// 2026-10-16 §9.1). It is a lab tool: run it through make app-lab, never in
// CI. docs/lab/app-id-lab.md says how to prepare the device.
//
// Usage:
//
//	APPLAB_KEY_HEADER=<file> go run ./internal/tools/applab -device fw02
//
// It reads the flow list and the variables file, fetches a fresh snapshot of
// the device into a temporary store, copies the snapshot for file mode, and
// per flow compares the device's test security-policy-match answer with
// proteus simulate policy --file. It removes both temporary directories at
// the end, also after a failure or an interrupt.
//
// The device answers op commands only: <show> and
// <test><security-policy-match>, and labkit.CheckOp refuses any other command
// before it is sent (AGENTS.md R2, plan C7). The API key comes from a header
// file, which holds one line "X-PAN-KEY: <key>". The tool never prints, logs
// or copies the key, and never asks the device for one.
//
// -render <file> prints a lab file with its placeholders filled from the
// variables file, for the XML API set calls of the lab run. Its output holds
// the real values: never save it in the repository.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/tools/labkit"
)

// options are the flags. Each flag can also come from the variable its help
// names.
type options struct {
	device, flows, vars, vsys, proteus, out, keyHeader, inventory, render string
}

// snapshotFiles are the files of the snapshot that file mode reads (plan
// D18): the configuration, the predefined services and the content file.
var snapshotFiles = []string{"config.xml", config.PredefinedFile, estate.AppsFile}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	var o options
	fs := flag.NewFlagSet("applab", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.device, "device", os.Getenv("DEVICE"), "the inventory name of the lab device ($DEVICE)")
	fs.StringVar(&o.flows, "flows", FlowsFile, "the flow list")
	fs.StringVar(&o.vars, "vars", VarsFile, "the variables file, untracked")
	fs.StringVar(&o.vsys, "vsys", "vsys1", "the vsys proteus checks")
	fs.StringVar(&o.proteus, "proteus", os.Getenv("APPLAB_PROTEUS"), "the proteus binary ($APPLAB_PROTEUS); built from ./cmd/proteus when empty")
	fs.StringVar(&o.out, "out", os.Getenv("APPLAB_OUT"), "where the answers go, outside the repository ($APPLAB_OUT); a new temporary directory when empty")
	fs.StringVar(&o.keyHeader, "key-header", os.Getenv("APPLAB_KEY_HEADER"), "the file with the line X-PAN-KEY: <key> ($APPLAB_KEY_HEADER)")
	fs.StringVar(&o.inventory, "config", "", "the proteus inventory (default $PROTEUS_CONFIG or proteus's default)")
	fs.StringVar(&o.render, "render", "", "print this lab file with its placeholders filled, and stop")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := lab(ctx, o, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "applab:", err)
		return 1
	}
	return 0
}

func lab(ctx context.Context, o options, stdout, stderr io.Writer) error {
	vars, err := labkit.ReadVarsFile(o.vars)
	if err != nil {
		return err
	}
	if o.render != "" {
		b, err := os.ReadFile(o.render)
		if err != nil {
			return err
		}
		s, err := fill(string(b), vars)
		if err != nil {
			return err
		}
		_, err = io.WriteString(stdout, s)
		return err
	}
	if o.device == "" {
		return errors.New("name the lab device: -device fw02, or DEVICE=fw02")
	}
	ff, err := os.Open(o.flows)
	if err != nil {
		return err
	}
	flows, err := ReadFlows(ff, vars)
	_ = ff.Close()
	if err != nil {
		return err
	}
	if o.keyHeader == "" {
		return errors.New("give the API key header file: -key-header <file>, or APPLAB_KEY_HEADER=<file>")
	}
	header, key, err := labkit.KeyHeader(o.keyHeader)
	if err != nil {
		return err
	}
	target, err := labkit.Lookup(o.inventory, o.device)
	if err != nil {
		return err
	}
	out, err := labkit.OutDir(o.out)
	if err != nil {
		return err
	}

	// Two temporary directories: the store of the fresh fetch, and the copy
	// file mode reads. Both go at the end, whatever happens.
	storeDir, err := os.MkdirTemp("", "applab-store-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(storeDir) }()
	copyDir, err := os.MkdirTemp("", "applab-copy-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(copyDir) }()

	bin := o.proteus
	if bin == "" {
		bin = filepath.Join(copyDir, "proteus")
		if err := labkit.Command(ctx, stderr, nil, "go", "build", "-o", bin, "./cmd/proteus"); err != nil {
			return fmt.Errorf("build proteus: %w", err)
		}
	}
	env := []string{"PROTEUS_STORE=" + storeDir, "PROTEUS_LOG_DIR=" + filepath.Join(out, "log")}
	if o.inventory != "" {
		env = append(env, "PROTEUS_CONFIG="+o.inventory)
	}
	fmt.Fprintf(stderr, "applab: fetching %s into a temporary store\n", o.device)
	if err := labkit.Command(ctx, stderr, env, bin, "fetch", o.device); err != nil {
		// Exit 3 is a partial fetch: what file mode needs may still be there,
		// and labkit.CopySnapshot checks it.
		if ee, ok := errors.AsType[*exec.ExitError](err); !ok || ee.ExitCode() != 3 {
			return fmt.Errorf("proteus fetch %s: %w", o.device, err)
		}
		fmt.Fprintf(stderr, "applab: the fetch of %s was partial (exit 3)\n", o.device)
	}
	version, err := labkit.CopySnapshot(storeDir, o.device, copyDir, snapshotFiles)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "device %s, content %s, %d flows, answers in %s\n", o.device, version, len(flows), out)

	dev := labkit.NewDevice(target.Host, target.InsecureTLS, target.Timeout, header, key)
	runProteus := func(ctx context.Context, args []string) ([]byte, []byte, int, error) {
		var so, se bytes.Buffer
		//nolint:gosec // G204: the binary and its arguments come from this tool's flags and flow list.
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env, cmd.Stdout, cmd.Stderr = append(os.Environ(), env...), &so, &se
		err := cmd.Run()
		if ee, ok := errors.AsType[*exec.ExitError](err); ok && ctx.Err() == nil {
			return so.Bytes(), se.Bytes(), ee.ExitCode(), nil
		}
		return so.Bytes(), se.Bytes(), 0, err
	}
	diffs, err := checkFlows(ctx, stdout, out, dev, runProteus, flows, filepath.Join(copyDir, "config.xml"), o.vsys)
	if err != nil {
		return err
	}
	if diffs > 0 {
		return fmt.Errorf("%d of %d flows differ", diffs, len(flows))
	}
	fmt.Fprintf(stdout, "all %d flows agree\n", len(flows))
	return nil
}
