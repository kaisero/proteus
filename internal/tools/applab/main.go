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
// <test><security-policy-match>, and checkOp refuses any other command before
// it is sent (AGENTS.md R2, plan C7). The API key comes from a header file,
// which holds one line "X-PAN-KEY: <key>". The tool never prints, logs or
// copies the key, and never asks the device for one.
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

	"github.com/kaisero/proteus/internal/inventory"
)

// options are the flags. Each flag can also come from the variable its help
// names.
type options struct {
	device, flows, vars, vsys, proteus, out, keyHeader, inventory, render string
}

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
	vars, err := readVarsFile(o.vars)
	if err != nil {
		return err
	}
	if o.render != "" {
		b, err := os.ReadFile(o.render)
		if err != nil {
			return err
		}
		s, err := Fill(string(b), vars)
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
	header, key, err := keyHeader(o.keyHeader)
	if err != nil {
		return err
	}
	target, err := lookup(o.inventory, o.device)
	if err != nil {
		return err
	}
	out, err := outDir(o.out)
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
		if err := command(ctx, stderr, nil, "go", "build", "-o", bin, "./cmd/proteus"); err != nil {
			return fmt.Errorf("build proteus: %w", err)
		}
	}
	env := []string{"PROTEUS_STORE=" + storeDir, "PROTEUS_LOG_DIR=" + filepath.Join(out, "log")}
	if o.inventory != "" {
		env = append(env, "PROTEUS_CONFIG="+o.inventory)
	}
	fmt.Fprintf(stderr, "applab: fetching %s into a temporary store\n", o.device)
	if err := command(ctx, stderr, env, bin, "fetch", o.device); err != nil {
		// Exit 3 is a partial fetch: what file mode needs may still be there,
		// and copySnapshot checks it.
		if ee, ok := errors.AsType[*exec.ExitError](err); !ok || ee.ExitCode() != 3 {
			return fmt.Errorf("proteus fetch %s: %w", o.device, err)
		}
		fmt.Fprintf(stderr, "applab: the fetch of %s was partial (exit 3)\n", o.device)
	}
	version, err := copySnapshot(storeDir, o.device, copyDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "device %s, content %s, %d flows, answers in %s\n", o.device, version, len(flows), out)

	dev := newDevice(target.Host, target.InsecureTLS, target.Timeout, header, key)
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

// readVarsFile reads the variables file. A missing file is no error for a
// flow list without placeholders, so it reads as empty.
func readVarsFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ReadVars(f)
}

// keyHeader reads the key header file. Its name is a path, not the key.
func keyHeader(path string) (string, string, error) {
	if path == "" {
		return "", "", errors.New("give the API key header file: -key-header <file>, or APPLAB_KEY_HEADER=<file>")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }()
	name, value, err := ReadKeyHeader(f)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", path, err)
	}
	return name, value, nil
}

// lookup finds the device in the proteus inventory: its host, its TLS
// setting and its time-out. The password stays with proteus fetch.
func lookup(path, name string) (inventory.Target, error) {
	if path == "" {
		p, err := inventory.DefaultPath(os.Getenv)
		if err != nil {
			return inventory.Target{}, err
		}
		path = p
	}
	inv, err := inventory.Load(path)
	if err != nil {
		return inventory.Target{}, err
	}
	t, err := inv.Resolve(name, os.Getenv)
	t.Password = ""
	return t, err
}

// outDir returns the output directory: the one given, or a new temporary
// one. It refuses a directory in the repository, so no answer of the lab
// device lands in git.
func outDir(dir string) (string, error) {
	if dir == "" {
		return os.MkdirTemp("", "applab-out-")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if wd, err := os.Getwd(); err == nil {
		if root, ok := repoRoot(wd); ok && insideRepo(abs, root) {
			return "", fmt.Errorf("-out %s is inside the repository %s; give a directory outside it", abs, root)
		}
	}
	return abs, os.MkdirAll(abs, 0o700)
}

// repoRoot is the nearest directory at or above dir that holds go.mod.
func repoRoot(dir string) (string, bool) {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// command runs one command with extra environment, its output to w.
func command(ctx context.Context, w io.Writer, env []string, name string, args ...string) error {
	//nolint:gosec // G204: the command and its arguments come from this tool.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env, cmd.Stdout, cmd.Stderr = append(os.Environ(), env...), w, w
	return cmd.Run()
}
