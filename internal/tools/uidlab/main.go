// Command uidlab compares proteus's User-ID answers with a lab device, flow
// by flow (spec 2026-10-17 §10.3). It is a lab tool: run it through make
// uid-lab, never in CI.
//
// Usage:
//
//	UIDLAB_KEY_HEADER=<file> go run ./internal/tools/uidlab -device fw01
//
// It reads the flow list and the variables file, fetches a fresh snapshot of
// the device into a temporary store, and stops when the snapshot has no
// identity data, or when a part of it is missing or the mapping table is
// partial (PD19): the error names the part. It copies the configuration,
// the predefined services and the identity file for file mode. It waits
// -settle, 300 s by default: the test command can answer "no rule" for a
// minute after a commit and keep its earlier answer for a few minutes after
// a User-ID message, as observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17
// M10, M18). Then it runs four checks: a policy flow against simulate
// policy, a user against lookup, an address against search and a group
// against lookup. A policy flow that differs, and whose outcome the device
// answer decides, is tried twice more, -retry-wait apart, and counts as a
// difference only when all three tries differ (M18). Each try keeps its
// device answers in -out. A user check or a resolved flow that names a
// member of the XML API group of the -login file stops the run (U18). It
// removes both temporary directories at the end, also after a failure or an
// interrupt; the run log of proteus is in one of them, because it names the
// host (§10.4).
//
// The device answers op commands only: <show> and
// <test><security-policy-match>, and labkit.CheckOp refuses any other command
// before it is sent (AGENTS.md R2, plan C7). The tool never configures,
// commits or sends a User-ID message: the lab steps apply the set, delete,
// login and logout files. The API key comes from a header file, which holds
// one line "X-PAN-KEY: <key>". The tool never prints, logs or copies the
// key, and never asks the device for one.
//
// The answers go to -out, outside the repository, or to a new temporary
// directory whose name starts with the name of the binary: uidlab-out-
// under go run (labkit.OutDir).
//
// -render <file> prints a lab file with its placeholders filled from the
// variables file, for the lab steps, and stops. Its output holds the real
// values: never save it in the repository.
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
	"time"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/identity"
	"github.com/kaisero/proteus/internal/store"
	"github.com/kaisero/proteus/internal/tools/labkit"
)

// options are the flags. Each flag can also come from the variable its help
// names.
type options struct {
	device, flows, vars, login, vsys, proteus, out, keyHeader, inventory, render string
	settle, retry                                                                time.Duration
}

// snapshotFiles are the files of the snapshot that file mode reads (plan
// D18, spec 2026-10-17 §7): the configuration, the predefined services and
// the identity file.
var snapshotFiles = []string{"config.xml", config.PredefinedFile, identity.FileName}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	var o options
	fs := flag.NewFlagSet("uidlab", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.device, "device", os.Getenv("DEVICE"), "the inventory name of the lab device ($DEVICE)")
	fs.StringVar(&o.flows, "flows", FlowsFile, "the flow list")
	fs.StringVar(&o.vars, "vars", VarsFile, "the variables file, untracked")
	fs.StringVar(&o.login, "login", LoginFile, "the User-ID messages of the lab, for the XML API group members (U18)")
	fs.StringVar(&o.vsys, "vsys", "vsys1", "the vsys proteus checks")
	fs.StringVar(&o.proteus, "proteus", os.Getenv("UIDLAB_PROTEUS"), "the proteus binary ($UIDLAB_PROTEUS); built from ./cmd/proteus when empty")
	fs.StringVar(&o.out, "out", os.Getenv("UIDLAB_OUT"), "where the answers go, outside the repository ($UIDLAB_OUT); a new temporary directory when empty")
	fs.StringVar(&o.keyHeader, "key-header", os.Getenv("UIDLAB_KEY_HEADER"), "the file with the line X-PAN-KEY: <key> ($UIDLAB_KEY_HEADER)")
	fs.StringVar(&o.inventory, "config", "", "the proteus inventory (default $PROTEUS_CONFIG or proteus's default)")
	fs.StringVar(&o.render, "render", "", "print this lab file with its placeholders filled, and stop")
	fs.DurationVar(&o.settle, "settle", 300*time.Second, "the wait before the first flow, after the last commit and User-ID message (M10, M18)")
	fs.DurationVar(&o.retry, "retry-wait", 60*time.Second, "the wait between two tries of a policy flow that differs (M18)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := lab(ctx, o, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "uidlab:", err)
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
			return inVars(err, o.vars)
		}
		_, err = io.WriteString(stdout, s)
		return err
	}
	if o.device == "" {
		return errors.New("name the lab device: -device fw01, or DEVICE=fw01")
	}
	ff, err := os.Open(o.flows)
	if err != nil {
		return err
	}
	flows, err := ReadFlows(ff, vars)
	_ = ff.Close()
	if err != nil {
		return inVars(err, o.vars)
	}
	login, err := os.ReadFile(o.login)
	if err != nil {
		return err
	}
	if err := refuseXMLAPIMembers(flows, login, vars); err != nil {
		return inVars(err, o.vars)
	}
	if o.keyHeader == "" {
		return errors.New("give the API key header file: -key-header <file>, or UIDLAB_KEY_HEADER=<file>")
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
	// file mode reads, with the run log of proteus. Both go at the end,
	// whatever happens.
	storeDir, err := os.MkdirTemp("", "uidlab-store-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(storeDir) }()
	copyDir, err := os.MkdirTemp("", "uidlab-copy-")
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
	env := []string{"PROTEUS_STORE=" + storeDir, "PROTEUS_LOG_DIR=" + filepath.Join(copyDir, "log")}
	if o.inventory != "" {
		env = append(env, "PROTEUS_CONFIG="+o.inventory)
	}
	fmt.Fprintf(stderr, "uidlab: fetching %s into a temporary store\n", o.device)
	if err := labkit.Command(ctx, stderr, env, bin, "fetch", o.device); err != nil {
		// Exit 3 is a partial fetch: the identity check below says whether
		// what the run needs arrived.
		if ee, ok := errors.AsType[*exec.ExitError](err); !ok || ee.ExitCode() != 3 {
			return fmt.Errorf("proteus fetch %s: %w", o.device, err)
		}
		fmt.Fprintf(stderr, "uidlab: the fetch of %s was partial (exit 3)\n", o.device)
	}
	if err := wholeIdentity(storeDir, o.device); err != nil {
		return err
	}
	if _, err := labkit.CopySnapshot(storeDir, o.device, copyDir, snapshotFiles); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "device %s, %d flows, answers in %s\n", o.device, len(flows), out)
	if o.settle > 0 {
		fmt.Fprintf(stderr, "uidlab: waiting %s for the device to settle (M10, M18)\n", o.settle)
		if err := wait(ctx, o.settle); err != nil {
			return err
		}
	}

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
	diffs, err := checkFlows(ctx, stdout, out, dev, runProteus, flows, filepath.Join(copyDir, "config.xml"), o.vsys, o.retry)
	if err != nil {
		return err
	}
	if diffs > 0 {
		return fmt.Errorf("%d of %d flows differ", diffs, len(flows))
	}
	fmt.Fprintf(stdout, "all %d flows agree\n", len(flows))
	return nil
}

// wholeIdentity stops a run whose snapshot has no identity data, or whose
// identity data misses a part or holds a partial mapping table: an answer
// from such data can be in doubt where the device decides (PD19, SG13).
func wholeIdentity(storeDir, device string) error {
	sn, err := store.At(storeDir).Latest(device)
	if err != nil {
		return err
	}
	path := sn.IdentityPath()
	if path == "" {
		return fmt.Errorf("the snapshot of %s has no identity data: check the inventory key identity and the fetch log", device)
	}
	d, err := identity.Load(path)
	if err != nil {
		return err
	}
	missing := d.PartsMissing()
	if d.File().MappingsPartial {
		missing = append(missing, identity.PartMappings+" (partial)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("the identity data of %s lacks %v: fetch again when the device answers every part", device, missing)
	}
	return nil
}
