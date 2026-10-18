package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/fetch"
	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/store"
	"github.com/okaiser/proteus/internal/task"
)

// fetchConcurrency bounds how many devices are fetched at once. It is a constant
// because spec §15 C14 adds no settings beyond its list; it becomes one when someone
// needs it.
const fetchConcurrency = 8

// fetchOptions are fetch's flags and arguments.
type fetchOptions struct {
	names  []string
	labels []string
	all    bool
	why    bool
}

func (a *app) fetchCmd() *cobra.Command {
	var o fetchOptions
	cmd := &cobra.Command{
		Use:   "fetch [device...]",
		Short: "Fetch devices into the store",
		Long: "Fetch logs in to each device, reads its configuration and operational state, and\n" +
			"stores them as a snapshot. Name devices, select them with --label, or pass --all.\n\n" +
			"Stages per device: resolve, login, ha, documents, template, applications, store",
		ValidArgsFunction: a.completeDevices,
		RunE: func(c *cobra.Command, names []string) error {
			o.names = names
			return a.emitRun(a.runFetch(c.Context(), o))
		},
	}
	cmd.Flags().BoolVar(&o.all, "all", false, "fetch every device in the inventory")
	cmd.Flags().StringArrayVar(&o.labels, "label", nil, "fetch devices with this key=value label (repeatable; all must hold)")
	bindWhy(cmd, &o.why)
	return cmd
}

func (a *app) runFetch(ctx context.Context, o fetchOptions) (answer, error) {
	kinds := 0
	for _, given := range []bool{len(o.names) > 0, len(o.labels) > 0, o.all} {
		if given {
			kinds++
		}
	}
	if kinds != 1 {
		return nil, usageErr("name devices, select them with --label, or pass --all; exactly one of those")
	}
	s, err := a.settings(true)
	if err != nil {
		return nil, err
	}
	names, err := s.inv.Select(o.names, o.labels)
	if err != nil {
		return nil, usageErr("%w", err)
	}
	if len(o.names) > 0 {
		// Select gives the inventory's order. Named devices are fetched and reported
		// in the order named, and each once: two fetches of one device in the same
		// second would write the same snapshot.
		names = unique(o.names)
	}
	if len(names) == 0 {
		return nil, usageErr("the selection matches no device")
	}
	st, err := a.openStore(s.storeRoot)
	if err != nil {
		return nil, err
	}
	ans := fetchAnswer{o: o, results: a.fetcher(s.inv, st).each(ctx, names)}
	// The export follows every run, a failed one too, so the server's device
	// list follows the inventory (spec 2026-10-09 §5).
	if s.inv.Defaults.ExportInventory {
		if ans.exportErr = inventory.WriteExport(s.storeRoot, s.inv); ans.exportErr != nil {
			a.log.Errorf(runlog.TagRun, "%v", ans.exportErr)
		} else {
			a.log.Infof(runlog.TagRun, "inventory exported to %s", inventory.ExportPath(s.storeRoot))
		}
	}
	return ans, nil
}

// unique returns names without repeats, in the order of their first appearance.
func unique(names []string) []string {
	seen := map[string]bool{}
	return slices.DeleteFunc(slices.Clone(names), func(n string) bool {
		if seen[n] {
			return true
		}
		seen[n] = true
		return false
	})
}

// fetcher fetches devices into one store.
type fetcher struct {
	inv    *inventory.Inventory
	st     *store.Store
	getenv func(string) string
	log    *runlog.Logger
	// peerHost maps an HA peer's reported management address to a host; nil uses
	// the address.
	peerHost func(mgmtIP string) string
	onStep   func(kind string, r task.Record) // progress; nil for none
}

func (a *app) fetcher(inv *inventory.Inventory, st *store.Store) fetcher {
	return fetcher{inv: inv, st: st, getenv: a.getenv, log: a.log, peerHost: a.peerHost, onStep: a.progress()}
}

// deviceFetch is one device's fetch as the command line runs it: the fetch package's
// state plus the steps around it.
type deviceFetch struct {
	fetch.State
	name     string
	resolved bool
	snap     store.Snapshot
	// contentFailed says that the App-ID content file could not be written.
	contentFailed bool
}

// lift runs a fetch package step on a deviceFetch's embedded state.
func lift(st task.Step[fetch.State]) task.Step[deviceFetch] {
	return task.Step[deviceFetch]{
		Name: st.Name, Slug: st.Slug,
		Do: func(ctx context.Context, d *deviceFetch) (task.Result, error) { return st.Do(ctx, &d.State) },
	}
}

func (f fetcher) steps() []task.Step[deviceFetch] {
	out := []task.Step[deviceFetch]{{Name: "resolve the inventory entry", Slug: "resolve", Do: f.resolve}}
	for _, st := range fetch.Steps() {
		out = append(out, lift(st))
	}
	return append(out, task.Step[deviceFetch]{Name: "store the snapshot", Slug: "store", Do: f.store})
}

func (f fetcher) resolve(_ context.Context, d *deviceFetch) (task.Result, error) {
	t, err := f.inv.Resolve(d.name, f.getenv)
	if err != nil {
		return task.Result{}, err
	}
	d.State = fetch.NewState(t, fetch.Documents, fetch.ActiveOptions{PeerHost: f.peerHost}, f.log)
	d.HaveApps = f.st.HaveContent
	d.resolved = true
	verification := "on"
	if t.InsecureTLS {
		verification = "off"
	}
	f.log.Infof(runlog.TagAPI, "%s: fetching %s, TLS verification %s", d.name, t.Host, verification)
	return task.Result{Detail: t.Host + ", TLS verification " + verification}, nil
}

func (f fetcher) store(_ context.Context, d *deviceFetch) (task.Result, error) {
	appVersion, appNote := f.storeContent(d)
	res := d.Result
	meta := store.Meta{
		Device: d.Target.Name, Host: d.Target.Host,
		Hostname: res.System.Hostname, Model: res.System.Model,
		Serial: res.System.Serial, SWVersion: res.System.SWVersion,
		AppVersion:  appVersion,
		FetchedFrom: res.FetchedFrom, Notes: simulate.Reasons(res.Notes).Texts(),
		ConfigSource: res.ConfigSource,
	}
	for _, o := range res.Outcomes {
		dm := store.DocumentMeta{Name: o.Name}
		if o.Err != nil {
			dm.Error = o.Err.Error()
		}
		meta.Documents = append(meta.Documents, dm)
	}
	sn, err := f.st.Write(meta, res.Docs, d.Target.SnapshotKeep)
	if err != nil {
		return task.Result{}, err
	}
	d.snap = sn
	f.log.Infof(runlog.TagSnap, "%s: stored %s", d.name, sn.ID)
	r := task.Result{Detail: sn.Device + "@" + sn.ID}
	if _, ok := res.Docs[store.ConfigDoc]; !ok {
		r.Status, r.Detail = task.Partial, r.Detail+"; no configuration, so latest did not move"
	}
	if appNote != nil {
		r.Status, r.Detail = task.Partial, r.Detail+"; the application data was not stored"
		r.Notes = []reason.Reason{*appNote}
	}
	return r, nil
}

// storeContent writes the App-ID content file of a miss before the snapshot,
// and returns the content version the snapshot names: the version of a hit or
// of a file written now, else "" (spec 2026-10-16 §3.1). A file that
// cannot be written adds the note with the cause and makes the run incomplete,
// as a failed inventory export does.
func (f fetcher) storeContent(d *deviceFetch) (string, *reason.Reason) {
	a := d.Result.Apps
	if a == nil {
		return "", nil
	}
	if a.File != nil {
		if err := f.st.WriteContent(a.Version, a.File); err != nil {
			f.log.Errorf(runlog.TagSnap, "%s: %v", d.name, err)
			n := reason.New("note.fetch-applications-missing",
				"the application data was not stored, so rules that name an application stay in doubt: "+err.Error())
			d.Result.Notes = append(d.Result.Notes, n)
			d.contentFailed = true
			return "", &n
		}
	}
	return a.Version, nil
}

// each fetches the devices, up to fetchConcurrency at once, and returns one result per
// name in the order named. Once ctx is done it starts no more devices; those not
// started are in the results with an error, so none drops silently.
func (f fetcher) each(ctx context.Context, names []string) []fetchResult {
	results := make([]fetchResult, len(names))
	for i, n := range names {
		results[i] = fetchResult{Device: n, Documents: []documentJSON{}, Stages: []stageJSON{}, Error: n + ": not started: interrupted"}
	}
	sem := make(chan struct{}, fetchConcurrency)
	var wg sync.WaitGroup
	for i, name := range names {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Go(func() {
			defer func() { <-sem }()
			results[i] = f.one(ctx, name)
		})
	}
	wg.Wait()
	// One prune per run, after every device: a prune reads every snapshot's
	// meta.json, so a prune per device would cost the square of the devices
	// (spec 2026-10-16 §3.4). A failed prune leaves files behind and fails
	// nothing.
	if err := f.st.PruneContent(); err != nil {
		f.log.Warnf(runlog.TagSnap, "pruning the content files: %v", err)
	} else {
		f.log.Debugf(runlog.TagSnap, "pruned the content files")
	}
	return results
}

// one fetches one device as a staged task whose kind is the device's name, so every
// error it returns starts with the name, once.
func (f fetcher) one(ctx context.Context, name string) fetchResult {
	d := &deviceFetch{name: name}
	recs, err := task.Run(ctx, name, d, f.steps(), task.Options{Log: f.log, OnStep: f.onStep})
	r := fetchResult{
		Device: name, Host: d.Target.Host, FetchedFrom: d.Result.FetchedFrom, System: d.Result.System,
		Notes: d.Result.Notes, Documents: []documentJSON{}, Stages: taskStages(recs),
		contentFailed: d.contentFailed,
	}
	if d.resolved {
		on := !d.Target.InsecureTLS
		r.TLSVerification = &on
	}
	for _, o := range d.Result.Outcomes {
		doc := documentJSON{Name: o.Name, Bytes: o.Bytes}
		if o.Err != nil {
			doc.Bytes, doc.Error = 0, o.Err.Error()
		}
		r.Documents = append(r.Documents, doc)
	}
	if d.snap.ID != "" {
		r.Stored, r.Snapshot = true, d.snap.ID
	}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

// taskStages is a staged task's records in the JSON stage shape.
func taskStages(recs []task.Record) []stageJSON {
	out := make([]stageJSON, len(recs))
	for i, r := range recs {
		out[i] = stageJSON{
			Slug: r.Slug, Name: r.Name, Status: string(r.Status), Detail: r.Detail, Notes: r.Notes,
			ElapsedMS: float64(r.Elapsed.Microseconds()) / 1000,
		}
	}
	return out
}

// fetchResult is one device in fetch's answer (spec §6.4).
type fetchResult struct {
	Device          string           `json:"device"`
	Host            string           `json:"host,omitempty"`
	FetchedFrom     string           `json:"fetched_from,omitempty"`
	TLSVerification *bool            `json:"tls_verification,omitempty"` // absent when resolve failed
	Stored          bool             `json:"stored"`
	Snapshot        string           `json:"snapshot,omitempty"`
	System          fetch.System     `json:"system"`
	Documents       []documentJSON   `json:"documents"`
	Stages          []stageJSON      `json:"stages"`
	Notes           simulate.Reasons `json:"notes,omitempty"`
	Error           string           `json:"error,omitempty"`
	// contentFailed says that the App-ID content file could not be written;
	// its note is in Notes.
	contentFailed bool
}

// documentJSON is one document of a device's fetch.
type documentJSON struct {
	Name  string `json:"name"`
	Bytes int    `json:"bytes,omitempty"`
	Error string `json:"error,omitempty"`
}

// fetchInput is fetch's input block.
type fetchInput struct {
	Devices []string `json:"devices,omitempty"`
	Labels  []string `json:"labels,omitempty"`
	All     bool     `json:"all,omitempty"`
}

// fetchAnswer is fetch's answer: one result per device named.
type fetchAnswer struct {
	o         fetchOptions
	results   []fetchResult
	exportErr error // the inventory export failed
}

func (f fetchAnswer) Command() string { return "fetch" }
func (f fetchAnswer) Input() any {
	return fetchInput{Devices: f.o.names, Labels: f.o.labels, All: f.o.all}
}
func (f fetchAnswer) Results() any { return f.results }

// Qualifiers holds one hole per device that failed, and every note the text shows:
// TLS verification off and each note of the fetch (spec §3.2).
func (f fetchAnswer) Qualifiers() qualifiers {
	var q qualifiers
	for _, r := range f.results {
		if r.TLSVerification != nil && !*r.TLSVerification {
			q.Notes = append(q.Notes, noteOf(r.Device, "", tlsOff()))
		}
		for _, n := range r.Notes {
			q.Notes = append(q.Notes, noteOf(r.Device, "", n))
		}
		if r.Error != "" {
			q.Holes = append(q.Holes, estate.NewHole(r.Device, "", reason.New("gap.fetch-failed", r.Error)))
		}
	}
	if n, ok := f.exportNote(); ok {
		q.Notes = append(q.Notes, noteOf("", "", n))
	}
	return q
}

// exportNote is the note of a failed inventory export, if it failed.
func (f fetchAnswer) exportNote() (reason.Reason, bool) {
	if f.exportErr == nil {
		return reason.Reason{}, false
	}
	return reason.New("note.export-failed", f.exportErr.Error()), true
}

// Status is C11: every device stored every document → complete; a failure with at
// least one device stored → incomplete; no device stored → an error (spec §6.4).
// An App-ID content file that could not be written counts as a failure of its
// device. A failed inventory export makes a complete run incomplete: the
// snapshots are stored, and the note names the part that is missing. It never makes a run an
// error, and a run that stored nothing stays one.
func (f fetchAnswer) Status() error {
	stored, failed := 0, 0
	for _, r := range f.results {
		if r.Stored {
			stored++
		}
		bad := r.Error != "" || r.contentFailed
		for _, d := range r.Documents {
			bad = bad || d.Error != ""
		}
		if bad {
			failed++
		}
	}
	switch {
	case stored == 0:
		return &exitErr{code: exitError, err: errors.New("no device was fetched")}
	case failed > 0 || f.exportErr != nil:
		return errIncomplete
	}
	return nil
}

// Text prints one block per device, in the order named. It prints no hole lines:
// each failed device's block already shows its error.
func (f fetchAnswer) Text(t *textOut) error {
	for _, r := range f.results {
		switch {
		case r.TLSVerification == nil:
		case *r.TLSVerification:
			fmt.Fprintf(t, "%s: TLS certificate verification on\n", t.pal.head(r.Device))
		default:
			fmt.Fprintf(t, "%s: TLS certificate verification %s (insecure_tls: true)\n", t.pal.head(r.Device), t.pal.warn("OFF"))
		}
		if r.FetchedFrom != "" {
			fmt.Fprintf(t, "  %s is the passive HA peer; fetched from the active peer %s\n", r.Device, r.FetchedFrom)
		}
		for _, n := range r.Notes {
			fmt.Fprintf(t, "  %s\n", noteStyle(t.pal, n)("note: "+n.Text))
		}
		var tb table
		for _, d := range r.Documents {
			if d.Error != "" {
				tb.row(plain(d.Name), cell{"FAILED", t.pal.bad}, plain(d.Error))
			} else {
				tb.row(plain(d.Name), plain(fmt.Sprintf("%d bytes", d.Bytes)))
			}
		}
		_ = tb.write(t, "  ", 1)
		if r.Stored {
			fmt.Fprintf(t, "  %s %s@%s (%s, PAN-OS %s, serial %s)\n", t.pal.ok("stored"),
				r.Device, r.Snapshot, r.System.Model, r.System.SWVersion, r.System.Serial)
		}
		if r.Error != "" {
			fmt.Fprintf(t, "%s\n", failedDevice(t.pal, r.Error))
		}
		if f.o.why {
			printTaskStages(t, r.Stages)
		}
	}
	if n, ok := f.exportNote(); ok {
		fmt.Fprintf(t, "%s\n", t.pal.warn("note: "+n.Text))
	}
	return t.err
}

// failedDevice styles the token of a device's error that says where it failed: the
// "<device>/<slug>" prefix before the first colon, or the whole error without one.
func failedDevice(p palette, err string) string {
	where, rest, ok := strings.Cut(err, ":")
	if !ok {
		return p.bad(err)
	}
	return p.bad(where) + ":" + rest
}

// printTaskStages is the --why stage table of a staged task; the status cell is
// styled by outcome: ok, partial/skipped warn, failed bad.
func printTaskStages(t *textOut, stages []stageJSON) {
	var tb table
	for _, st := range stages {
		status := cell{text: st.Status}
		switch task.Status(st.Status) {
		case task.OK:
			status.style = t.pal.ok
		case task.Partial, task.Skipped:
			status.style = t.pal.warn
		case task.Failed:
			status.style = t.pal.bad
		}
		tb.row(plain(st.Slug), status, plain(st.Detail))
	}
	_ = tb.write(t, "  ", 1)
}

func (a *app) inventoryInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Write an inventory template",
		Args:  args(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error {
			return a.emitRun(a.runInventoryInit())
		},
	}
}

// initResult is inventory init's one result: the file it wrote.
type initResult struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

// initInput is inventory init's input block: the path it was asked to write.
type initInput struct {
	Path string `json:"path"`
}

// initAnswer is inventory init's answer.
type initAnswer struct{ path string }

func (a *app) runInventoryInit() (answer, error) {
	if err := inventory.WriteTemplate(a.invPath); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, usageErr("%s exists; name another file with --config, or move it", a.invPath)
		}
		return nil, err
	}
	return initAnswer{path: a.invPath}, nil
}

func (i initAnswer) Command() string        { return "inventory init" }
func (i initAnswer) Input() any             { return initInput{Path: i.path} }
func (i initAnswer) Results() any           { return []initResult{{Path: i.path, Mode: "0600"}} }
func (i initAnswer) Qualifiers() qualifiers { return qualifiers{} }

func (i initAnswer) Text(t *textOut) error {
	fmt.Fprintf(t, "wrote %s (mode 0600)\nset the hosts and credentials, then run: proteus fetch --all\n", i.path)
	return t.err
}
