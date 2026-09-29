package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/spf13/cobra"

	"github.com/okaiser/panos-analyst/fetch"
	"github.com/okaiser/panos-analyst/inventory"
	"github.com/okaiser/panos-analyst/runlog"
	"github.com/okaiser/panos-analyst/store"
)

// fetchConcurrency bounds how many devices are fetched at once. It is a constant
// because spec §15 C14 adds no settings beyond four; it becomes one when someone
// needs it.
const fetchConcurrency = 8

func (a *app) fetchCmd() *cobra.Command {
	var all bool
	var labels []string
	cmd := &cobra.Command{
		Use:   "fetch [device...]",
		Short: "Fetch devices into the store",
		Long: "Fetch logs in to each device, reads its configuration and operational state, and\n" +
			"stores them as a snapshot. Name devices, select them with --label, or pass --all.",
		RunE: func(c *cobra.Command, names []string) error {
			kinds := 0
			for _, given := range []bool{len(names) > 0, len(labels) > 0, all} {
				if given {
					kinds++
				}
			}
			if kinds != 1 {
				return usageErr("name devices, select them with --label, or pass --all; exactly one of those")
			}
			s, err := a.settings(true)
			if err != nil {
				return err
			}
			if all || len(labels) > 0 {
				if names, err = s.inv.Select(nil, labels); err != nil {
					return usageErr("%v", err)
				}
			}
			st, err := a.openStore(s.storeRoot)
			if err != nil {
				return err
			}
			return fetchDevices(c.Context(), a.stdout, s.inv, st, names, a.getenv, a.log)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "fetch every device in the inventory")
	cmd.Flags().StringArrayVar(&labels, "label", nil, "fetch devices with this key=value label (repeatable; all must hold)")
	return cmd
}

// fetchDevices fetches the named devices, up to fetchConcurrency at once, and prints
// each device's report in the order the devices were named. A device that fails is
// reported and the rest still run (spec S10). Some failures exit 3; all of them
// exit 1.
func fetchDevices(ctx context.Context, out io.Writer, inv *inventory.Inventory, st *store.Store,
	names []string, getenv func(string) string, log *runlog.Logger,
) error {
	errs, stored := fetchEach(ctx, out, inv, st, names, getenv, log)
	var joined []error
	anyStored := false
	for i, name := range names {
		anyStored = anyStored || stored[i]
		if errs[i] != nil {
			joined = append(joined, fmt.Errorf("%s: %w", name, errs[i]))
		}
	}
	switch {
	case len(joined) == 0:
		return nil
	case !anyStored:
		return errors.Join(joined...)
	default:
		return errIncomplete
	}
}

// fetchEach fetches the devices in parallel and returns, per device and in order,
// its error and whether a snapshot was stored. Each device's report is printed
// whole, so reports never interleave.
func fetchEach(ctx context.Context, out io.Writer, inv *inventory.Inventory, st *store.Store,
	names []string, getenv func(string) string, log *runlog.Logger,
) ([]error, []bool) {
	reports := make([]bytes.Buffer, len(names))
	errs := make([]error, len(names))
	stored := make([]bool, len(names))
	sem := make(chan struct{}, fetchConcurrency)
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			stored[i], errs[i] = fetchOne(ctx, &reports[i], inv, st, name, getenv, log)
			if errs[i] != nil {
				fmt.Fprintf(&reports[i], "%s: %v\n", name, errs[i])
			}
		}()
	}
	wg.Wait()
	for i := range reports {
		_, _ = out.Write(reports[i].Bytes())
	}
	return errs, stored
}

// peerHost maps an HA peer's reported management address to a host; nil uses the
// address. Tests point it at a second fake device.
var peerHost func(mgmtIP string) string

func fetchOne(ctx context.Context, out io.Writer, inv *inventory.Inventory, st *store.Store,
	name string, getenv func(string) string, log *runlog.Logger,
) (bool, error) {
	t, err := inv.Resolve(name, getenv)
	if err != nil {
		return false, err
	}
	if t.InsecureTLS {
		fmt.Fprintf(out, "%s: TLS certificate verification OFF (insecure_tls: true)\n", name)
	} else {
		fmt.Fprintf(out, "%s: TLS certificate verification on\n", name)
	}
	log.Infof(runlog.TagAPI, "%s: fetching %s, TLS verification %s", name, t.Host, map[bool]string{true: "off", false: "on"}[t.InsecureTLS])
	res, err := fetch.RunActive(ctx, t, fetch.Documents, fetch.ActiveOptions{PeerHost: peerHost}, log)
	if err != nil {
		return false, err
	}
	meta := store.Meta{
		Device: t.Name, Host: t.Host,
		Hostname: res.System.Hostname, Model: res.System.Model,
		Serial: res.System.Serial, SWVersion: res.System.SWVersion,
		FetchedFrom: res.FetchedFrom, Notes: res.Notes,
	}
	if res.FetchedFrom != "" {
		fmt.Fprintf(out, "  %s is the passive HA peer; fetched from the active peer %s\n", name, res.FetchedFrom)
	}
	for _, n := range res.Notes {
		fmt.Fprintf(out, "  note: %s\n", n)
	}
	var docErrs []error
	for _, o := range res.Outcomes {
		if o.Err != nil {
			meta.Documents = append(meta.Documents, store.DocumentMeta{Name: o.Name, Error: o.Err.Error()})
			docErrs = append(docErrs, fmt.Errorf("%s: %w", o.Name, o.Err))
			fmt.Fprintf(out, "  %-12s FAILED  %v\n", o.Name, o.Err)
			continue
		}
		meta.Documents = append(meta.Documents, store.DocumentMeta{Name: o.Name})
		fmt.Fprintf(out, "  %-12s %8d bytes\n", o.Name, o.Bytes)
	}
	sn, err := st.Write(meta, res.Docs, t.SnapshotKeep)
	if err != nil {
		return false, err
	}
	fmt.Fprintf(out, "  stored %s@%s (%s, PAN-OS %s, serial %s)\n",
		sn.Device, sn.ID, res.System.Model, res.System.SWVersion, res.System.Serial)
	log.Infof(runlog.TagSnap, "%s: stored %s", name, sn.ID)
	return true, errors.Join(docErrs...)
}

func (a *app) inventoryInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Write an inventory template",
		Args:  args(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error {
			path := a.configFlag
			if path == "" {
				var err error
				if path, err = inventory.DefaultPath(a.getenv); err != nil {
					return err
				}
			}
			if err := inventory.WriteTemplate(path); err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "wrote %s (mode 0600)\n"+
				"set the hosts and credentials, then run: panos-analyst fetch --all\n", path)
			return nil
		},
	}
}
