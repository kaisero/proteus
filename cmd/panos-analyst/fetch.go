package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/okaiser/panos-analyst/fetch"
	"github.com/okaiser/panos-analyst/inventory"
	"github.com/okaiser/panos-analyst/store"
)

// fetchDevices fetches each named device into the store, one after another. A
// device that fails is reported and the rest still run (spec S10); the returned
// error names every failure.
func fetchDevices(ctx context.Context, out io.Writer, inv *inventory.Inventory, st *store.Store,
	names []string, getenv func(string) string,
) error {
	var failed []error
	for _, name := range names {
		if err := fetchOne(ctx, out, inv, st, name, getenv); err != nil {
			fmt.Fprintf(out, "%s: %v\n", name, err)
			failed = append(failed, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(failed...)
}

func fetchOne(ctx context.Context, out io.Writer, inv *inventory.Inventory, st *store.Store,
	name string, getenv func(string) string,
) error {
	t, err := inv.Resolve(name, getenv)
	if err != nil {
		return err
	}
	if t.InsecureTLS {
		fmt.Fprintf(out, "%s: TLS certificate verification OFF (insecure_tls: true)\n", name)
	} else {
		fmt.Fprintf(out, "%s: TLS certificate verification on\n", name)
	}
	res, err := fetch.Run(ctx, t, fetch.Documents)
	if err != nil {
		return err
	}
	meta := store.Meta{
		Device: t.Name, Host: t.Host,
		Hostname: res.System.Hostname, Model: res.System.Model,
		Serial: res.System.Serial, SWVersion: res.System.SWVersion,
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
		return err
	}
	fmt.Fprintf(out, "  stored %s@%s (%s, PAN-OS %s, serial %s)\n",
		sn.Device, sn.ID, res.System.Model, res.System.SWVersion, res.System.Serial)
	return errors.Join(docErrs...)
}
