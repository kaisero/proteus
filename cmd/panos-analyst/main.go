// Command panos-analyst fetches firewall configurations and operational state into
// an on-disk store, so that panos-explore can answer from what a device said.
//
// Usage:
//
//	panos-analyst init                 write an inventory template
//	panos-analyst fetch <device>...    fetch devices into the store
//	panos-analyst fetch --all          fetch every device in the inventory
//	panos-analyst snapshots <device>   list a device's stored snapshots
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/okaiser/panos-analyst/inventory"
	"github.com/okaiser/panos-analyst/store"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := root().ExecuteContext(ctx)
	stop()
	if err != nil {
		os.Exit(1)
	}
}

func root() *cobra.Command {
	var configPath, storePath string
	cmd := &cobra.Command{
		Use:          "panos-analyst",
		Short:        "Fetch PAN-OS firewalls into a snapshot store",
		Version:      version,
		SilenceUsage: true,
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "",
		"inventory file (default $PANOS_CONFIG or ~/.config/panos-analyst/config.yaml)")
	cmd.PersistentFlags().StringVar(&storePath, "store", "",
		"snapshot store (default $PANOS_STORE or ~/.local/share/panos-analyst)")

	// paths applies the precedence default < PANOS_* env < flag (spec S7) to the
	// inventory file and the store root.
	paths := func() (string, string, error) {
		c, s := configPath, storePath
		var err error
		if c == "" {
			if c, err = inventory.DefaultPath(os.Getenv); err != nil {
				return "", "", err
			}
		}
		if s == "" {
			if s, err = store.DefaultRoot(os.Getenv); err != nil {
				return "", "", err
			}
		}
		return c, s, nil
	}

	cmd.AddCommand(initCmd(paths), fetchCmd(paths), snapshotsCmd(paths))
	return cmd
}

type pathsFunc func() (configPath, storeRoot string, err error)

func initCmd(paths pathsFunc) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Write an inventory template",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cfgPath, _, err := paths()
			if err != nil {
				return err
			}
			if err := inventory.WriteTemplate(cfgPath); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "wrote %s (mode 0600)\n"+
				"set the hosts and credentials, then run: panos-analyst fetch --all\n", cfgPath)
			return nil
		},
	}
}

func fetchCmd(paths pathsFunc) *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "fetch [device...]",
		Short: "Fetch devices into the store",
		RunE: func(c *cobra.Command, args []string) error {
			cfgPath, storeRoot, err := paths()
			if err != nil {
				return err
			}
			inv, err := inventory.Load(cfgPath)
			if err != nil {
				return err
			}
			names := args
			switch {
			case all && len(args) > 0:
				return errors.New("name devices or pass --all, not both")
			case all:
				names = inv.Names()
			case len(args) == 0:
				return errors.New("name at least one device, or pass --all")
			}
			st, err := store.Open(storeRoot)
			if err != nil {
				return err
			}
			return fetchDevices(c.Context(), c.OutOrStdout(), inv, st, names, os.Getenv)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "fetch every device in the inventory")
	return cmd
}

func snapshotsCmd(paths pathsFunc) *cobra.Command {
	return &cobra.Command{
		Use:   "snapshots <device>",
		Short: "List a device's stored snapshots, newest first; * marks latest",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			_, storeRoot, err := paths()
			if err != nil {
				return err
			}
			st, err := store.Open(storeRoot)
			if err != nil {
				return err
			}
			ids, err := st.List(args[0])
			if err != nil {
				return err
			}
			latest, _ := st.Latest(args[0])
			for _, id := range ids {
				sn, err := st.Get(args[0], id)
				if err != nil {
					return err
				}
				mark := " "
				if id == latest.ID {
					mark = "*"
				}
				failed := 0
				for _, d := range sn.Meta.Documents {
					if d.Error != "" {
						failed++
					}
				}
				fmt.Fprintf(c.OutOrStdout(), "%s %s  PAN-OS %-8s %d documents, %d failed\n",
					mark, id, sn.Meta.SWVersion, len(sn.Meta.Documents), failed)
			}
			return nil
		},
	}
}
