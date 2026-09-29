package cli

import (
	"slices"

	"github.com/spf13/cobra"
)

// registerCompletions teaches shell completion the values proteus knows: device
// names from the inventory, and the fixed values of --output and --log-level.
// Cobra's own completion command writes the shell scripts.
func (a *app) registerCompletions(root *cobra.Command) {
	_ = root.RegisterFlagCompletionFunc("output", fixedValues("text", "json"))
	_ = root.RegisterFlagCompletionFunc("log-level", fixedValues("error", "warn", "info", "debug"))
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("device") != nil {
			_ = c.RegisterFlagCompletionFunc("device", a.completeDevices)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

// completeDevices offers the inventory's device names that are not given yet.
// Completion runs no pre-run hook, so it reads the inventory itself; without one
// there is nothing to offer.
func (a *app) completeDevices(_ *cobra.Command, given []string, _ string) ([]string, cobra.ShellCompDirective) {
	a.loadInventory()
	if a.inv == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, n := range a.inv.Names() {
		if !slices.Contains(given, n) {
			out = append(out, n)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeOneDevice offers device names for a command that takes one device.
func (a *app) completeOneDevice(c *cobra.Command, given []string, prefix string) ([]string, cobra.ShellCompDirective) {
	if len(given) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return a.completeDevices(c, given, prefix)
}

func fixedValues(values ...string) cobra.CompletionFunc {
	return func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}
