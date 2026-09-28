package main

import (
	"fmt"

	"github.com/RoaringBitmap/roaring/v2"
	"github.com/spf13/cobra"

	"github.com/okaiser/panos-analyst/index"
)

// flow is the input of spec §11.3 as flags (spec §15 C12).
type flow struct {
	protocol, application, user, url string
	port, sourcePort                 int
	fromZone, toZone                 string
}

// secpolicyCmd is the stopgap of spec §15 C15: today's composition for one device,
// kept so the device probe runs until M4 replaces its insides with the staged
// simulator. The command's surface is the one M4 keeps.
func (a *app) secpolicyCmd() *cobra.Command {
	var sel selection
	var fl flow
	cmd := &cobra.Command{
		Use:   "secpolicy <source> <destination>",
		Short: "Which security rule one flow would hit on one device",
		Args:  args(cobra.ExactArgs(2)),
		RunE: func(c *cobra.Command, argv []string) error {
			if (fl.fromZone == "") != (fl.toZone == "") {
				return usageErr("give both --from-zone and --to-zone, or neither")
			}
			s, err := a.settings(sel.file == "")
			if err != nil {
				return err
			}
			ts, holes, err := a.targets(c.Context(), sel, s, a.stderr)
			if err != nil {
				return err
			}
			if len(ts) != 1 {
				if len(ts) == 0 {
					printQualifiers(a, holes, nil, nil)
					return fmt.Errorf("the selection has no device and vsys to simulate on")
				}
				return usageErr("the selection has %d device and vsys pairs; estate simulation arrives in M5, so select one device and one vsys", len(ts))
			}
			t := ts[0]
			idx, err := index.For(t.Config, t.Scope)
			if err != nil {
				return err
			}
			src, dst := argv[0], argv[1]
			srcRules, srcRep := idx.Candidates(index.Source, src)
			dstRules, dstRep := idx.Candidates(index.Destination, dst)
			un, notes := qualifiers(ts)
			for _, rep := range []index.Report{srcRep, dstRep} {
				for _, u := range rep.Unresolved {
					un = append(un, unresolved{Device: t.Device, Vsys: t.Vsys, Value: u.Value, Reason: u.Reason})
				}
			}
			cand := roaring.And(srcRules, dstRules)
			zoned := fl.fromZone != ""
			if zoned {
				fromRules, _ := idx.Candidates(index.FromZone, fl.fromZone)
				toRules, _ := idx.Candidates(index.ToZone, fl.toZone)
				cand.And(fromRules)
				cand.And(toRules)
			}
			cand.AndNot(idx.Disabled())

			notEvaluated := []string{"application", "service"}
			if !zoned {
				notEvaluated = append(notEvaluated, "zones")
			}
			for flag, val := range map[string]string{"user": fl.user, "url": fl.url} {
				if val != "" {
					notEvaluated = append(notEvaluated, flag)
				}
			}
			type rule struct {
				Position int    `json:"position"`
				Name     string `json:"name"`
				Action   string `json:"action"`
				Layer    string `json:"layer"`
				Scope    string `json:"scope"`
			}
			rules := idx.Rules()
			var candidates []rule
			for it := cand.Iterator(); it.HasNext(); {
				r := rules[it.Next()]
				candidates = append(candidates, rule{r.Position, r.Name, r.Action, r.Layer.String(), r.Scope.String()})
			}
			var firstMatch *rule
			if len(candidates) > 0 {
				firstMatch = &candidates[0]
			}

			if s.output == "json" {
				in := map[string]any{
					"source": src, "destination": dst, "protocol": fl.protocol, "port": fl.port,
					"source_port": fl.sourcePort, "from_zone": fl.fromZone, "to_zone": fl.toZone,
					"application": fl.application, "user": fl.user, "url": fl.url, "selection": sel.input(),
				}
				res := map[string]any{
					"target": targetOf(t), "candidates": candidates, "first_match": firstMatch,
					"not_evaluated": notEvaluated,
				}
				if err := writeJSON(a.stdout, envelope{Command: "simulate secpolicy", Input: in, Results: res, Holes: holes, Unresolved: un, Notes: notes}); err != nil {
					return err
				}
				return finish(holes, un)
			}
			fmt.Fprintf(a.stdout, "%s -> %s %s", src, dst, fl.protocol)
			if fl.port != 0 {
				fmt.Fprintf(a.stdout, "/%d", fl.port)
			}
			fmt.Fprintf(a.stdout, "\n%s\n", header(t, a.now()))
			for _, n := range t.Notes {
				fmt.Fprintf(a.stdout, "  note: %s\n", n)
			}
			if zoned {
				fmt.Fprintf(a.stdout, "  zones: from %s, to %s\n", fl.fromZone, fl.toZone)
			}
			for _, r := range candidates {
				fmt.Fprintf(a.stdout, "  %3d. %-26s %-6s [%-11s %s]\n", r.Position, r.Name, r.Action, r.Layer, r.Scope)
			}
			printQualifiers(a, holes, un, notes)
			fmt.Fprintf(a.stdout, "not evaluated: %s\n", join(notEvaluated, ", "))
			if firstMatch == nil {
				fmt.Fprintln(a.stdout, "no enabled rule matches")
			} else {
				fmt.Fprintf(a.stdout, "first match: %s (%s)\n", firstMatch.Name, firstMatch.Action)
			}
			return finish(holes, un)
		},
	}
	sel.bind(cmd.Flags(), true)
	f := cmd.Flags()
	f.StringVar(&fl.protocol, "protocol", "tcp", "tcp, udp, icmp or a protocol number")
	f.IntVar(&fl.port, "port", 0, "destination port")
	f.IntVar(&fl.sourcePort, "source-port", 0, "source port")
	f.StringVar(&fl.fromZone, "from-zone", "", "source zone; zones are not evaluated when absent")
	f.StringVar(&fl.toZone, "to-zone", "", "destination zone")
	f.StringVar(&fl.application, "application", "", "application (not evaluated yet)")
	f.StringVar(&fl.user, "user", "", "source user (not evaluated yet)")
	f.StringVar(&fl.url, "url", "", "URL (not evaluated yet)")
	return cmd
}
