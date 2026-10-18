package cli

import (
	"fmt"
	"strconv"
	"time"

	"github.com/kaisero/proteus/internal/query"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/nat"
)

// renderNAT draws a NAT answer (spec §18 N9): the answer line, one box as in
// routing, the packet before and after, and what security policy matches —
// pre-NAT addresses and port, post-NAT zones (§18 F5, F6, verified on fw01).
func renderNAT(t *textOut, run simulate.Run, r nat.Result, answer string, takenAt, now time.Time, why bool) {
	f := run.Input.Flow
	fmt.Fprintf(t, "simulate nat %s -> %s %s on %s            fidelity: %s\n\n",
		query.EndpointText(f.Source), f.Destination, portSpec(f.Protocol, f.DestPort), run.Device, styledLevel(t.pal, run.Fidelity.Level()))
	fmt.Fprintf(t, "%s\n\n", answer)

	pre := r.PreNAT
	out := pre.Out
	if r.PostNAT != nil {
		out = r.PostNAT.Out
	}
	title := fmt.Sprintf("┌─ %s ─ %s ─ router %s", run.Device, run.Vsys, pre.Out.Router)
	if pre.Out.Router == "" {
		title = fmt.Sprintf("┌─ %s ─ %s", run.Device, run.Vsys)
	}
	if !takenAt.IsZero() {
		title += " ─ snapshot " + ago(now.Sub(takenAt))
	}
	in := natIngress(run)
	rows := [][2]string{{"zones", zoneText(in.Zone) + " -> " + zoneText(out.Zone)}}
	if in.Interface != "" {
		rows = append(rows, [2]string{"in", portText(in)})
	}
	if out.Interface != "" {
		rows = append(rows, [2]string{"out", portText(out)})
	}
	for _, m := range pre.Routes {
		rows = append(rows, [2]string{"route", matchText(m, "", pre.Out) + prePost(r.PostNAT != nil, "pre-NAT")})
	}
	if r.PostNAT != nil {
		for _, m := range r.PostNAT.Routes {
			rows = append(rows, [2]string{"route", matchText(m, "", r.PostNAT.Out) + "   (post-NAT)"})
		}
	}
	switch {
	case r.Dropped != "":
		rows = append(rows, [2]string{"rule", "none: " + r.Dropped})
	case r.Rule == nil:
		rows = append(rows, [2]string{"rule", "none: the packet leaves untranslated"})
	default:
		name := t.pal.accent(r.Rule.Name)
		if r.Rule.Origin != "" {
			name += " (implicit rule of the bi-directional " + r.Rule.Origin + ")"
		}
		rows = append(rows, [2]string{"rule", fmt.Sprintf("%s, matched %s -> %s", name, zoneText(in.Zone), zoneText(pre.Out.Zone))})
	}
	if s := r.Source; s != nil {
		rows = append(rows, [2]string{"source", query.SourceTranslation(query.EndpointText(f.Source), s)})
	}
	if d := r.Destination; d != nil {
		rows = append(rows, [2]string{"dest", fmt.Sprintf("%s:%s", f.Destination, query.PortNumber(f.DestPort)) + " -> " + query.DestinationTranslation(d, f.DestPort)})
	}
	for _, d := range r.Doubts {
		rows = append(rows, [2]string{"doubt", d.Rule + ": " + d.Text()})
	}
	for _, n := range r.Notes {
		rows = append(rows, [2]string{"note", n.Text})
	}
	b := newBox(title, rows)
	b.draw(t, max(minBox, b.width), false)

	a := r.Flow
	fmt.Fprintln(t)
	fmt.Fprintf(t, "  before   %s -> %s:%s  %s\n", query.EndpointText(f.Source), f.Destination, query.PortNumber(f.DestPort), f.Protocol)
	fmt.Fprintf(t, "  after    %s -> %s:%s  %s\n\n", afterSource(f, a, r.Source), a.Destination, query.PortNumber(a.DestPort), a.Protocol)
	if r.Dropped == "" {
		fmt.Fprintf(t, "security policy matches: %s -> %s, port %s, zones %s -> %s\n",
			query.EndpointText(f.Source), f.Destination, query.PortNumber(f.DestPort), zoneText(in.Zone), zoneText(out.Zone))
	}
	if run.Fidelity.Level() != "exact" {
		fmt.Fprintf(t, "may be incomplete: %s\n", run.Fidelity.Level())
		for _, st := range run.Stages {
			if st.Fidelity.Level() != "exact" {
				fmt.Fprintf(t, "  %-12s %s\n", st.Slug, st.Detail)
			}
		}
	}
	if why {
		fmt.Fprintln(t)
		var excluded table
		for _, e := range r.Excluded {
			excluded.row(plain("not"), plain(e.Rule), plain(e.Field))
		}
		_ = excluded.write(t, "  ", 1)
		printFidelityStages(t, run.Stages)
	}
}

// printFidelityStages is a simulation's --why stage table: slug, fidelity styled by
// level, detail.
func printFidelityStages(t *textOut, stages []simulate.Stage) {
	var tb table
	for _, st := range stages {
		lvl := st.Fidelity.Level()
		tb.row(plain(st.Slug), cell{text: lvl, style: fidelityStyle(t.pal, lvl)}, plain(st.Detail))
	}
	_ = tb.write(t, "  ", 1)
}

// natIngress is the ingress the place stage settled on, from the match's input.
func natIngress(run simulate.Run) simulate.Port {
	if r, ok := run.Output.(nat.Result); ok {
		return r.In
	}
	return simulate.Port{}
}

func prePost(translated bool, label string) string {
	if !translated {
		return ""
	}
	return "   (" + label + ")"
}

func portSpec(proto string, port uint16) string {
	if port == 0 {
		return proto
	}
	return proto + "/" + strconv.Itoa(int(port))
}

func afterSource(before, after simulate.Flow, t *nat.Translation) string {
	if t == nil {
		return query.EndpointText(before.Source)
	}
	s := after.Source.String()
	if t.Port == nat.PortRuntime {
		s += ":(runtime)"
	}
	return s
}
