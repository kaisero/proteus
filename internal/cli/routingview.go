package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/topology"
)

// minBox is the narrowest box; a longer row widens it, never wraps.
const minBox = 56

// renderPath draws a path as one box per hop (spec §17.3, R8): the zone pair first,
// because that is where a rule goes; a link line between boxes; the end; then the
// firewalls on the path and what makes the answer uncertain. title leads the
// first line; rows, when not nil, gives hop i (0-based) extra rows after
// routing's.
func renderPath(t *textOut, title string, run simulate.Run, p routing.Path, now time.Time, why bool, rows func(i int) [][2]string) {
	fmt.Fprintf(t, "%s            fidelity: %s\n\n", title, styledLevel(t.pal, run.Fidelity.Level()))
	for _, n := range p.Notes {
		fmt.Fprintf(t, "  %s\n", noteStyle(t.pal, n)("note: "+n))
	}
	if len(p.Notes) > 0 {
		fmt.Fprintln(t)
	}
	if len(p.Hops) > 0 {
		first := p.Hops[0]
		switch {
		case p.Placed == topology.PlacedRouted:
			fmt.Fprintf(t, "  %s   placed by route %s on %s (inferred)\n", p.Source, p.PlacedVia, first.Device)
		case len(p.Source.Addrs) == 0:
			fmt.Fprintf(t, "  start on %s, router %s\n", first.Device, hopRouter(first))
		default:
			fmt.Fprintf(t, "  %s\n", p.Source)
		}
		if first.In.Addr.IsValid() {
			fmt.Fprintf(t, "     │ %s\n", first.In.Link())
		}
	}
	boxes := make([]hopBox, len(p.Hops))
	width := minBox
	for i, h := range p.Hops {
		var extra [][2]string
		if rows != nil {
			extra = rows(i)
		}
		boxes[i] = newHopBox(h, now, extra)
		width = max(width, boxes[i].width)
	}
	for i, h := range p.Hops {
		last := i == len(p.Hops)-1
		boxes[i].draw(t, width, !last || continues(p))
		switch {
		case !last:
			next := p.Hops[i+1]
			link := "     │"
			if h.Out.Addr.IsValid() {
				link += " " + h.Out.Link().String()
				if next.In.Addr.IsValid() {
					link += fmt.Sprintf("   %s -> %s", h.Out.Addr.Addr(), next.In.Addr.Addr())
				}
			} else if h.Device == next.Device {
				link += fmt.Sprintf(" %s -> %s", h.Vsys, next.Vsys)
			}
			fmt.Fprintln(t, link)
		case continues(p) && h.Out.Addr.IsValid() && p.Outcome != routing.LeftByInterface:
			fmt.Fprintf(t, "     │ %s\n", h.Out.Link())
		case continues(p):
			fmt.Fprintf(t, "     │ %s\n", h.Out.Interface)
		}
	}
	fmt.Fprintf(t, "  %s\n\n", p.End)

	var fws []string
	for _, h := range p.Hops {
		fws = append(fws, fmt.Sprintf("%s (%s -> %s)", h.Device, zoneText(h.Flow.FromZone), zoneText(h.Flow.ToZone)))
	}
	if len(fws) > 0 {
		fmt.Fprintf(t, "firewalls on the path: %s\n", strings.Join(fws, ", "))
	}
	if len(p.Hidden) > 0 {
		fmt.Fprintf(t, "may be on the path, not detected: %s\n", strings.Join(p.Hidden, ", "))
	}
	if run.Fidelity.Level() != "exact" {
		fmt.Fprintf(t, "may be incomplete: %s\n", incompleteText(run.Fidelity))
	}
	if why {
		fmt.Fprintln(t)
		printFidelityStages(t, run.Stages)
	}
}

// continues reports whether the last box has a line out of it: the packet goes
// somewhere rather than stopping inside the firewall.
func continues(p routing.Path) bool {
	switch p.Outcome {
	case routing.Delivered, routing.LeftEstate, routing.LeftByInterface:
		return true
	}
	return false
}

// routingTitle is simulate routing's title: the traced source and destination.
func routingTitle(p routing.Path) string {
	return fmt.Sprintf("simulate routing %s -> %s", sourceText(p), p.Destination)
}

func sourceText(p routing.Path) string {
	if len(p.Source.Addrs) == 0 && p.Source.Name == "" {
		return "(no source)"
	}
	return p.Source.String()
}

func zoneText(z string) string {
	if z == "" {
		return "?"
	}
	return z
}

func incompleteText(f simulate.Fidelity) string {
	parts := f.Reasons()
	if s := f.Skipped(); len(s) > 0 {
		parts = append(parts, "not evaluated: "+strings.Join(s, ", "))
	}
	if len(parts) == 0 {
		return f.Level() + ": some hops rest on assumptions; see their notes"
	}
	return strings.Join(parts, "; ")
}

// hopBox is one hop's box before drawing: its title, its rows, and the width they
// need. Every box of a path is drawn as wide as the widest.
type hopBox struct {
	title string
	lines []string
	width int
}

func newHopBox(h routing.Hop, now time.Time, extra [][2]string) hopBox {
	title := fmt.Sprintf("┌─ %s ─ %s ─ router %s", h.Device, h.Vsys, hopRouter(h))
	if !h.TakenAt.IsZero() {
		title += " ─ snapshot " + ago(now.Sub(h.TakenAt))
	}
	rows := [][2]string{{"zones", zoneText(h.Flow.FromZone) + " -> " + zoneText(h.Flow.ToZone)}}
	if h.In.Interface != "" {
		rows = append(rows, [2]string{"in", portText(h.In)})
	}
	if h.Out.Interface != "" {
		rows = append(rows, [2]string{"out", portText(h.Out)})
	}
	for _, l := range h.Lookups {
		rows = append(rows, [2]string{"route", routeText(l, h.Out)})
	}
	if len(h.ECMP) > 0 {
		var hops []string
		for _, nf := range h.ECMP {
			s := nf.NextHop
			if nf.Reaches != "" {
				s += " (" + nf.Reaches + ")"
			}
			hops = append(hops, s)
		}
		rows = append(rows, [2]string{"ecmp", fmt.Sprintf("%d other next hops not followed: %s", len(h.ECMP), strings.Join(hops, ", "))})
	}
	for _, n := range h.Notes {
		rows = append(rows, noteRow(n))
	}
	for _, a := range h.Alternates {
		s := fmt.Sprintf("%s via %s   %s, distance %d", a.Destination, nextHopsText(a), a.Protocol, a.Distance)
		if a.Selected && len(h.Lookups) > 0 && a.Destination == h.Lookups[0].Match.Destination {
			s += " (active)"
		}
		rows = append(rows, [2]string{"alt", s})
	}
	rows = append(rows, extra...)

	return newBox(title, rows)
}

// hopRouter is the router a hop starts in: its first lookup's, or, when no
// route matched, the ingress interface's.
func hopRouter(h routing.Hop) string {
	if len(h.Lookups) > 0 {
		return h.Lookups[0].Router
	}
	return h.In.Router
}

// newBox lays out a box's title and labelled rows; the routing and NAT renderers
// share it.
func newBox(title string, rows [][2]string) hopBox {
	b := hopBox{title: title, width: visibleWidth(title) + 3}
	for _, r := range rows {
		l := fmt.Sprintf("│  %-8s%s", r[0], r[1])
		b.lines = append(b.lines, l)
		b.width = max(b.width, visibleWidth(l)+2)
	}
	return b
}

// draw writes the box at the given width; an open box has a line out of its
// bottom.
func (b hopBox) draw(w io.Writer, width int, open bool) {
	fmt.Fprintln(w, "  "+b.title+" "+strings.Repeat("─", width-visibleWidth(b.title)-2)+"┐")
	for _, l := range b.lines {
		fmt.Fprintln(w, "  "+l+strings.Repeat(" ", width-visibleWidth(l)-1)+"│")
	}
	if open {
		fmt.Fprintln(w, "  └──┬"+strings.Repeat("─", width-5)+"┘")
	} else {
		fmt.Fprintln(w, "  └"+strings.Repeat("─", width-2)+"┘")
	}
}

func portText(p simulate.Port) string {
	if !p.Addr.IsValid() {
		return p.Interface
	}
	return fmt.Sprintf("%-13s %s", p.Interface, p.Addr)
}

// routeText is a route: via its next hop, or via its interface when it has none.
// Only a route the routing table calls connected, or failing a routing table one
// that stays inside the interface's own net, reads "connected": a static route
// into a tunnel has no next hop either.
func routeText(l routing.Lookup, out simulate.Port) string {
	if l.Stage != "" {
		return matchText(l.Match, l.Protocol, out) + "   (" + l.Stage + ")"
	}
	return matchText(l.Match, l.Protocol, out)
}

// matchText is one route match, with its protocol when the routing table gives it.
func matchText(m simulate.Match, protocol string, out simulate.Port) string {
	first := m.First()
	via, ok := addrOrNone(first.NextHop)
	connected := !ok && (protocol == "connected" ||
		protocol == "" && out.Addr.IsValid() && out.Link().Overlaps(m.Destination) && out.Addr.Bits() <= m.Destination.Bits())
	if connected {
		return fmt.Sprintf("%s  connected", m.Destination)
	}
	if !ok {
		via = first.Interface
	}
	s := fmt.Sprintf("%s via %s", m.Destination, via)
	if protocol != "" {
		s += "   " + protocol
	}
	return s
}

func addrOrNone(s string) (string, bool) {
	if s == "" || s == "0.0.0.0" {
		return "", false
	}
	return s, true
}

// nextHopsText names a routing table entry's next hops: an address, or the
// interface of a directly connected one.
func nextHopsText(r resolve.RIBRoute) string {
	var out []string
	for _, nh := range r.NextHops {
		if nh.IP.IsValid() {
			out = append(out, nh.IP.String())
		} else {
			out = append(out, nh.Interface)
		}
	}
	return strings.Join(out, ", ")
}

// noteRow gives a hop note its row label: pbf, nat, schema, or note.
func noteRow(n string) [2]string {
	for _, p := range []string{"pbf ", "nat "} {
		if after, ok := strings.CutPrefix(n, p); ok {
			return [2]string{strings.TrimSpace(p), after}
		}
	}
	if rest, ok := strings.CutPrefix(n, "schema: "); ok {
		return [2]string{"schema", rest}
	}
	return [2]string{"note", n}
}
