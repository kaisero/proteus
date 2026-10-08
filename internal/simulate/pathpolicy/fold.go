package pathpolicy

import (
	"fmt"
	"strings"

	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/routing"
)

// The notes a result may carry (spec §4.8, E17).
const (
	noteLocal = "the firewall's own services (interface management profile) are not checked"
)

// hopState is what one hop concludes, and the point that names why. Undecided
// wins over stop on one hop (spec §4.7): the path's and the zones' doubts first,
// then the first undecided check; then the first check that stops.
func hopState(h Hop) (HopVerdict, *Point) {
	if len(h.Doubts) > 0 {
		return Undecided, &Point{Hop: h.Index, Check: checkRouting, Reason: h.Doubts[0]}
	}
	for _, want := range []HopVerdict{Undecided, Stop} {
		for _, c := range h.Checks {
			if c.Verdict == want {
				return want, &Point{Hop: h.Index, Check: c.Name, Rule: c.Rule, Reason: c.Reason}
			}
		}
	}
	return Pass, nil
}

// fold walks the hops in order and sets the verdict, its point, the after-deny
// flags, the fidelity and the notes (spec §5). The first hop that is undecided or
// stops sets the point; every later hop is still evaluated (E5), and those after
// a stop carry AfterDeny. A stop after an undecided point leaves the answer
// undecided, and a note names it (E7). With no such hop, routing's end decides.
func fold(r *Result, routingFid simulate.Fidelity) {
	stopped := false
	for i := range r.Hops {
		h := &r.Hops[i]
		h.AfterDeny = stopped
		v, pt := hopState(*h)
		switch {
		case v == Pass:
		case r.At == nil:
			r.At, r.Verdict = pt, VerdictUndecided
			if v == Stop {
				r.Verdict = VerdictDenied
			}
		case v == Stop && !stopped:
			r.Notes = append(r.Notes, fmt.Sprintf("a later hop denies: hop %d (%s), %s", h.Index, describe(h.Routing), pt.Reason))
		}
		if v == Stop {
			stopped = true
		}
	}
	if r.At == nil {
		// The end line pads its columns for the text; a reason reads as a
		// sentence.
		end := &Point{Hop: len(r.Hops), Check: checkRouting, Reason: strings.Join(strings.Fields(r.Path.End), " ")}
		switch r.Path.Outcome {
		case routing.Delivered, routing.Local:
			r.Verdict = VerdictAllowed
		case routing.Dropped:
			r.Verdict, r.At = VerdictDenied, end
		default:
			// left-estate, left-by-interface, loop, too-long, unresolved: the path
			// goes on where this estate cannot follow it.
			r.Verdict, r.At = VerdictUndecided, end
		}
	}
	// Checks after the point do not lower the answer's fidelity (spec §5.3).
	upto := len(r.Hops)
	if r.At != nil {
		upto = r.At.Hop
	}
	fs := []simulate.Fidelity{routingFid}
	for _, h := range r.Hops[:upto] {
		// A hop the path or its zones leave undecided may miss what its checks
		// found, whatever they declared.
		for _, d := range h.Doubts {
			fs = append(fs, simulate.UnderMatch(d))
		}
		for _, c := range h.Checks {
			fs = append(fs, c.Fidelity)
		}
	}
	r.Fidelity = simulate.Weakest(fs...)
	if r.Path.Outcome == routing.Local {
		r.Notes = append(r.Notes, noteLocal)
	}
	if len(r.Path.Hidden) > 0 {
		// Spec E17: a firewall that forwards without a router may sit on the path
		// unseen; the verdict does not include it.
		r.Notes = append(r.Notes, "firewalls that may sit on the path unseen are not checked: "+strings.Join(r.Path.Hidden, ", "))
	}
}

// describe names a hop for a note: "fw01 vsys1".
func describe(h routing.Hop) string { return strings.TrimSpace(h.Device + " " + h.Vsys) }
