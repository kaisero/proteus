package simulate

import (
	"fmt"
	"strings"

	"github.com/okaiser/proteus/internal/reason"
)

// DNSNotes names what this machine's resolver said about the flow's FQDNs
// beyond the addresses used, source first (spec 2026-10-09 §3.7, §12 C2, C3):
// the canonical name of an alias, and the addresses other than the first, which
// a simulation that follows one address leaves out. used says what the
// simulation did with the first address, "traced" or "checked"; empty leaves
// the other addresses out.
func DNSNotes(f Flow, used string) Reasons {
	var out Reasons
	for _, ep := range []Endpoint{f.Source, f.Destination} {
		if ep.Name == "" {
			continue
		}
		if ep.Canonical != "" {
			out = append(out, reason.New("dns.canonical-name",
				fmt.Sprintf("%s has the canonical name %s, as this machine's resolver reports it", ep.Name, ep.Canonical)))
		}
		if used != "" && len(ep.Addrs) > 1 {
			rest := make([]string, 0, len(ep.Addrs)-1)
			for _, a := range ep.Addrs[1:] {
				rest = append(rest, a.String())
			}
			out = append(out, reason.New("dns.other-addresses",
				fmt.Sprintf("%s resolved to %d addresses; %s %s, not %s", ep.Name, len(ep.Addrs), used, ep.Addrs[0], strings.Join(rest, ", "))))
		}
	}
	return out
}

// FirstAddresses is the flow with each endpoint cut to its first address, and
// the FQDN's name kept for matching FQDN objects. A simulation that follows one
// address uses the first, which a resolved name has IPv4 when it has one (spec
// 2026-10-07 §3.3, D1b); DNSNotes names the others. The flow itself is not
// changed.
func (f Flow) FirstAddresses() Flow {
	for _, ep := range []*Endpoint{&f.Source, &f.Destination} {
		if len(ep.Addrs) > 1 {
			ep.Addrs = ep.Addrs[:1:1]
		}
	}
	return f
}
