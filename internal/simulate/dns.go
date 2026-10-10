package simulate

import (
	"fmt"
	"strings"

	"github.com/okaiser/proteus/internal/reason"
)

// DNSNotes names what this machine's resolver said about the flow's FQDNs
// beyond the addresses used, source first (spec 2026-10-09 §3.7, §12 C2, C3):
// the canonical name of an alias, and, when traced is true, the addresses
// other than the first, which a simulation that follows one address leaves
// out.
func DNSNotes(f Flow, traced bool) Reasons {
	var out Reasons
	for _, ep := range []Endpoint{f.Source, f.Destination} {
		if ep.Name == "" {
			continue
		}
		if ep.Canonical != "" {
			out = append(out, reason.New("dns.canonical-name",
				fmt.Sprintf("%s has the canonical name %s, as this machine's resolver reports it", ep.Name, ep.Canonical)))
		}
		if traced && len(ep.Addrs) > 1 {
			rest := make([]string, 0, len(ep.Addrs)-1)
			for _, a := range ep.Addrs[1:] {
				rest = append(rest, a.String())
			}
			out = append(out, reason.New("dns.other-addresses",
				fmt.Sprintf("%s resolved to %d addresses; traced %s, not %s", ep.Name, len(ep.Addrs), ep.Addrs[0], strings.Join(rest, ", "))))
		}
	}
	return out
}
