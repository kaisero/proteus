// Package nat is the NAT engine: which NAT rule a packet hits on one firewall and
// vsys, and the packet after translation (spec §18). It is pure: route lookups
// arrive through Input.Lookup and FQDNs through Input.Resolved, so the standalone
// simulation, the routing path and the security-policy simulation share it.
//
// PAN-OS behaviour it follows, each verified on fw01 on 2026-09-29 (spec §18.1):
// rules match the pre-NAT packet top down and the first match applies (F1, F16);
// the destination zone and interface are those of the pre-NAT route lookup (F3),
// a local address taking its owning interface (F15); a bi-directional static rule
// adds an implicit destination rule directly after itself (F9); security policy
// then matches pre-NAT addresses and port with post-NAT zones (F5, F6).
package nat

import (
	"encoding/json"
	"net/netip"

	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/rulebase"
)

// Rule is a NAT rule as the dataplane evaluates it: an explicit rule, or the
// implicit destination rule of a bi-directional one, which carries its origin's
// name (as `show running nat-policy` lists it).
type Rule struct {
	resolve.NATRule
	// Origin names the bi-directional rule an implicit rule comes from; empty for
	// an explicit rule.
	Origin string
	// explicit is the rule's position in the rulebase index; -1 for an implicit rule.
	explicit int
}

// Doubt is a rule above the match that could also have matched, and why the engine
// cannot tell (spec §18 N11). A rule can be in doubt for several reasons.
type Doubt struct {
	Rule    string
	Reasons simulate.Reasons
}

// Text is the reasons as one line: "the ingress zone is unknown; the source is
// unknown".
func (d Doubt) Text() string { return d.Reasons.Text() }

// MarshalJSON writes {"rule", "reason"}, the reasons joined, as format 1 does.
func (d Doubt) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
	}{d.Rule, d.Text()})
}

// Excluded is a rule above the match that did not match, and the field that
// excluded it; `--why` lists them.
type Excluded struct {
	Rule  string `json:"rule"`
	Field string `json:"field"`
}

// Input is one NAT question.
type Input struct {
	Target simulate.Target // the vsys's configuration
	Vsys   string          // the vsys name: vsys1
	Flow   simulate.Flow   // the pre-NAT packet
	In     simulate.Port   // the ingress interface and zone; a zone "" is unknown
	// Lookup is a route lookup in the ingress router.
	Lookup func(netip.Addr) simulate.Forward
	// Interfaces are the device's interface states, for an interface address
	// configured without an address.
	Interfaces []resolve.InterfaceState
	// Resolved holds FQDNs resolved by the caller.
	Resolved map[string][]netip.Addr
	// PreNAT is the caller's pre-NAT lookup; nil makes the engine call Lookup.
	PreNAT *simulate.Forward
}

// MatchResult is the rule a packet hits and what stood above it.
type MatchResult struct {
	Rule       *Rule              `json:"rule"` // nil: the packet leaves untranslated
	Doubts     []Doubt            `json:"doubts,omitempty"`
	Excluded   []Excluded         `json:"excluded,omitempty"`
	In         simulate.Port      `json:"in"` // the ingress the answer assumed
	PreNAT     simulate.Forward   `json:"pre_nat"`
	Dropped    string             `json:"dropped,omitempty"` // why no NAT applies at all
	Notes      simulate.Reasons   `json:"notes,omitempty"`
	Unresolved []index.Unresolved `json:"unresolved,omitempty"`
	Fidelity   simulate.Fidelity  `json:"fidelity"`

	// vsys is the configuration Match read the rule from. Translate and FQDNs use
	// it, so the vsys is loaded once and a rule never meets an empty configuration.
	vsys rulebase.Vsys
}
