package nat

import (
	"fmt"
	"math/big"
	"net/netip"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/rulebase"
)

// Port kinds of a translation.
const (
	PortUnchanged = "unchanged"
	PortRuntime   = "assigned at runtime"
)

// Translation is what a rule makes of one side of the packet.
type Translation struct {
	Kind string `json:"kind"`
	// Candidates are the addresses the device may choose from: one for a static
	// translation, a pool or an interface address otherwise (spec §18 N2).
	Candidates []string   `json:"candidates"`
	Address    netip.Addr `json:"address"`          // the one the answer follows
	Port       string     `json:"port"`             // PortUnchanged, PortRuntime, or a number
	Others     []string   `json:"others,omitempty"` // dynamic destination: not followed
	Fallback   []string   `json:"fallback,omitempty"`
}

// Result is a NAT answer: the match, both translations, the translated packet and
// the lookup of its destination.
type Result struct {
	MatchResult
	Source      *Translation      `json:"source,omitempty"`
	Destination *Translation      `json:"destination,omitempty"`
	PostNAT     *simulate.Forward `json:"post_nat,omitempty"` // after destination NAT (spec §18 F4)
	Flow        simulate.Flow     `json:"flow"`               // the packet as it leaves
}

// Translate applies a match to the packet.
func Translate(in Input, m MatchResult) Result {
	out := Result{MatchResult: m, Flow: in.Flow}
	if m.Rule == nil {
		return out
	}
	v, _ := rulebase.Load(func(string, string) (simulate.Target, error) { return in.Target, nil }, in.In.Device, in.Vsys)
	tr := translator{in: in, v: v, res: &out}
	if s := m.Rule.Source; s != nil {
		out.Source = tr.source(s, m.Rule)
		if out.Source != nil && out.Source.Address.IsValid() {
			out.Flow.Source = simulate.Addr(out.Source.Address)
		}
	}
	if d := m.Rule.Destination; d != nil {
		out.Destination = tr.destination(d, m.Rule)
		if out.Destination != nil && out.Destination.Address.IsValid() {
			out.Flow.Destination = simulate.Addr(out.Destination.Address)
			if p := out.Destination.Port; p != PortUnchanged {
				var n int
				_, _ = fmt.Sscanf(p, "%d", &n)
				out.Flow.DestPort = uint16(n) //nolint:gosec // a translated port is 1-65535 in the schema
			}
			if in.Lookup != nil {
				f := in.Lookup(out.Destination.Address)
				out.PostNAT = &f
				out.Fidelity = simulate.Weakest(out.Fidelity, f.Fidelity)
			}
		}
	}
	return out
}

type translator struct {
	in  Input
	v   rulebase.Vsys
	res *Result
}

func (t translator) unresolved(value, reason string) {
	t.res.Unresolved = append(t.res.Unresolved, index.Unresolved{Value: value, Reason: reason})
	t.res.Fidelity = simulate.Weakest(t.res.Fidelity, simulate.UnderMatch(reason))
}

// source translates the source (spec §18 F7).
func (t translator) source(s *resolve.SourceTranslation, r *Rule) *Translation {
	out := &Translation{Kind: s.Kind, Port: PortRuntime}
	switch s.Kind {
	case resolve.DIPP, resolve.PersistentDIPP, resolve.DynamicIP:
		out.Candidates = t.pool(s, r)
		if s.Kind == resolve.DynamicIP {
			out.Port = PortUnchanged
			if s.Fallback != nil {
				out.Fallback = t.pool(s.Fallback, r)
			} else {
				t.res.Notes = append(t.res.Notes, fmt.Sprintf("rule %s has no fallback: new sessions are dropped when its pool is exhausted", r.Name))
			}
		}
		out.Address = firstAddr(out.Candidates)
	case resolve.StaticIP:
		out.Port = PortUnchanged
		a, err := t.mapStatic(first(r.Fields["source"]), first(s.Addresses), sourceAddr(t.in.Flow.Source.Addrs))
		if err != "" {
			t.unresolved(r.Name, err)
			return out
		}
		out.Address, out.Candidates = a, []string{a.String()}
	default:
		t.unresolved(r.Name, fmt.Sprintf("rule %s translates the source as %s, which is not read yet", r.Name, strings.TrimPrefix(s.Kind, resolve.UnknownKind)))
	}
	return out
}

// pool is a source pool's candidates: its addresses, or its interface's address.
func (t translator) pool(s *resolve.SourceTranslation, r *Rule) []string {
	if s.Interface == "" && s.IPv6Interface != "" {
		t.unresolved(r.Name, fmt.Sprintf("rule %s translates to the IPv6 address of %s, which is not simulated", r.Name, s.IPv6Interface))
		return nil
	}
	if s.Interface != "" {
		if s.InterfaceIP != "" {
			return t.values(s.InterfaceIP, r, true)
		}
		for _, i := range t.in.Interfaces {
			if i.Name == s.Interface && i.Prefix.IsValid() {
				return []string{i.Prefix.Addr().String()}
			}
		}
		t.unresolved(r.Name, fmt.Sprintf("rule %s translates to the address of %s, which the interface state does not hold", r.Name, s.Interface))
		return nil
	}
	var out []string
	for _, a := range s.Addresses {
		out = append(out, t.values(a, r, false)...)
	}
	return out
}

// values reads an address, an address object or a static group into what it
// holds. A dynamic group or an external list is runtime content (spec §18 N2).
// hostOnly drops a prefix length: an interface address is written with its mask.
func (t translator) values(name string, r *Rule, hostOnly bool) []string {
	lit := func(v string) (string, bool) {
		if p, err := netip.ParsePrefix(v); err == nil && hostOnly {
			return p.Addr().String(), true
		}
		if len(index.PrefixesOf(v)) > 0 {
			return v, true
		}
		return "", false
	}
	if v, ok := lit(name); ok {
		return []string{v}
	}
	for _, kind := range []string{"address", "address-group"} {
		objs, _ := resolve.ObjectsInScope(t.v.Config, t.v.Scope, kind)
		for _, o := range objs {
			if o.Name != name {
				continue
			}
			if kind == "address" {
				if v, ok := lit(o.Value); ok {
					return []string{v}
				}
				return []string{o.Value} // an FQDN
			}
			var out []string
			for _, m := range strings.Split(o.Value, ", ") {
				if strings.Contains(m, "'") { // a dynamic group's filter
					t.unresolved(r.Name, fmt.Sprintf("rule %s uses dynamic group %s, whose members are known at runtime", r.Name, name))
					return nil
				}
				out = append(out, t.values(m, r, hostOnly)...)
			}
			return out
		}
	}
	t.unresolved(r.Name, fmt.Sprintf("rule %s uses %s, which is runtime content or not in the configuration", r.Name, name))
	return nil
}

// destination translates the destination (spec §18 F8).
func (t translator) destination(d *resolve.DestinationTranslation, r *Rule) *Translation {
	out := &Translation{Kind: d.Kind, Port: PortUnchanged}
	if d.Port > 0 {
		out.Port = fmt.Sprint(d.Port)
	}
	if d.DNSRewrite != "" {
		t.res.Notes = append(t.res.Notes, fmt.Sprintf("rule %s also rewrites DNS answers (%s), which is not simulated", r.Name, d.DNSRewrite))
	}
	if d.Kind == resolve.StaticDestination {
		a, err := t.mapStatic(first(r.Fields["destination"]), d.Address, t.in.Flow.Destination.Addrs[0])
		if err != "" {
			t.unresolved(r.Name, err)
			return out
		}
		out.Address, out.Candidates = a, []string{a.String()}
		return out
	}
	// Dynamic: an FQDN resolved by the caller, or an object's addresses. The lowest
	// is followed, the others named (spec §18 N2).
	var addrs []netip.Addr
	resolvedByDNS := false
	for _, v := range t.values(d.Address, r, false) {
		if pfx := index.PrefixesOf(v); len(pfx) > 0 {
			addrs = append(addrs, pfx[0].Addr())
			continue
		}
		addrs = append(addrs, t.in.Resolved[v]...)
		resolvedByDNS = true
	}
	if len(addrs) == 0 {
		t.unresolved(r.Name, fmt.Sprintf("rule %s translates to %s, which resolves to no address; the device then matches no rule for this flow", r.Name, d.Address))
		return out
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	addrs = slices.Compact(addrs)
	out.Address = addrs[0]
	for _, a := range addrs {
		out.Candidates = append(out.Candidates, a.String())
	}
	out.Others = out.Candidates[1:]
	if resolvedByDNS {
		t.res.Fidelity = simulate.Weakest(t.res.Fidelity, simulate.Inferred)
		t.res.Notes = append(t.res.Notes, fmt.Sprintf("%s resolved by this machine's DNS, which may answer differently from the firewall's", d.Address))
	}
	if len(out.Others) > 0 {
		t.res.Fidelity = simulate.Weakest(t.res.Fidelity, simulate.UnderMatch(fmt.Sprintf("rule %s distributes sessions (%s); followed %s, not %s", r.Name, d.Distribution, out.Address, strings.Join(out.Others, ", "))))
	}
	return out
}

// mapStatic translates a within original to the same offset within translated:
// one address to one, a range or netmask first to first (spec §18 F8, verified on
// fw01: 198.18.19.0/28 -> 198.18.250.32-198.18.250.47).
func (t translator) mapStatic(original, translated string, a netip.Addr) (netip.Addr, string) {
	tv := t.values(translated, &Rule{}, false)
	if len(tv) != 1 {
		return netip.Addr{}, "the translated address " + translated + " is not one address, range or netmask"
	}
	ts, tn, ok := span(tv[0])
	if !ok {
		return netip.Addr{}, "the translated address " + translated + " is not one address, range or netmask"
	}
	if tn == 1 {
		return ts, ""
	}
	if original == "any" || original == "" {
		return netip.Addr{}, "a static translation of " + original + " to " + translated + " is not simulated"
	}
	ov := t.values(original, &Rule{}, false)
	if len(ov) != 1 {
		return netip.Addr{}, "a static translation of " + original + " to " + translated + " is not simulated"
	}
	os, on, ok := span(ov[0])
	if !ok || on != tn || !a.IsValid() {
		return netip.Addr{}, "a static translation of " + original + " to " + translated + " is not simulated"
	}
	off := new(big.Int).Sub(new(big.Int).SetBytes(a.AsSlice()), new(big.Int).SetBytes(os.AsSlice()))
	if off.Sign() < 0 || off.Uint64() >= on {
		return netip.Addr{}, a.String() + " lies outside " + original
	}
	b := new(big.Int).Add(new(big.Int).SetBytes(ts.AsSlice()), off).FillBytes(make([]byte, len(ts.AsSlice())))
	out, _ := netip.AddrFromSlice(b)
	return out, ""
}

// span reads an address, a netmask or a range as its first address and size.
func span(v string) (netip.Addr, uint64, bool) {
	if a, err := netip.ParseAddr(v); err == nil {
		return a, 1, true
	}
	if p, err := netip.ParsePrefix(v); err == nil && p.Addr().Is4() {
		return p.Masked().Addr(), 1 << (32 - p.Bits()), true
	}
	lo, hi, ok := strings.Cut(v, "-")
	if !ok {
		return netip.Addr{}, 0, false
	}
	a, err1 := netip.ParseAddr(strings.TrimSpace(lo))
	b, err2 := netip.ParseAddr(strings.TrimSpace(hi))
	if err1 != nil || err2 != nil || !a.Is4() || !b.Is4() || b.Less(a) {
		return netip.Addr{}, 0, false
	}
	n := new(big.Int).Sub(new(big.Int).SetBytes(b.AsSlice()), new(big.Int).SetBytes(a.AsSlice()))
	return a, n.Uint64() + 1, true
}

// firstAddr is the first address a candidate list names.
func firstAddr(cands []string) netip.Addr {
	for _, c := range cands {
		if a, _, ok := span(c); ok {
			return a
		}
	}
	return netip.Addr{}
}

// FQDNs lists the names a rule's dynamic destination needs resolved, so a caller
// can fill Input.Resolved before Translate.
func FQDNs(in Input, r *Rule) []string {
	if r == nil || r.Destination == nil || r.Destination.Kind != resolve.DynamicDestination {
		return nil
	}
	v, _ := rulebase.Load(func(string, string) (simulate.Target, error) { return in.Target, nil }, in.In.Device, in.Vsys)
	res := &Result{}
	var out []string
	for _, val := range (translator{in: in, v: v, res: res}).values(r.Destination.Address, r, false) {
		if len(index.PrefixesOf(val)) == 0 {
			out = append(out, val)
		}
	}
	return out
}
