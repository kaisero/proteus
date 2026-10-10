package query

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
)

// dnsTimeout bounds one name's resolution. A server's call timeout must exceed it.
const dnsTimeout = 5 * time.Second

// FlowInput is a flow as asked: the endpoints as given, an address or an FQDN,
// and the port as text, 443 or tcp/443.
type FlowInput struct {
	Source      string `json:"source" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is checked"`
	Destination string `json:"destination" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is checked"`
	Protocol    string `json:"protocol,omitempty" jsonschema:"tcp, udp, icmp or sctp"`
	Port        string `json:"port,omitempty" jsonschema:"the destination port: 443, or tcp/443 with the protocol"`
	SourcePort  int    `json:"source_port,omitempty" jsonschema:"the source port"`
	Application string `json:"application,omitempty" jsonschema:"recorded, not evaluated; it does not change the answer"`
	User        string `json:"user,omitempty" jsonschema:"the source user, such as corp\\alice"`
	URL         string `json:"url,omitempty" jsonschema:"the URL; it decides URL categories"`
	FromZone    string `json:"from_zone,omitempty" jsonschema:"the source zone; derived when empty"`
	ToZone      string `json:"to_zone,omitempty" jsonschema:"the destination zone; derived when empty"`
	// NoDNS leaves an FQDN unresolved.
	NoDNS bool `json:"no_dns,omitempty" jsonschema:"leave a host name unresolved"`
}

// flow is the flow without its endpoints: protocol, ports, zones and the
// layer-7 fields. The port range is checked here, and that a destination is
// given: the command line always gives one, another caller may not.
func (f FlowInput) flow() (simulate.Flow, *UsageError) {
	out := simulate.Flow{
		Protocol: strings.ToLower(f.Protocol), Application: f.Application, User: f.User,
		URL: f.URL, FromZone: f.FromZone, ToZone: f.ToZone,
	}
	if strings.TrimSpace(f.Destination) == "" {
		return out, usage("give a destination", "")
	}
	if f.SourcePort < 0 || f.SourcePort > 65535 {
		return out, usage(fmt.Sprintf("--source-port %d is not a port", f.SourcePort),
			fmt.Sprintf("source_port %d is not a port", f.SourcePort))
	}
	out.SourcePort = uint16(f.SourcePort) //nolint:gosec // G115: range checked above
	if f.Port == "" {
		return out, nil
	}
	port := f.Port
	if proto, p, ok := strings.Cut(f.Port, "/"); ok {
		out.Protocol, port = strings.ToLower(proto), p
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return out, usage(fmt.Sprintf("--port %q: want 443 or tcp/443", f.Port), fmt.Sprintf("port %q: want 443 or tcp/443", f.Port))
	}
	out.DestPort = uint16(n)
	return out, nil
}

// endpoint reads a source or destination: an address, or an FQDN resolved with
// the env's resolver. A network is not an endpoint.
func endpoint(ctx context.Context, env Env, s string, noDNS bool) (simulate.Endpoint, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return simulate.Addr(addr), nil
	}
	if len(index.PrefixesOf(s)) > 0 {
		return simulate.Endpoint{}, usage(fmt.Sprintf("%q is a network, not an endpoint; simulate one address", s), "")
	}
	if !strings.Contains(s, ".") {
		return simulate.Endpoint{}, usage(fmt.Sprintf("%q is neither an address nor an FQDN", s), "")
	}
	ep := simulate.Endpoint{Name: strings.ToLower(s)}
	switch {
	case noDNS:
		env.Log.Infof(runlog.TagRun, "dns: %s not resolved (--no-dns)", ep.Name)
		return ep, nil
	case env.Resolve == nil:
		env.Log.Infof(runlog.TagRun, "dns: %s not resolved (no resolver)", ep.Name)
		return ep, nil
	}
	rctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	addrs, err := env.Resolve(rctx, ep.Name)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			// The call ended, not the lookup: the name is not known to have
			// no address.
			return ep, cerr
		}
		env.Log.Warnf(runlog.TagRun, "dns: %s: %v", ep.Name, err)
		return ep, nil
	}
	// The resolver answers IPv4 and IPv6 in its own order. A simulation that
	// follows one address takes the first, which must be IPv4, so the first
	// IPv4 address moves to the front and the rest keep their order (C3).
	var rest []netip.Addr
	for _, ad := range addrs {
		ad = ad.Unmap()
		if ad.Is4() && len(ep.Addrs) == 0 {
			ep.Addrs = append(ep.Addrs, ad)
			continue
		}
		rest = append(rest, ad)
	}
	ep.Addrs = append(ep.Addrs, rest...)
	ep.Resolved = len(ep.Addrs) > 0
	env.Log.Infof(runlog.TagRun, "dns: %s -> %v", ep.Name, ep.Addrs)
	if ep.Resolved {
		ep.Canonical = canonical(rctx, env, ep.Name)
	}
	return ep, nil
}

// canonical is the name's canonical name as the env's resolver reports it,
// or "" when it is the name itself or cannot be read. Resolvers differ: the
// cgo one reports the first alias of a chain, the pure Go one the last (C2).
func canonical(ctx context.Context, env Env, name string) string {
	if env.CanonicalName == nil {
		return ""
	}
	c, err := env.CanonicalName(ctx, name)
	if err != nil {
		env.Log.Warnf(runlog.TagRun, "dns: canonical name of %s: %v", name, err)
		return ""
	}
	c = strings.ToLower(strings.TrimSuffix(c, "."))
	if c == "" || c == name {
		return ""
	}
	env.Log.Infof(runlog.TagRun, "dns: %s is an alias of %s", name, c)
	return c
}

// pathEndpoint reads an endpoint for path mode. A path is traced from an
// address, so an FQDN must resolve to an IPv4 one: endpoint puts the first in
// front (spec 2026-10-07 §3.3).
func pathEndpoint(ctx context.Context, env Env, s string, noDNS bool) (simulate.Endpoint, error) {
	ep, err := endpoint(ctx, env, s, noDNS)
	if err != nil || ep.Name == "" || (len(ep.Addrs) > 0 && ep.Addrs[0].Is4()) {
		return ep, err
	}
	return ep, usage(fmt.Sprintf("path mode needs an address for %s; remove --no-dns or give an address", ep.Name),
		fmt.Sprintf("path mode needs an address for %s; set no_dns to false or give an address", ep.Name))
}

// endpoints resolves a flow's source, when one is given, and its destination. An
// FQDN that resolves to no address is a usage error: there is nothing to simulate.
func endpoints(ctx context.Context, env Env, flow *simulate.Flow, src, dst string, noDNS bool) error {
	var err error
	if src != "" {
		if flow.Source, err = endpoint(ctx, env, src, noDNS); err != nil {
			return err
		}
	}
	if flow.Destination, err = endpoint(ctx, env, dst, noDNS); err != nil {
		return err
	}
	for _, ep := range []simulate.Endpoint{flow.Source, flow.Destination} {
		if ep.Name != "" && len(ep.Addrs) == 0 {
			return usage(ep.Name+" resolved to no address", "")
		}
	}
	return nil
}
