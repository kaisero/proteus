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
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol,omitempty"`
	Port        string `json:"port,omitempty"`
	SourcePort  int    `json:"source_port,omitempty"`
	Application string `json:"application,omitempty"`
	User        string `json:"user,omitempty"`
	URL         string `json:"url,omitempty"`
	FromZone    string `json:"from_zone,omitempty"`
	ToZone      string `json:"to_zone,omitempty"`
	// NoDNS leaves an FQDN unresolved.
	NoDNS bool `json:"no_dns,omitempty"`
}

// flow is the flow without its endpoints: protocol, ports, zones and the
// layer-7 fields. The port range is checked here.
func (f FlowInput) flow() (simulate.Flow, *UsageError) {
	out := simulate.Flow{
		Protocol: strings.ToLower(f.Protocol), Application: f.Application, User: f.User,
		URL: f.URL, FromZone: f.FromZone, ToZone: f.ToZone,
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
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	addrs, err := env.Resolve(ctx, ep.Name)
	if err != nil {
		env.Log.Warnf(runlog.TagRun, "dns: %s: %v", ep.Name, err)
		return ep, nil
	}
	for _, ad := range addrs {
		ep.Addrs = append(ep.Addrs, ad.Unmap())
	}
	ep.Resolved = len(ep.Addrs) > 0
	env.Log.Infof(runlog.TagRun, "dns: %s -> %v", ep.Name, ep.Addrs)
	return ep, nil
}

// pathEndpoint reads an endpoint for path mode. A path is traced from an
// address, so an FQDN must resolve to an IPv4 one: the first in the resolver's
// order is traced, and moves to the front (spec 2026-10-07 §3.3).
func pathEndpoint(ctx context.Context, env Env, s string, noDNS bool) (simulate.Endpoint, error) {
	ep, err := endpoint(ctx, env, s, noDNS)
	if err != nil || ep.Name == "" {
		return ep, err
	}
	for i, ad := range ep.Addrs {
		if ad.Is4() {
			rest := append(append([]netip.Addr{}, ep.Addrs[:i]...), ep.Addrs[i+1:]...)
			ep.Addrs = append([]netip.Addr{ad}, rest...)
			return ep, nil
		}
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
