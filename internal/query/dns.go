package query

import (
	"context"
	"net"
	"net/netip"
)

// SystemResolve resolves a name with this machine's resolver: IPv4 and IPv6,
// in the resolver's order (C3). It is the Env.Resolve of the command line and
// the server, so both trace the same address.
func SystemResolve(ctx context.Context, name string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
}

// SystemCanonicalName is a name's canonical name as this machine's resolver
// reports it (C2). The query trims the trailing dot.
func SystemCanonicalName(ctx context.Context, name string) (string, error) {
	return net.DefaultResolver.LookupCNAME(ctx, name)
}
