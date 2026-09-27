package index

import (
	"strconv"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/go-panos-schema/resolve"
)

// serviceResolver answers the service value space: which service objects cover a
// protocol and port.
//
// A service is a protocol and a set of port ranges, so containment here is interval
// containment rather than prefix containment. It is the same question the address
// resolver answers with a trie, asked of a different kind of value, which is why it
// is a separate resolver rather than a special case inside one.
type serviceResolver struct {
	services []serviceEntry
	rules    *rulesIndex
}

type serviceEntry struct {
	hit      Hit
	protocol string // tcp, udp, sctp
	ports    []portRange
}

type portRange struct{ lo, hi int }

func (p portRange) contains(n int) bool { return n >= p.lo && n <= p.hi }

func (p portRange) String() string {
	if p.lo == p.hi {
		return strconv.Itoa(p.lo)
	}
	return strconv.Itoa(p.lo) + "-" + strconv.Itoa(p.hi)
}

func newServiceResolver(objs []resolve.Object, rules *rulesIndex) *serviceResolver {
	r := &serviceResolver{rules: rules}
	for _, o := range objs {
		proto, ports, ok := strings.Cut(o.Value, "/")
		if !ok {
			continue
		}
		e := serviceEntry{
			hit:      Hit{Name: o.Name, Kind: o.Kind, Scope: o.Scope, Via: o.Value},
			protocol: strings.ToLower(proto),
			ports:    parsePortRanges(ports),
		}
		if len(e.ports) == 0 {
			continue
		}
		r.services = append(r.services, e)
	}
	return r
}

func (r *serviceResolver) kinds() []string { return []string{"service", "service-group"} }

func (r *serviceResolver) resolve(value string, _ Providers) ([]Hit, []Unresolved, bool) {
	proto, port, ok := parseServiceQuery(value)
	if !ok {
		return nil, nil, false
	}
	var hits []Hit
	for _, s := range r.services {
		if proto != "" && s.protocol != proto {
			continue
		}
		for _, pr := range s.ports {
			if pr.contains(port) {
				h := s.hit
				h.Via = s.protocol + "/" + pr.String()
				hits = append(hits, h)
				break
			}
		}
	}
	return hits, nil, true
}

// literalRules returns nothing. A rule's service field names a service or the
// keyword application-default; it never holds a port itself.
func (r *serviceResolver) literalRules(Field, string) *roaring.Bitmap { return roaring.New() }

func (r *serviceResolver) search(substr string) []Hit {
	want := strings.ToLower(substr)
	var out []Hit
	for _, s := range r.services {
		if strings.Contains(strings.ToLower(s.hit.Via), want) {
			out = append(out, s.hit)
		}
	}
	return out
}

// parseServiceQuery reads "tcp/443", "443/tcp" or a bare "443". A bare port matches
// any protocol, because a caller asking about a port usually does not know or care.
func parseServiceQuery(value string) (proto string, port int, ok bool) {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return "", 0, false
	}
	a, b, split := strings.Cut(v, "/")
	if !split {
		n, err := strconv.Atoi(v)
		if err != nil || !validPort(n) {
			return "", 0, false
		}
		return "", n, true
	}
	if n, err := strconv.Atoi(b); err == nil && isProtocol(a) && validPort(n) {
		return a, n, true
	}
	if n, err := strconv.Atoi(a); err == nil && isProtocol(b) && validPort(n) {
		return b, n, true
	}
	return "", 0, false
}

func isProtocol(s string) bool {
	return s == "tcp" || s == "udp" || s == "sctp"
}

func validPort(n int) bool { return n >= 0 && n <= 65535 }

// parsePortRanges reads a PAN-OS port list: comma separated, each a port or a
// low-high range.
func parsePortRanges(s string) []portRange {
	var out []portRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil || !validPort(a) {
			continue
		}
		if !isRange {
			out = append(out, portRange{lo: a, hi: a})
			continue
		}
		b, err := strconv.Atoi(strings.TrimSpace(hi))
		if err != nil || !validPort(b) || b < a {
			continue
		}
		out = append(out, portRange{lo: a, hi: b})
	}
	return out
}
