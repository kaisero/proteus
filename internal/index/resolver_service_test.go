package index

import "testing"

// A service is a protocol and a set of port ranges, so containment is interval
// containment. The same question the address resolver answers with a trie, asked of a
// different kind of value.
func TestServiceResolverMatchesAPortInARange(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	for _, q := range []string{"tcp/8050", "8050", "8050/tcp"} {
		_, rep := idx.Candidates(Service, q)
		if len(rep.Hits) != 1 || rep.Hits[0].Name != "svc-range" {
			t.Errorf("%s hits = %+v, want svc-range", q, rep.Hits)
			continue
		}
		if rep.Hits[0].Via != "tcp/8000-8100" {
			t.Errorf("%s Via = %q, want the range that matched", q, rep.Hits[0].Via)
		}
	}
}

// The boundaries of a range are inside it, and one past either end is not.
func TestServiceResolverRangeBoundaries(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	for _, in := range []string{"tcp/8000", "tcp/8100", "tcp/9000"} {
		if _, rep := idx.Candidates(Service, in); len(rep.Hits) == 0 {
			t.Errorf("%s should be covered by svc-range", in)
		}
	}
	for _, out := range []string{"tcp/7999", "tcp/8101", "tcp/8999"} {
		if _, rep := idx.Candidates(Service, out); len(rep.Hits) != 0 {
			t.Errorf("%s should not be covered, got %+v", out, rep.Hits)
		}
	}
}

// A protocol has to agree. The same port number on another protocol is a different
// service.
func TestServiceResolverRespectsTheProtocol(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	if _, rep := idx.Candidates(Service, "udp/53"); len(rep.Hits) != 1 || rep.Hits[0].Name != "svc-dns" {
		t.Errorf("udp/53 hits = %+v, want svc-dns", rep.Hits)
	}
	if _, rep := idx.Candidates(Service, "tcp/53"); len(rep.Hits) != 0 {
		t.Errorf("tcp/53 should not match a udp service, got %+v", rep.Hits)
	}
	// A bare port names no protocol, so it matches either.
	if _, rep := idx.Candidates(Service, "53"); len(rep.Hits) != 1 {
		t.Errorf("a bare port should match regardless of protocol, got %+v", rep.Hits)
	}
}

// A service group reaches its rule the same way an address group does, through the
// closure.
func TestServiceGroupReachesItsRule(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	rules, rep := idx.Candidates(Service, "tcp/8006")
	if !ruleNames(idx, rules)["svc-rule"] {
		t.Error("a rule naming a service group was not reached through the group")
	}
	var viaGroup bool
	for _, g := range rep.Groups {
		if g == "svc-grp" {
			viaGroup = true
		}
	}
	if !viaGroup {
		t.Errorf("the group was not reported in the path: %v", rep.Groups)
	}
}

// A value that is not a port is not this resolver's business, and must not be
// reported as a service.
func TestServiceResolverIgnoresNonPorts(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	for _, q := range []string{"tcp/notaport", "70000", "tcp/70000", "web-browsing"} {
		if _, rep := idx.Candidates(Service, q); len(rep.Hits) != 0 {
			t.Errorf("%s produced service hits: %+v", q, rep.Hits)
		}
	}
}

// A port no service covers reaches only the rules whose service is any, and that is a
// complete answer rather than an incomplete one.
func TestServiceResolverPortNothingCovers(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	_, rep := idx.Candidates(Service, "tcp/12345")
	if len(rep.Hits) != 0 {
		t.Errorf("hits = %+v, want none", rep.Hits)
	}
	if len(rep.Unresolved) != 0 {
		t.Errorf("a recognised port that matches nothing is a complete answer: %v", rep.Unresolved)
	}
}

// Searching finds a service by a fragment of its port specification.
func TestServiceResolverSearch(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	hits := idx.SearchValues("8000-8100")
	if len(hits) != 1 || hits[0].Name != "svc-range" {
		t.Errorf("search hits = %+v, want svc-range", hits)
	}
}

// A port specification the parser cannot read contributes no range, and the rest of
// the same object still works. A service with no protocol at all contributes nothing.
func TestServiceResolverSkipsUnreadablePorts(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat-edge.xml", "vsys1")

	// Reversed, non-numeric and out-of-range specifications yield no service.
	for _, q := range []string{"tcp/8500", "tcp/70000", "tcp/65535"} {
		if _, rep := idx.Candidates(Service, q); len(rep.Hits) != 0 {
			t.Errorf("%s matched an unreadable service: %+v", q, rep.Hits)
		}
	}
	// The readable parts of a mixed list still match.
	for _, q := range []string{"tcp/80", "tcp/150"} {
		_, rep := idx.Candidates(Service, q)
		if len(rep.Hits) != 1 || rep.Hits[0].Name != "svc-mixed" {
			t.Errorf("%s hits = %+v, want svc-mixed", q, rep.Hits)
		}
	}
	// And a well formed one is unaffected by its neighbours.
	if _, rep := idx.Candidates(Service, "tcp/443"); len(rep.Hits) != 1 {
		t.Errorf("tcp/443 hits = %+v, want svc-ok", rep.Hits)
	}
}
