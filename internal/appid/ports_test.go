package appid_test

import (
	"slices"
	"testing"

	"github.com/okaiser/proteus/internal/appid"
)

// flow is one protocol and port of a flow; port 0 gives none.
type flow struct {
	proto string
	port  uint16
}

// expectMatch fails when the default of app does not give want for each flow.
func expectMatch(t *testing.T, d *appid.Data, app string, want appid.PortMatch, flows ...flow) {
	t.Helper()
	a, ok := d.App(app)
	if !ok {
		t.Fatalf("the fixture lacks %s", app)
	}
	for _, f := range flows {
		if got := a.Default.Match(f.proto, f.port); got != want {
			t.Errorf("%s (%s) on %s/%d: %v, want %v", app, a.Default, f.proto, f.port, got, want)
		}
	}
}

// P1, F10: a port member gives its protocol and ports, also with spaces after
// the commas and as a range.
func TestDefaultPorts(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectMatch(t, d, "app-remote", appid.PortYes, flow{"tcp", 80}, flow{"tcp", 443}, flow{"tcp", 8090}, flow{"6", 443})
	expectMatch(t, d, "app-remote", appid.PortNo, flow{"tcp", 22}, flow{"udp", 443}, flow{"17", 443}, flow{"gre", 443})
	expectMatch(t, d, "app-remote", appid.PortOpen, flow{"tcp", 0}, flow{"", 443}, flow{"", 0})
	expectMatch(t, d, "app-remote", appid.PortNo, flow{"udp", 0})
	expectMatch(t, d, "app-range", appid.PortYes, flow{"tcp", 1025}, flow{"tcp", 1024}, flow{"udp", 1030})
	expectMatch(t, d, "app-range", appid.PortNo, flow{"tcp", 1023}, flow{"udp", 1031}, flow{"sctp", 1025})
}

// P2, F11: a /secure extended port matches as a secure port; a port that port
// also lists is a plain default port.
func TestDefaultSecurePort(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectMatch(t, d, "web-browsing", appid.PortSecure, flow{"tcp", 443})
	expectMatch(t, d, "web-browsing", appid.PortYes, flow{"tcp", 80})
	expectMatch(t, d, "web-browsing", appid.PortNo, flow{"tcp", 8080})
	expectMatch(t, d, "app-ldap", appid.PortSecure, flow{"tcp", 636}, flow{"tcp", 3269})
	expectMatch(t, d, "app-ldap", appid.PortYes, flow{"tcp", 389})
	expectMatch(t, d, "app-ldap", appid.PortOpen, flow{"tcp", 0})
	// The plain port wins when the extended list repeats it as secure.
	both := appid.Default{Ports: []appid.PortRange{
		{Protocol: "tcp", Low: 465, High: 465, Secure: true}, {Protocol: "tcp", Low: 465, High: 465},
	}}
	if got := both.Match("tcp", 465); got != appid.PortYes {
		t.Errorf("tcp/465 plain and secure: %v, want PortYes", got)
	}
	secureAny := appid.Default{Ports: []appid.PortRange{{Protocol: "tcp", AnyPort: true, Secure: true}}}
	if got := secureAny.Match("tcp", 9); got != appid.PortSecure {
		t.Errorf("a secure any port: %v, want PortSecure", got)
	}
}

// P3: tcp/dynamic and udp/dynamic mean any port of their protocol.
func TestDefaultDynamic(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectMatch(t, d, "app-dyn-tcp", appid.PortYes, flow{"tcp", 1}, flow{"tcp", 65535}, flow{"tcp", 0})
	expectMatch(t, d, "app-dyn-tcp", appid.PortNo, flow{"udp", 53}, flow{"udp", 0})
	expectMatch(t, d, "app-dyn-udp", appid.PortYes, flow{"udp", 53}, flow{"17", 0})
	expectMatch(t, d, "app-dyn-udp", appid.PortNo, flow{"tcp", 53})
}

// P11: tcp/80,dynamic and tcp/any mean any TCP port, not UDP.
func TestDefaultAnyTCP(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for _, app := range []string{"app-tcp-mixed", "app-tcp-any"} {
		expectMatch(t, d, app, appid.PortYes, flow{"tcp", 60000}, flow{"tcp", 80}, flow{"tcp", 0})
		expectMatch(t, d, app, appid.PortNo, flow{"udp", 60000})
	}
}

// P4: ident-by-ip-protocol N means protocol N with any port.
func TestDefaultIPProtocol(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectMatch(t, d, "ospf", appid.PortYes, flow{"89", 0}, flow{"89", 1})
	expectMatch(t, d, "ospf", appid.PortNo, flow{"6", 0}, flow{"tcp", 89})
	expectMatch(t, d, "ospf", appid.PortOpen, flow{"", 0})
}

// P5: ident-by-icmp-type means protocol 1 and ident-by-icmp6-type protocol
// 58, with any type.
func TestDefaultICMP(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectMatch(t, d, "ping", appid.PortICMP, flow{"icmp", 0}, flow{"1", 0})
	expectMatch(t, d, "ping", appid.PortNo, flow{"58", 0}, flow{"ipv6-icmp", 0}, flow{"tcp", 8})
	expectMatch(t, d, "ping6", appid.PortICMP, flow{"58", 0}, flow{"icmp6", 0})
	expectMatch(t, d, "ping6", appid.PortNo, flow{"1", 0}, flow{"icmp", 0})
}

// P11: icmp/dynamic means protocol 1, and icmp6/dynamic protocol 58.
func TestDefaultICMPAny(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectMatch(t, d, "app-icmp-any", appid.PortYes, flow{"1", 0}, flow{"58", 0}, flow{"icmp", 0})
	expectMatch(t, d, "app-icmp-any", appid.PortNo, flow{"tcp", 80}, flow{"89", 0})
}

// P6: an application without a default block matches every protocol and
// port, custom or predefined.
func TestDefaultNoneMatchesAll(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	all := []flow{{"tcp", 1}, {"udp", 53}, {"47", 0}, {"", 0}, {"", 443}}
	expectMatch(t, d, "app-nodefault", appid.PortYes, all...)
	custom := appid.Default{None: true}
	for _, f := range all {
		if got := custom.Match(f.proto, f.port); got != appid.PortYes {
			t.Errorf("Default{None} on %s/%d: %v", f.proto, f.port, got)
		}
	}
}

// P12: ident-by-dport does not change application-default.
func TestIdentDoesNotChangeTheDefault(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	if ssl, _ := d.App("ssl"); !ssl.Flags["ident-by-dport"] {
		t.Fatal("ssl lacks ident-by-dport in the fixture")
	}
	expectMatch(t, d, "ssl", appid.PortYes, flow{"tcp", 443})
	expectMatch(t, d, "ssl", appid.PortNo, flow{"tcp", 8443})
}

// Spec 2026-10-16 §4.1: the flow protocols of a default.
func TestDefaultProtocols(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for app, want := range map[string][]string{
		"ssl":           {"tcp"},
		"web-browsing":  {"tcp"},
		"app-range":     {"tcp", "udp"},
		"dns":           {"udp"},
		"ping":          {"icmp"},
		"ping6":         {"58"},
		"ospf":          {"89"},
		"app-icmp-any":  {"icmp", "58"},
		"app-nodefault": nil,
	} {
		a, _ := d.App(app)
		if got := a.Default.Protocols(); !slices.Equal(got, want) {
			t.Errorf("%s protocols %q, want %q", app, got, want)
		}
	}
	sctp := appid.Default{Ports: []appid.PortRange{{Protocol: "sctp", Low: 2905, High: 2905}}, IPProtocol: 6}
	if got := sctp.Protocols(); !slices.Equal(got, []string{"tcp", "sctp"}) {
		t.Errorf("sctp and protocol 6: %q", got)
	}
}

// The text of a default, for the app card.
func TestDefaultString(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for app, want := range map[string]string{
		"ssl":           "tcp/443",
		"app-remote":    "tcp/80,443,8090",
		"web-browsing":  "tcp/80; tcp/443/secure",
		"app-ldap":      "tcp/389; tcp/636,3269/secure",
		"app-range":     "tcp/1024-1030; udp/1024-1030",
		"app-tcp-mixed": "tcp/80,any",
		"app-dyn-udp":   "udp/any",
		"app-icmp-any":  "icmp/any; icmp6/any",
		"ospf":          "ip-protocol/89",
		"ping":          "icmp-type",
		"ping6":         "icmp6-type",
		"app-nodefault": "any",
	} {
		a, _ := d.App(app)
		if got := a.Default.String(); got != want {
			t.Errorf("%s: %q, want %q", app, got, want)
		}
	}
}

// P4, P5: protocol names and numbers.
func TestProtocolNumber(t *testing.T) {
	t.Parallel()
	for p, want := range map[string]int{
		"tcp": 6, "udp": 17, "sctp": 132, "icmp": 1, "icmp6": 58, "ipv6-icmp": 58,
		"TCP": 6, "0": 0, "89": 89, "255": 255,
	} {
		if got, ok := appid.ProtocolNumber(p); !ok || got != want {
			t.Errorf("ProtocolNumber(%q) = %d, %v; want %d", p, got, ok, want)
		}
	}
	for _, p := range []string{"300", "x", "", "-1"} {
		if got, ok := appid.ProtocolNumber(p); ok {
			t.Errorf("ProtocolNumber(%q) = %d, ok", p, got)
		}
	}
}

// PortMatch names its value.
func TestPortMatchString(t *testing.T) {
	t.Parallel()
	for m, want := range map[appid.PortMatch]string{
		appid.PortNo: "no", appid.PortYes: "yes", appid.PortSecure: "secure",
		appid.PortICMP: "icmp", appid.PortOpen: "open", appid.PortMatch(99): "PortMatch(99)",
	} {
		if got := m.String(); got != want {
			t.Errorf("%d: %q, want %q", int(m), got, want)
		}
	}
}

// P7: a custom application takes its default from the configuration, in the
// forms of P1-P5; without a form it allows everything (P6).
func TestCustomDefault(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		ports       []string
		ip          string
		icmp, icmp6 bool
		want        string
	}{
		{[]string{"tcp/8443"}, "", false, false, "tcp/8443"},
		{[]string{"tcp/80,443", "udp/dynamic"}, "", false, false, "tcp/80,443; udp/any"},
		{nil, "89", false, false, "ip-protocol/89"},
		{nil, "", true, false, "icmp-type"},
		{nil, "", false, true, "icmp6-type"},
		{nil, "", false, false, "any"},
	} {
		d, err := appid.CustomDefault(tc.ports, tc.ip, tc.icmp, tc.icmp6)
		if err != nil || d.String() != tc.want {
			t.Errorf("CustomDefault(%v, %q, %v, %v) = %q, %v; want %q", tc.ports, tc.ip, tc.icmp, tc.icmp6, d, err, tc.want)
		}
	}
	// A custom port member has no /secure form.
	for _, bad := range [][]string{{"tcp/x"}, {"tcp/443/secure"}} {
		if _, err := appid.CustomDefault(bad, "", false, false); err == nil {
			t.Errorf("CustomDefault(%v): want an error", bad)
		}
	}
	if _, err := appid.CustomDefault(nil, "300", false, false); err == nil {
		t.Error("ident-by-ip-protocol 300: want an error")
	}
}
