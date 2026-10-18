package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/config"
)

func natRules(t *testing.T, file string) map[string]NATRule {
	t.Helper()
	cfg, _, err := config.Load("../../testdata/config/" + file)
	if err != nil {
		t.Fatal(err)
	}
	tgs := Targets(cfg)
	if len(tgs) != 1 {
		t.Fatalf("targets: %v", tgs)
	}
	out := map[string]NATRule{}
	for _, r := range tgs[0].NATRules() {
		out[r.Name] = r
	}
	return out
}

// fw01's test rules (spec §18.5), as the device showed them in its running NAT
// policy (testdata/opdata/fw01-running-nat-policy.xml).
func TestNATTranslationsOfFw01(t *testing.T) {
	t.Parallel()
	rs := natRules(t, "firewall-nat.xml")
	if r := rs["t-no-nat"]; r.Source != nil || r.Destination != nil {
		t.Errorf("t-no-nat translates: %+v", r)
	}
	if d := rs["t-dnat-port"].Destination; d == nil || d.Kind != StaticDestination || d.Address != "198.18.10.100" || d.Port != 443 {
		t.Errorf("t-dnat-port = %+v", d)
	}
	if r := rs["t-dnat-port"]; r.Service != "t-8443" {
		t.Errorf("t-dnat-port = %+v", r)
	}
	if s := rs["t-bidir"].Source; s == nil || s.Kind != StaticIP || !s.BiDirectional || s.Addresses[0] != "198.18.250.20" {
		t.Errorf("t-bidir = %+v", s)
	}
	if s := rs["t-static-block"].Source; s.Kind != StaticIP || s.Addresses[0] != "198.18.250.32/28" {
		t.Errorf("t-static-block = %+v", s)
	}
	if s := rs["t-pdipp"].Source; s.Kind != PersistentDIPP || s.Interface != "ethernet1/1" || s.InterfaceIP != "" {
		t.Errorf("t-pdipp = %+v", s)
	}
	s := rs["t-dip-pool"].Source
	if s.Kind != DynamicIP || s.Addresses[0] != "198.18.250.64/29" || s.Fallback == nil || s.Fallback.Kind != DIPP || s.Fallback.Interface != "ethernet1/1" {
		t.Errorf("t-dip-pool = %+v, fallback %+v", s, s.Fallback)
	}
	if d := rs["t-dnat-fqdn"].Destination; d.Kind != DynamicDestination || d.Address != "t-fqdn" || d.Distribution != "round-robin" || d.Port != 0 {
		t.Errorf("t-dnat-fqdn = %+v", d)
	}
	if s := rs["server-access"].Source; s.Kind != DIPP || s.Interface != "ethernet1/2" || s.InterfaceIP != "198.18.10.1/24" {
		t.Errorf("server-access = %+v", s)
	}
	if r := rs["internet-a"]; r.ToInterface != "ethernet1/1" || r.Source.InterfaceIP != "" {
		t.Errorf("internet-a = %+v", r)
	}
	if !rs["t-disabled"].Disabled {
		t.Error("t-disabled")
	}
}

// Shapes the lab does not carry, synthetic: an unknown kind, an HA binding, a
// dns-rewrite, dynamic-ip on an IPv6 interface, a floating address.
func TestNATTranslationShapes(t *testing.T) {
	t.Parallel()
	rs := natRules(t, "firewall-nat-shapes.xml")
	if s := rs["future"].Source; s == nil || s.Kind != UnknownKind+"magic-ip" {
		t.Errorf("future = %+v", s)
	}
	if r := rs["bound"]; r.HABinding != "primary" || r.Source.FloatingIP != "10.0.0.9" {
		t.Errorf("bound = %+v %+v", r, r.Source)
	}
	if d := rs["rewrite"].Destination; d.DNSRewrite != "reverse" || d.Address != "10.1.1.1" {
		t.Errorf("rewrite = %+v", d)
	}
	if s := rs["v6pool"].Source; s.Kind != DynamicIP || s.IPv6Interface != "ethernet1/9" || s.Interface != "" {
		t.Errorf("v6pool = %+v", s)
	}
	if d := rs["dyn-default"].Destination; d.Kind != DynamicDestination || d.Distribution != "round-robin" {
		t.Errorf("dyn-default = %+v", d)
	}
	if s := rs["empty"].Source; s != nil {
		t.Errorf("empty = %+v", s)
	}
	if s := rs["object-ip"].Source; s.InterfaceIP != "fw-public" {
		t.Errorf("object-ip = %+v", s)
	}
}

// A translated port that is not a port number keeps its text, so the NAT
// simulation can say so instead of reading it as "unchanged".
func TestATranslatedPortThatIsNoNumberIsKept(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("../../testdata/config/firewall-nat.xml")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"70000", "https"} {
		doc := strings.Replace(string(src), "<translated-port>443</translated-port>",
			"<translated-port>"+bad+"</translated-port>", 1)
		path := filepath.Join(t.TempDir(), "nat.xml")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, _, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		var d *DestinationTranslation
		for _, r := range Targets(cfg)[0].NATRules() {
			if r.Name == "t-dnat-port" {
				d = r.Destination
			}
		}
		if d == nil || d.Port != 0 || d.PortText != bad {
			t.Errorf("%s: destination translation = %+v", bad, d)
		}
	}
}
