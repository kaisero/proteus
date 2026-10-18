package pathpolicy

import (
	"context"
	"testing"

	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/pathlab"
)

// BenchmarkPathWithNAT answers one path question across the two firewalls of
// the path fixture; the first hop has NAT rules. Each configuration is loaded
// once, as one run of the command loads it: the simulation is what is measured.
func BenchmarkPathWithNAT(b *testing.B) {
	l := lab{config: map[string][]byte{pathlab.FW02: withNAT(b)}, defaults: allowAll, predefined: true}
	env := l.env(b)
	load, loaded := env.Load, map[string]simulate.Target{}
	env.Load = func(device, vsys string) (simulate.Target, error) {
		if t, ok := loaded[device+"/"+vsys]; ok {
			return t, nil
		}
		t, err := load(device, vsys)
		if err == nil {
			loaded[device+"/"+vsys] = t
		}
		return t, err
	}
	in := input(pathlab.Destination)
	in.Flow.Protocol, in.Flow.DestPort = "tcp", 443
	b.ReportAllocs()
	for b.Loop() {
		r, _, err := Run(context.Background(), env, in)
		if err != nil || r.Verdict != VerdictAllowed {
			b.Fatalf("verdict %s, %v", r.Verdict, err)
		}
	}
}
