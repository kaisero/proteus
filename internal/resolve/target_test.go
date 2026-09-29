package resolve

import (
	"testing"

	"github.com/okaiser/proteus/internal/config"
)

// A firewall's policy targets are its vsys, one each, keyed by device and vsys.
func TestTargetsAreKeyedByDeviceAndVsys(t *testing.T) {
	got := Targets(vsysLab(t))
	want := []string{
		"localhost.localdomain/vsys1",
		"localhost.localdomain/vsys2",
		"localhost.localdomain/vsys3",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d", len(got), len(want))
	}
	for i, tg := range got {
		if k := tg.Serial() + "/" + tg.Vsys(); k != want[i] {
			t.Errorf("target %d = %s, want %s", i, k, want[i])
		}
	}
}

func TestTargetForChain(t *testing.T) {
	tg, err := TargetFor(vsysLab(t), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	if got, want := tg.Scope().String(), "vsys:vsys1"; got != want {
		t.Errorf("scope = %q, want %q", got, want)
	}
	want := []string{"shared", "vsys:vsys1"}
	got := scopeStrings(tg.Chain())
	if len(got) != len(want) {
		t.Fatalf("chain = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chain[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestTargetForRejectsUnknown(t *testing.T) {
	cfg := vsysLab(t)
	if _, err := TargetFor(cfg, "no-such-device", "vsys1"); err == nil {
		t.Error("an unknown device must be an error")
	}
	_, err := TargetFor(cfg, "localhost.localdomain", "vsys9")
	if err == nil {
		t.Fatal("an unknown vsys must be an error")
	}
	if !contains(err.Error(), "vsys1") {
		t.Errorf("the error should name the vsys the device does have, got: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func scopeStrings(ss []config.Scope) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.String()
	}
	return out
}
