package resolve

import "testing"

// The key is (serial, vsys), never serial. One firewall had vsys2 in at-ooe and
// vsys3 in at-ktn, so keying by serial merges two different policies.
// Observed on Panorama 11.2.7-h1.
func TestTargetsAreKeyedBySerialAndVsys(t *testing.T) {
	got, err := Targets(lab(t))
	if err != nil {
		t.Fatalf("Targets: %v", err)
	}
	type key struct{ serial, vsys string }
	byKey := map[key]string{}
	for _, tg := range got {
		byKey[key{tg.Serial(), tg.Vsys()}] = tg.DeviceGroup()
	}
	want := map[key]string{
		{"007900000000004", "vsys3"}: "at-ktn",
		{"007900000000004", "vsys2"}: "at-ooe",
		{"007900000000003", "vsys1"}: "host_1_directory",
	}
	if len(byKey) != len(want) {
		t.Fatalf("got %d targets, want %d: %+v", len(byKey), len(want), byKey)
	}
	for k, w := range want {
		if byKey[k] != w {
			t.Errorf("%s/%s -> %q, want %q", k.serial, k.vsys, byKey[k], w)
		}
	}
}

func TestTargetForChainAndTemplateStack(t *testing.T) {
	tg, err := TargetFor(lab(t), "007900000000003", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	if got, want := tg.Scope().String(), "dg:host_1_directory"; got != want {
		t.Errorf("scope = %q, want %q", got, want)
	}
	want := []string{"shared", "dg:corp", "dg:host_1_directory"}
	got := scopeStrings(tg.Chain())
	if len(got) != len(want) {
		t.Fatalf("chain = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chain[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if tg.TemplateStack() != "s_corp" {
		t.Errorf("template stack = %q, want s_corp", tg.TemplateStack())
	}
}

func TestTargetForRejectsUnknown(t *testing.T) {
	cfg := lab(t)
	if _, err := TargetFor(cfg, "000000000000000", "vsys1"); err == nil {
		t.Error("an unknown serial must be an error")
	}
	_, err := TargetFor(cfg, "007900000000003", "vsys9")
	if err == nil {
		t.Fatal("an unknown vsys must be an error")
	}
	if !contains(err.Error(), "vsys1") {
		t.Errorf("the error should name the vsys the serial does have, got: %v", err)
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
