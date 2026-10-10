package config

import "testing"

func TestScopeString(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		s    Scope
		want string
	}{
		{Scope{Sort: ScopeShared}, "shared"},
		{Scope{Sort: ScopeVsys, Name: "vsys1"}, "vsys:vsys1"},
		{Scope{Sort: ScopePredefined}, "predefined"},
	} {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

func TestParseScope(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]Scope{
		"shared":     {Sort: ScopeShared},
		"vsys:vsys1": {Sort: ScopeVsys, Name: "vsys1"},
	} {
		got, err := ParseScope(in)
		if err != nil {
			t.Fatalf("ParseScope(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("ParseScope(%q) = %+v, want %+v", in, got, want)
		}
	}
	for _, bad := range []string{"", "nope", "vsys:", "shared:x", "dg:x", "tpl:x", "tplstack:x"} {
		if _, err := ParseScope(bad); err == nil {
			t.Errorf("ParseScope(%q) must fail", bad)
		}
	}
}

// A scope round-trips through its string form, which is what the index caches on.
func TestScopeRoundTrips(t *testing.T) {
	t.Parallel()
	for _, s := range []Scope{
		{Sort: ScopeShared},
		{Sort: ScopeVsys, Name: "vsys1"},
		{Sort: ScopePredefined},
	} {
		got, err := ParseScope(s.String())
		if err != nil {
			t.Fatalf("ParseScope(%q): %v", s.String(), err)
		}
		if got != s {
			t.Errorf("%+v round-tripped to %+v", s, got)
		}
	}
}
