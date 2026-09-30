package cli

import "testing"

// Spec §9.1, one case per row.
func TestUseColor(t *testing.T) {
	t.Parallel()
	env := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	for _, tc := range []struct {
		name string
		mode colorMode
		f    format
		env  func(string) string
		tty  bool
		want bool
	}{
		{"never", colorNever, formatText, env(), true, false},
		{"always", colorAlways, formatText, env("NO_COLOR", "1"), false, true},
		{"no-color", colorAuto, formatText, env("NO_COLOR", "1"), true, false},
		{"force", colorAuto, formatText, env("CLICOLOR_FORCE", "1"), false, true},
		{"force-0", colorAuto, formatText, env("CLICOLOR_FORCE", "0"), false, false},
		{"dumb", colorAuto, formatText, env("TERM", "dumb"), true, false},
		{"tty", colorAuto, formatText, env(), true, true},
		{"pipe", colorAuto, formatText, env(), false, false},
		{"json", colorAlways, formatJSON, env(), true, false},
		{"yaml", colorAlways, formatYAML, env("CLICOLOR_FORCE", "1"), true, false},
	} {
		if got := useColor(tc.mode, tc.f, tc.env, tc.tty); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPaletteAndWidth(t *testing.T) {
	t.Parallel()
	on, off := palette{on: true}, palette{}
	if off.bad("x") != "x" || on.bad("x") != "\x1b[31mx\x1b[0m" || on.bad("") != "" {
		t.Error("bad")
	}
	for _, tc := range []struct {
		name string
		fn   func(palette, string) string
		code string
	}{
		{"bad", palette.bad, "31"},
		{"warn", palette.warn, "33"},
		{"ok", palette.ok, "32"},
		{"head", palette.head, "1"},
		{"dim", palette.dim, "2"},
		{"accent", palette.accent, "36"},
	} {
		if off := tc.fn(off, "x"); off != "x" {
			t.Errorf("%s off: %q, want plain", tc.name, off)
		}
		want := "\x1b[" + tc.code + "mx\x1b[0m"
		if got := tc.fn(on, "x"); got != want {
			t.Errorf("%s on: %q, want %q", tc.name, got, want)
		}
		if got := tc.fn(on, ""); got != "" {
			t.Errorf("%s on empty: %q, want empty", tc.name, got)
		}
	}
	if visibleWidth(on.warn("abc")+"de") != 5 || visibleWidth("─┐") != 2 {
		t.Error("visibleWidth must ignore SGR sequences and count runes")
	}
}
