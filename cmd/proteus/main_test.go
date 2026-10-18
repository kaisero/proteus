package main

import (
	"runtime/debug"
	"testing"
)

func TestVersionOf(t *testing.T) {
	t.Parallel()
	vcs := func(rev, modified string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: rev}, {Key: "vcs.modified", Value: modified},
		}}
	}
	for _, tc := range []struct {
		name     string
		stamped  string
		info     *debug.BuildInfo
		ok       bool
		expected string
	}{
		{"a make build keeps its stamp", "v1.2.3", vcs("abc", "false"), true, "v1.2.3"},
		{"no build information", "dev", nil, false, "dev"},
		{"a module version", "dev", &debug.BuildInfo{Main: debug.Module{Version: "v0.4.0"}}, true, "v0.4.0"},
		{"a commit", "dev", vcs("0123456789abcdef0123", "false"), true, "0123456789ab"},
		{"a commit with local changes", "dev", vcs("0123456789abcdef0123", "true"), true, "0123456789ab-dirty"},
		{"a short revision", "dev", vcs("abc", "false"), true, "abc"},
		{"nothing to go on", "dev", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, "dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := versionOf(tc.stamped, tc.info, tc.ok); got != tc.expected {
				t.Errorf("got %q, want %q", got, tc.expected)
			}
		})
	}
}
