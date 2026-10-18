package config

import (
	"strings"
	"testing"
)

func TestReportEmpty(t *testing.T) {
	t.Parallel()
	var r Report
	if r.HasUnknown() {
		t.Error("an empty report has nothing unknown")
	}
	if got := r.String(); got != "no untyped elements" {
		t.Errorf("String = %q", got)
	}
}

func TestReportWithUntyped(t *testing.T) {
	t.Parallel()
	r := Report{Untyped: []Untyped{
		{XPath: "/config/shared/foo"},
		{XPath: "/config/shared/bar"},
	}}
	if !r.HasUnknown() {
		t.Error("a report with entries has something unknown")
	}
	got := r.String()
	if !strings.Contains(got, "2 untyped") || !strings.Contains(got, "/config/shared/foo") {
		t.Errorf("String = %q, want the count and the first path", got)
	}
}
