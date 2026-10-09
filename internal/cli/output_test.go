package cli

import "testing"

// orList joins names the way a usage error lists them.
func TestOrList(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   []string
		want string
	}{{nil, ""}, {[]string{"a"}, "a"}, {[]string{"a", "b"}, "a or b"}, {[]string{"a", "b", "c"}, "a, b or c"}} {
		if got := orList(tc.in); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.in, got, tc.want)
		}
	}
}

// emptySlice prints [] for nil and for a nil slice, and keeps anything else.
func TestEmptySlice(t *testing.T) {
	t.Parallel()
	var none []int
	if got, ok := emptySlice(nil).([]any); !ok || got == nil {
		t.Errorf("nil: %#v", emptySlice(nil))
	}
	if got, ok := emptySlice(none).([]int); !ok || got == nil {
		t.Errorf("nil slice: %#v", emptySlice(none))
	}
	if got := emptySlice(3); got != 3 {
		t.Errorf("int: %#v", got)
	}
}
