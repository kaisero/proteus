package estate

import (
	"strings"
	"testing"
)

func TestRegistry(t *testing.T) {
	t.Parallel()
	if got := strings.Join(Kinds(), ","); got != "nat,policy,routing" {
		t.Errorf("Kinds = %s", got)
	}
	for k, s := range Simulations {
		if s.Kind() != k {
			t.Errorf("%s is registered as %s", s.Kind(), k)
		}
	}
}
