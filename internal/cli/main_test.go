package cli

import (
	"testing"

	"go.uber.org/goleak"
)

// The fetch fan-out and every command must end their goroutines.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
