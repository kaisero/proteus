package fetch

import (
	"testing"

	"go.uber.org/goleak"
)

// Every fetch must end its goroutines: the HTTP transport's connection loops
// included, also after a cancelled run.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
