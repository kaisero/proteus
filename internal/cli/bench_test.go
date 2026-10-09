package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"
)

// benchCommand runs one command per iteration, the way one CLI process runs it:
// a fresh app, the configuration read from the file, every index built for this
// run. R7: these back the figures for search and lookup on the largest fixture.
func benchCommand(b *testing.B, code int, args ...string) {
	b.Helper()
	dir := b.TempDir()
	env := map[string]string{
		"PROTEUS_STORE":   filepath.Join(dir, "store"),
		"PROTEUS_LOG_DIR": filepath.Join(dir, "log"),
	}
	args = append(args, "--config", filepath.Join(dir, "config.yaml"), "--output", "json")
	for b.Loop() {
		var out, errOut bytes.Buffer
		a := newApp(&out, &errOut, func(k string) string { return env[k] }, time.Now)
		if got := a.execute(context.Background(), args); got != code {
			b.Fatalf("exit %d, want %d: %s", got, code, errOut.String())
		}
	}
}

func BenchmarkSearchFile(b *testing.B) {
	benchCommand(b, 0, "search", "10.0.0.0/8", "--file", fixture("firewall-nat.xml"))
}

func BenchmarkLookupFile(b *testing.B) {
	benchCommand(b, 0, "lookup", "server", "--file", fixture("firewall-nat.xml"))
}
