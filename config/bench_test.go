package config

import "testing"

// Load parses the file and takes the schema from a process-wide cache. The first
// Load in a process also decodes the digest and builds the reference table, which
// together cost about 55 ms; every Load after that does not.
func BenchmarkLoad(b *testing.B) {
	for b.Loop() {
		if _, _, err := Load("../testdata/config/panorama-lab.xml"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWalk(b *testing.B) {
	cfg, _, err := Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		_ = cfg.Walk(func(Event) bool { return true })
	}
}

func BenchmarkBuildRefTable(b *testing.B) {
	cfg, _, err := Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		_ = buildRefTable(cfg.schema.root)
	}
}
