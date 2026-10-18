package config_test

import (
	"fmt"

	"github.com/kaisero/proteus/internal/config"
)

// Point the library at a configuration file and it reports what it is.
func Example() {
	cfg, rep, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		fmt.Println("load:", err)
		return
	}
	fmt.Printf("PAN-OS %s (%s)\n", cfg.Version(), cfg.DetailVersion())
	fmt.Printf("untyped elements: %d\n", len(rep.Untyped))
	// Output:
	// PAN-OS 11.2.0 (11.2.5)
	// untyped elements: 0
}

// WalkPaths yields every reference the configuration makes, with the scope it was
// made in. The same shared group means different things in different vsys, so the
// scope is part of the answer.
func ExampleConfig_WalkPaths() {
	cfg, _, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		fmt.Println("load:", err)
		return
	}
	_ = cfg.WalkPaths(func(e config.Event) bool {
		if e.Field != "source" {
			return true
		}
		fmt.Printf("%s names %v as its source\n", e.Scope, e.Values)
		return true
	})
	// Output:
	// vsys:vsys1 names [corp-location] as its source
}
