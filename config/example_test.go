package config_test

import (
	"fmt"

	"github.com/okaiser/go-panos-schema/config"
)

// Point the library at a configuration file and it reports what it is.
func Example() {
	cfg, rep, err := config.Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		fmt.Println("load:", err)
		return
	}
	fmt.Printf("PAN-OS %s (%s), %s\n", cfg.Version(), cfg.DetailVersion(), cfg.Platform())
	fmt.Printf("untyped elements: %d\n", len(rep.Untyped))
	// Output:
	// PAN-OS 11.2.0 (11.2.7), panorama
	// untyped elements: 0
}

// Walk yields every reference the configuration makes, with the scope it was made
// in. The same shared group means different things in different device groups, so
// the scope is part of the answer.
func ExampleConfig_Walk() {
	cfg, _, err := config.Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		fmt.Println("load:", err)
		return
	}
	_ = cfg.Walk(func(e config.Event) bool {
		if e.Field != "source" {
			return true
		}
		fmt.Printf("%s names %v as its source\n", e.Scope, e.Values)
		return true
	})
	// Output:
	// dg:host_1_directory names [corp-location] as its source
}
