package codegen

import (
	"strings"
	"testing"
)

// Five of the six children of /config are sequences, not entry arrays. Without a
// root type the model cannot load a configuration file at all.
func TestConfigRootIsEmitted(t *testing.T) {
	shapes, ns := allShapes(t)
	src := Emit(ModelPackage, fixtureRoot(t), ns, shapes)
	block := typeBlock(t, src, "Config")

	for _, want := range []string{
		"Version string `xml:\"version,attr\"`",
		"DetailVersion string `xml:\"detail-version,attr\"`",
		"Shared *",
		"Devices *",
		"Readonly *",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("Config is missing %q, got:\n%s", want, block)
		}
	}
	if !strings.Contains(block, ReservedUntyped+" []RawNode") {
		t.Error("Config needs the escape hatch like any other struct")
	}
}

// The schema declares readonly as empty, so its generated type is empty too.
// parent-dg is not modelled anywhere; see AGENTS.md R8.
func TestReadonlyTypeIsEmpty(t *testing.T) {
	shapes, ns := allShapes(t)
	src := Emit(ModelPackage, fixtureRoot(t), ns, shapes)
	block := typeBlock(t, src, "Readonly")
	if strings.Contains(block, "ParentDg") {
		t.Error("parent-dg must not appear in the generated model")
	}
}

// The real schema has an inline sequence named "config", under
// mgt-config/users/entry/preferences/saved-log-query. It must not take the root
// type's name.
func TestRootNameIsReserved(t *testing.T) {
	shapes, ns := allShapes(t)
	for _, n := range ns {
		for _, nm := range append([]string{n.Canonical}, n.Aliases...) {
			for _, reserved := range reservedTypeNames {
				if nm == reserved {
					t.Errorf("shape at %s took the reserved name %s", n.Shallowest, reserved)
				}
			}
		}
	}
	src := Emit(ModelPackage, fixtureRoot(t), ns, shapes)
	if got := strings.Count(src, "\ntype Config struct {"); got != 1 {
		t.Errorf("Config declared %d times, want exactly 1", got)
	}
}
