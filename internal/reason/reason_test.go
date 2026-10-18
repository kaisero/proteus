package reason

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var classes = []Class{Doubt, Gap, Path, Zone, Default, DNS, Input, Note, Call, Verdict}

// codeShape is "<class>.<name>": lower case words joined by dashes, with dots
// between the parts.
var codeShape = regexp.MustCompile(`^[a-z]+(\.[a-z0-9]+(-[a-z0-9]+)*)+$`)

func TestRegistryIsSortedAndUnique(t *testing.T) {
	t.Parallel()
	reg := Registry()
	if len(reg) == 0 {
		t.Fatal("the registry is empty")
	}
	for i := 1; i < len(reg); i++ {
		if reg[i-1].Code >= reg[i].Code {
			t.Errorf("%q is not before %q", reg[i-1].Code, reg[i].Code)
		}
	}
}

func TestEveryEntryIsWellFormed(t *testing.T) {
	t.Parallel()
	for _, e := range Registry() {
		if !slices.Contains(classes, e.Class) {
			t.Errorf("%s: class %q is not a class", e.Code, e.Class)
		}
		if !codeShape.MatchString(string(e.Code)) {
			t.Errorf("%s: the code is not <class>.<name> in lower case", e.Code)
		}
		if !strings.HasPrefix(string(e.Code), string(e.Class)+".") {
			t.Errorf("%s: the code does not start with its class %q", e.Code, e.Class)
		}
		if e.Description == "" || strings.Contains(e.Description, "\n") {
			t.Errorf("%s: the description must be one non-empty line", e.Code)
		}
	}
}

// Every class has at least one code, so no class is declared for nothing.
func TestEveryClassHasACode(t *testing.T) {
	t.Parallel()
	for _, c := range classes {
		if !slices.ContainsFunc(Registry(), func(e Entry) bool { return e.Class == c }) {
			t.Errorf("class %q has no code", c)
		}
	}
}

// Spec §12 C7: every not-evaluated dimension has its own code, and no wildcard.
// C11: path.pbf-no-port is gone. gap.version is gone: one schema reads every
// version.
func TestRegistryHoldsTheCorrections(t *testing.T) {
	t.Parallel()
	for _, d := range []string{"zones", "source-zone", "destination-zone", "service", "url", "application", "user", "nat", "pbf"} {
		if !Known(Code("doubt.not-evaluated." + d)) {
			t.Errorf("doubt.not-evaluated.%s is missing", d)
		}
	}
	var notEvaluated int
	for _, e := range Registry() {
		if strings.HasPrefix(string(e.Code), "doubt.not-evaluated.") {
			notEvaluated++
		}
	}
	if notEvaluated != 9 {
		t.Errorf("%d not-evaluated codes, want 9", notEvaluated)
	}
	for _, c := range []Code{"doubt.imsi", "doubt.imei", "doubt.nw-slice", "doubt.saas-user-list", "doubt.saas-tenant-list", "verdict.rule", "verdict.default"} {
		if !Known(c) {
			t.Errorf("%s is missing", c)
		}
	}
	if Known("path.pbf-no-port") {
		t.Error("path.pbf-no-port is registered; PBF matching ignores the port")
	}
	if Known("gap.version") {
		t.Error("gap.version is registered; one schema reads every version")
	}
}

// specCodes are the codes spec §3.1 and its corrections in §12 name, by class.
// Each must stay registered: removing one fails here, not only at a producer.
var specCodes = map[Class][]string{
	Doubt: {
		"application", "service-application-default", "service-predefined", "service-absent",
		"service-no-port", "category-no-url", "category-undefined", "hip", "schedule", "edl",
		"region", "dynamic-group", "fqdn-resolution",
		"not-evaluated.zones", "not-evaluated.source-zone", "not-evaluated.destination-zone",
		"not-evaluated.service", "not-evaluated.url", "not-evaluated.application",
		"not-evaluated.user", "not-evaluated.nat", "not-evaluated.pbf",
		"imsi", "imei", "nw-slice", "saas-user-list", "saas-tenant-list",
	},
	Gap: {"fqdn-no-address", "object-unresolved", "load-failed", "snapshot-missing", "config-missing"},
	Path: {
		"left-estate", "left-by-interface", "loop", "too-long", "unresolved", "no-route", "ecmp",
		"pbf", "nat-undermatch", "nat-no-port", "start-default-route", "hidden-firewall",
	},
	Zone:    {"missing", "undefined", "placeholder", "vsys-unknown", "derived"},
	Default: {"precedence-unverified", "zones-unknown", "invalid-action", "vsys-missing"},
	DNS:     {"other-addresses", "canonical-name"},
	Input:   {"port", "protocol", "url", "device", "router", "from-zone", "to-zone"},
	Note:    {"snapshot-stale", "ha-peer", "local-services", "later-deny"},
	Call:    {"timeout", "busy", "usage", "choice", "internal"},
	Verdict: {"rule", "default", "relevant-route", "not-relevant"},
}

func TestEverySpecCodeIsRegistered(t *testing.T) {
	t.Parallel()
	class := map[Code]Class{}
	for _, e := range Registry() {
		class[e.Code] = e.Class
	}
	for c, names := range specCodes {
		for _, n := range names {
			code := Code(string(c) + "." + n)
			if got, ok := class[code]; !ok || got != c {
				t.Errorf("%s: registered %v, class %q; want class %q", code, ok, got, c)
			}
		}
	}
}

func TestRegistryReturnsACopy(t *testing.T) {
	t.Parallel()
	reg := Registry()
	first := reg[0].Code
	reg[0].Code = "changed.by-caller"
	if Registry()[0].Code != first {
		t.Error("a caller changed the registry")
	}
}

func TestNewKeepsCodeAndText(t *testing.T) {
	t.Parallel()
	r := New("doubt.service-no-port", "rule web matches service web-ports")
	if r.Code != "doubt.service-no-port" || r.Text != "rule web matches service web-ports" || r.String() != r.Text {
		t.Errorf("New = %+v", r)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"code":"doubt.service-no-port","text":"rule web matches service web-ports"}` {
		t.Errorf("JSON = %s", b)
	}
}

// The hook: in a test binary, New panics on a code the registry does not hold,
// so any package's tests fail when a producer uses one.
func TestNewPanicsOnAnUnregisteredCodeInATest(t *testing.T) {
	t.Parallel()
	defer func() {
		got, _ := recover().(string)
		if !strings.Contains(got, `"doubt.no-such-code"`) {
			t.Errorf("recover() = %q, want a panic naming the code", got)
		}
	}()
	New("doubt.no-such-code", "text")
	t.Error("New returned for an unregistered code")
}

// Outside a test binary, New keeps the code. The test flips strict, so it runs
// before the parallel tests resume.
//
//nolint:paralleltest // it changes the package's strict flag
func TestNewKeepsAnUnregisteredCodeInProduction(t *testing.T) {
	strict = false
	defer func() { strict = true }()
	if r := New("doubt.no-such-code", "text"); r.Code != "doubt.no-such-code" {
		t.Errorf("New = %+v", r)
	}
}
