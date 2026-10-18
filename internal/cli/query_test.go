package cli

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// questions are the commands that ask the query layer, and whether each opens
// the store.
var questions = []struct {
	args  []string
	store bool
}{
	{[]string{"simulate", "policy", "198.18.1.10", "198.18.10.100"}, true},
	{[]string{"simulate", "policy", "10.1.0.5", "10.2.0.5", "--file", fixture("firewall-zones.xml"), "--vsys", "vsys1"}, false},
	{[]string{"simulate", "routing", "198.18.10.5", "8.8.8.8"}, true},
	{[]string{"simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw01"}, true},
	{[]string{"search", "198.18.10.100"}, true},
	{[]string{"lookup", "dc01"}, true},
	{[]string{"snapshot", "show"}, true},
	{[]string{"snapshot", "diff"}, true},
}

// A question stops at an inventory it cannot read, and at a store it cannot open,
// before it asks anything: exit 1 with the cause.
func TestQuestionsStopAtABrokenSetting(t *testing.T) {
	t.Parallel()
	for _, q := range questions {
		c := newCLI(t)
		c.inventory("version: 9\ndevices: []\n")
		if _, errOut, code := c.run(q.args...); code != exitError || !strings.Contains(errOut, "version 9") {
			t.Errorf("%v: unreadable inventory: exit %d\n%s", q.args, code, errOut)
		}
		if !q.store {
			continue
		}
		c = newCLI(t)
		c.inventory(inventoryFor("fw01.example.test", "fw02.example.test"))
		blocker := filepath.Join(c.dir, "blocker")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		c.env["PROTEUS_STORE"] = filepath.Join(blocker, "store")
		if _, errOut, code := c.run(q.args...); code != exitError || !strings.Contains(errOut, "store:") {
			t.Errorf("%v: no store: exit %d\n%s", q.args, code, errOut)
		}
	}
}

// A broken inventory wins over a bad port, as before the query layer.
func TestRoutingReadsSettingsBeforeItsInput(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory("version: 9\ndevices: []\n")
	if _, errOut, code := c.run("simulate", "routing", "198.18.10.5", "8.8.8.8", "--port", "bad"); code != exitError || !strings.Contains(errOut, "version 9") {
		t.Errorf("exit %d\n%s", code, errOut)
	}
}

// A question leaves no store behind: not on a usage error, and not on an
// answer from a store that does not exist.
func TestAQuestionCreatesNoStore(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor("fw01.example.test", "fw02.example.test"))
	c.want(2, "simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw09")
	c.want(3, "search", "10.0.0.1")
	if _, err := os.Stat(c.env["PROTEUS_STORE"]); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the store was created: %v", err)
	}
}

// One address decides a wildcard object, however it is written: as an address, a
// /32 or a range of one address, search finds the same objects, groups and rules
// and exits 0 (decision C1).
func TestOneAddressInEverySpellingDecidesAWildcard(t *testing.T) {
	t.Parallel()
	answer := func(term string) (string, string) {
		out := newCLI(t).want(0, "search", term, "--file", fixture("firewall-wildcard.xml"), "--output", "json")
		var doc map[string]json.RawMessage
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%s: %v\n%s", term, err, out)
		}
		return string(doc["results"]), string(doc["unresolved"])
	}
	want, _ := answer("10.88.7.1")
	if !strings.Contains(want, `"name": "wc"`) || !strings.Contains(want, `"name": "to-g-wc"`) {
		t.Fatalf("10.88.7.1 must find wc and the rules naming it:\n%s", want)
	}
	for _, term := range []string{"10.88.7.1/32", "10.88.7.1-10.88.7.1"} {
		if got, un := answer(term); got != want || un != "" && un != "[]" {
			t.Errorf("%s: results\n%s\nunresolved %s\nwant the results of 10.88.7.1:\n%s", term, got, un, want)
		}
	}
}
