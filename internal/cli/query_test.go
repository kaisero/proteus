package cli

import (
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
