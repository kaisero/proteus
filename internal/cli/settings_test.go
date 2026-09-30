package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingsLogTheirSource(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory("version: 1\ndefaults: {max_snapshot_age: 7d}\ndevices: []\n")
	c.env["PROTEUS_OUTPUT"] = "json"
	c.run("snapshot", "list", "fw01", "--color", "never") // the exit is not what this checks
	log := c.logFile()
	for _, want := range []string{
		"setting output=json from PROTEUS_OUTPUT",
		"setting max-age=7d from inventory",
		"setting color=never from flag",
		"setting log-level=info from default",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("run log misses %q:\n%s", want, log)
		}
	}
}

func TestABadSettingNamesItsSource(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, inv, env, want string
	}{
		{"env", "", "xml", `output "xml" (from PROTEUS_OUTPUT)`},
		{"inventory", "version: 1\ndefaults: {output: xml}\ndevices: []\n", "", `output "xml" (from inventory)`},
		{"color", "version: 1\ndefaults: {color: sometimes}\ndevices: []\n", "", `color "sometimes" (from inventory)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newCLI(t)
			if tc.inv != "" {
				c.inventory(tc.inv)
			}
			if tc.env != "" {
				c.env["PROTEUS_OUTPUT"] = tc.env
			}
			_, errOut, code := c.run("inventory", "init")
			if code != exitUsage || !strings.Contains(errOut, tc.want) {
				t.Errorf("exit %d, stderr %q; want 2 and %q", code, errOut, tc.want)
			}
		})
	}
}

func TestHomeExpandsFromEverySource(t *testing.T) {
	t.Parallel()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	c := newCLI(t)
	c.env["PROTEUS_STORE"] = "~/proteus-test-store-" + filepath.Base(c.dir)
	a := newApp(nil, nil, func(k string) string { return c.env[k] }, nil)
	a.configFlag = c.cfgPath
	if err := a.resolveSettings(); err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, "proteus-test-store-"+filepath.Base(c.dir)); a.storeRoot != want {
		t.Errorf("store = %q, want %q", a.storeRoot, want)
	}
}
