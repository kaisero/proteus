package fetch

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/fakepanos"
	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/task"
)

// identityCmds are the identity commands of a fetch whose table fits one
// page, in the order of spec 2026-10-17 §3.2, as the fake device names them.
var identityCmds = []string{
	fakepanos.GroupMappingStatsCmd, fakepanos.GroupMappingStateCmd, fakepanos.CIEStatusCmd,
	fakepanos.UserIDsCmd, fakepanos.UserAttributesCmd, fakepanos.GroupListCmd,
	fakepanos.DUGListCmd, fakepanos.RegisteredUsersCmd, fakepanos.MappingPageCmd(10000, 1),
}

// identityData reads the identity file of a fetch.
func identityData(t *testing.T, s State) *identity.Data {
	t.Helper()
	if s.Result.Identity == nil {
		t.Fatal("no identity file")
	}
	d, err := identity.Read(bytes.NewReader(s.Result.Identity))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// identityFile is the identity file of a fetch.
func identityFile(t *testing.T, s State) identity.File {
	t.Helper()
	return identityData(t, s).File()
}

// opCmds are the op commands the device received, in order.
func opCmds(d *fakepanos.Device) []string {
	var out []string
	for _, r := range d.Requests() {
		if r.Type == "op" {
			out = append(out, r.Cmd)
		}
	}
	return out
}

// sourceOf is the source of a group of the file, or "" when the file does not
// list the group.
func sourceOf(f identity.File, group string) string {
	for _, g := range f.Groups {
		if g.Name == group {
			return g.Source
		}
	}
	return ""
}

// Each identity command of fetch is the fake device's, and so is the first
// page of the mapping table.
func TestTheFakeDeviceAsksTheSameCommands(t *testing.T) {
	t.Parallel()
	var ours []string
	for _, c := range identityCalls {
		ours = append(ours, c.cmd)
	}
	ours = append(ours, fmt.Sprintf(mappingPageCmd, 10000, 1))
	if !slices.Equal(ours, identityCmds) {
		t.Errorf("fetch asks\n%q\nthe fake device answers\n%q", ours, identityCmds)
	}
	if mappingPage != 10000 {
		t.Errorf("page size %d; U1 takes a limit of up to 10,000", mappingPage)
	}
}

// After the App-ID data, the step asks the eight commands of spec §3.2 and one
// page of the mapping table, in that order, and keeps one identity file with
// the data of the fake device's answers (§3.1, §3.2, SG1).
func TestIdentityStepAsksEveryPartInOrder(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	start := time.Now()
	s, steps := fetched(t, d)
	cmds := opCmds(d)
	i := slices.Index(cmds, fakepanos.ContainersCmd)
	if i < 1 || cmds[i-1] != fakepanos.ApplicationsCmd || !slices.Equal(cmds[i+1:], identityCmds) {
		t.Errorf("op commands:\n%q", cmds)
	}
	r := steps["identity"]
	if r.Status != task.OK || r.Detail != "9 calls: 4 users, 8 groups, 6 mappings in 1 page, 2 sources" || len(r.Notes) != 0 {
		t.Errorf("identity step = %+v", r)
	}
	data := identityData(t, s)
	f := data.File()
	if got, want := data.Counts(), (identity.Counts{Users: 4, Groups: 8, Memberships: 9, Mappings: 6, Tags: 2, TagPairs: 3}); got != want {
		t.Errorf("counts = %+v, want %+v", got, want)
	}
	// U6 statistics and state join by profile, so each LDAP group takes its
	// profile by base; the longest base wins.
	wantLDAP := []identity.LDAPSource{
		{Name: "branch", Base: "ou=branch,dc=example,dc=com", Groups: 1},
		{Name: "example.com", Base: "dc=example,dc=com", Groups: 3},
	}
	if !slices.Equal(f.Sources.LDAP, wantLDAP) || len(f.Sources.CIE) != 0 {
		t.Errorf("sources = %+v", f.Sources)
	}
	for group, want := range map[string]string{
		`cn=branch staff,ou=branch,dc=example,dc=com`: "ldap:branch",
		`cn=domain users,cn=users,dc=example,dc=com`:  "ldap:example.com",
		"dug-a":       "dug",
		"engineering": "xmlapi",
	} {
		if got := sourceOf(f, group); got != want {
			t.Errorf("%s: source %q, want %q", group, got, want)
		}
	}
	if !slices.Equal(f.DUGs, []string{"dug-a", "dug-ab"}) || len(f.PartsMissing) != 0 || f.MappingsPartial {
		t.Errorf("dugs %v, missing %v, partial %v", f.DUGs, f.PartsMissing, f.MappingsPartial)
	}
	// U8 alone gives a user without groups (D13).
	dave, ok := data.User(`example.com\dave`)
	if !ok || !slices.Equal(dave.Alt, []string{"dave@example.com"}) || len(dave.Groups) != 0 {
		t.Errorf("dave = %+v, %v", dave, ok)
	}
	if f.TakenAt.Before(start) || f.TakenAt.After(time.Now()) {
		t.Errorf("taken at %s, not during the fetch", f.TakenAt)
	}
}

// The default fake device misses no part: its CIE answer lists no profile, so
// no profile needs a domain (spec §3.4, SG2).
func TestIdentityStepDefaultHasNoMissingPart(t *testing.T) {
	t.Parallel()
	s, steps := fetched(t, device())
	if f := identityFile(t, s); len(f.PartsMissing) != 0 || f.MappingsPartial {
		t.Errorf("missing %v, partial %v", f.PartsMissing, f.MappingsPartial)
	}
	if codes(s) != "" || len(steps["identity"].Notes) != 0 || steps["identity"].Status != task.OK {
		t.Errorf("notes %s, step %+v", codes(s), steps["identity"])
	}
}

// entry is one mapping of U1 in the layout of X1.
func entry(ip, user string) string {
	return "<entry><ip>" + ip + "</ip><vsys>vsys1</vsys><type>XMLAPI</type><user>" + user +
		"</user><timeout>14400</timeout><origin>203.0.113.5</origin></entry>\n"
}

// page is a page of U1 in the layout of X1: its entries, then count and
// total.
func page(total int, entries ...string) string {
	return fakepanos.Success(strings.Join(entries, "") + fmt.Sprintf("<count>%d</count>\n<total>%d</total>\n", len(entries), total))
}

// pagesAsked are the pages of the mapping table the device received, in
// order.
func pagesAsked(d *fakepanos.Device) []string {
	return slices.DeleteFunc(opCmds(d), func(c string) bool {
		return !strings.HasPrefix(c, "<show><user><ip-user-mapping-mp>")
	})
}

// addresses are the addresses of the mappings of a file with their users, in
// the order of the file.
func addresses(f identity.File) []string {
	var out []string
	for _, m := range f.Mappings {
		out = append(out, m.IP.String()+" "+m.User)
	}
	return out
}

// pageSize sets the page size of the mapping table.
func pageSize(n int) func(*State) { return func(s *State) { s.mappingPage = n } }

// The step reads the table in pages from start-point 1, each one limit
// entries further on, until it holds total entries (spec 2026-10-17 U1,
// §3.2).
func TestIdentityStepPagesTheMappings(t *testing.T) {
	t.Parallel()
	t.Run("five entries", func(t *testing.T) {
		t.Parallel()
		d := fullDevice(t)
		d.Ops[fakepanos.MappingPageCmd(2, 1)] = page(5, entry("198.51.100.1", `example.com\alice`), entry("198.51.100.2", `example.com\bob`))
		d.Ops[fakepanos.MappingPageCmd(2, 3)] = page(5, entry("198.51.100.3", `example.com\carol`), entry("198.51.100.4", `example.com\dave`))
		d.Ops[fakepanos.MappingPageCmd(2, 5)] = page(5, entry("198.51.100.5", `other\ghost`))
		s, steps := fetched(t, d, pageSize(2))
		want := []string{fakepanos.MappingPageCmd(2, 1), fakepanos.MappingPageCmd(2, 3), fakepanos.MappingPageCmd(2, 5)}
		if got := pagesAsked(d); !slices.Equal(got, want) {
			t.Errorf("pages %q", got)
		}
		if f := identityFile(t, s); len(f.Mappings) != 5 || f.MappingsPartial || codes(s) != "" {
			t.Errorf("mappings %q, partial %v, notes %s", addresses(f), f.MappingsPartial, codes(s))
		}
		if r := steps["identity"]; r.Detail != "11 calls: 4 users, 8 groups, 5 mappings in 3 pages, 2 sources" {
			t.Errorf("identity step = %+v", r)
		}
	})
	t.Run("a full last page", func(t *testing.T) {
		t.Parallel()
		d := fullDevice(t)
		d.Ops[fakepanos.MappingPageCmd(2, 1)] = page(4, entry("198.51.100.1", `example.com\alice`), entry("198.51.100.2", `example.com\bob`))
		d.Ops[fakepanos.MappingPageCmd(2, 3)] = page(4, entry("198.51.100.3", `example.com\carol`), entry("198.51.100.4", `example.com\dave`))
		s, _ := fetched(t, d, pageSize(2))
		if got := pagesAsked(d); !slices.Equal(got, []string{fakepanos.MappingPageCmd(2, 1), fakepanos.MappingPageCmd(2, 3)}) {
			t.Errorf("pages %q", got)
		}
		if f := identityFile(t, s); len(f.Mappings) != 4 || f.MappingsPartial || codes(s) != "" {
			t.Errorf("mappings %q, partial %v, notes %s", addresses(f), f.MappingsPartial, codes(s))
		}
	})
}

// A page shorter than the limit ends the read, whatever total says (spec
// §3.2). A read that holds fewer entries than total did not see the whole
// table, so the table counts as moved: it is partial, with the note (ruling
// T7-I1, SG13, PD19).
func TestIdentityStepStopsAtAShortPage(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Ops[fakepanos.MappingPageCmd(2, 1)] = page(9, entry("198.51.100.1", `example.com\alice`), entry("198.51.100.2", `example.com\bob`))
	d.Ops[fakepanos.MappingPageCmd(2, 3)] = page(9, entry("198.51.100.3", `example.com\carol`))
	s, _ := fetched(t, d, pageSize(2))
	if got := pagesAsked(d); !slices.Equal(got, []string{fakepanos.MappingPageCmd(2, 1), fakepanos.MappingPageCmd(2, 3)}) {
		t.Errorf("pages %q", got)
	}
	if f := identityFile(t, s); len(f.Mappings) != 3 || !f.MappingsPartial || codes(s) != "note.identity-mappings-moved" {
		t.Errorf("mappings %q, partial %v, notes %s", addresses(f), f.MappingsPartial, codes(s))
	}
}

// An insert and a delete between two pages keep total, but shift the later
// page: one entry comes twice and one is not read. The read then holds fewer
// entries than total, so the table counts as moved, and the later entry of
// the repeated address wins (ruling T7-I1, spec §3.2, SG13).
func TestIdentityStepNotesAShiftedTable(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Ops[fakepanos.MappingPageCmd(2, 1)] = page(4, entry("198.51.100.1", `example.com\alice`), entry("198.51.100.2", `example.com\bob`))
	d.Ops[fakepanos.MappingPageCmd(2, 3)] = page(4, entry("198.51.100.2", `example.com\carol`), entry("198.51.100.3", `example.com\dave`))
	d.Ops[fakepanos.MappingPageCmd(2, 5)] = page(4)
	s, _ := fetched(t, d, pageSize(2))
	if got := len(pagesAsked(d)); got != 3 {
		t.Errorf("%d pages", got)
	}
	f := identityFile(t, s)
	want := []string{`198.51.100.1 example.com\alice`, `198.51.100.2 example.com\carol`, `198.51.100.3 example.com\dave`}
	if !slices.Equal(addresses(f), want) || !f.MappingsPartial || codes(s) != "note.identity-mappings-moved" {
		t.Errorf("mappings %q, partial %v, notes %s", addresses(f), f.MappingsPartial, codes(s))
	}
}

// When total changes between pages, the step keeps every page, the later
// entry of an address wins, and the table is partial, with a note (spec
// §3.2, SG13).
func TestIdentityStepNotesMovedMappings(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Ops[fakepanos.MappingPageCmd(2, 1)] = page(4, entry("198.51.100.1", `example.com\alice`), entry("198.51.100.2", `example.com\bob`))
	d.Ops[fakepanos.MappingPageCmd(2, 3)] = page(5, entry("198.51.100.2", `example.com\carol`), entry("198.51.100.3", `example.com\dave`))
	d.Ops[fakepanos.MappingPageCmd(2, 5)] = page(5, entry("198.51.100.4", `other\ghost`))
	s, steps := fetched(t, d, pageSize(2))
	if got := len(pagesAsked(d)); got != 3 {
		t.Errorf("%d pages", got)
	}
	f := identityFile(t, s)
	want := []string{`198.51.100.1 example.com\alice`, `198.51.100.2 example.com\carol`, `198.51.100.3 example.com\dave`, `198.51.100.4 other\ghost`}
	if !slices.Equal(addresses(f), want) || !f.MappingsPartial {
		t.Errorf("mappings %q, partial %v", addresses(f), f.MappingsPartial)
	}
	if codes(s) != "note.identity-mappings-moved" || len(steps["identity"].Notes) != 1 ||
		s.Result.Notes[0].Text != "the mapping table changed while it was read in pages, so the snapshot can miss a mapping or hold an old one" {
		t.Errorf("notes %+v, step %+v", s.Result.Notes, steps["identity"])
	}
}

// A table larger than the cap keeps its first entries, and it is partial,
// with a note (spec §3.2, SG13). No page starts after the cap. The cap is the
// start-point limit of U1.
func TestIdentityStepCutsAtTheCap(t *testing.T) {
	t.Parallel()
	if mappingCap != 512000 {
		t.Errorf("cap %d; U1 takes a start-point of up to 512,000", mappingCap)
	}
	capAt := func(n int) func(*State) { return func(s *State) { s.mappingCap = n } }
	t.Run("a page over the cap", func(t *testing.T) {
		t.Parallel()
		d := fullDevice(t)
		s, _ := fetched(t, d, capAt(4))
		if got := pagesAsked(d); !slices.Equal(got, []string{fakepanos.MappingPageCmd(10000, 1)}) {
			t.Errorf("pages %q", got)
		}
		f := identityFile(t, s)
		want := []string{`198.51.100.10 example\alice`, `198.51.100.11 example.com\alice`, `198.51.100.12 other\ghost`, `198.51.100.13 example.com\carol`}
		if !slices.Equal(addresses(f), want) || !f.MappingsPartial {
			t.Errorf("mappings %q, partial %v", addresses(f), f.MappingsPartial)
		}
		if codes(s) != "note.identity-mappings-cut" || s.Result.Notes[0].Text != "the mapping table holds 6 entries; the snapshot keeps the first 4" {
			t.Errorf("notes %+v", s.Result.Notes)
		}
	})
	t.Run("pages up to the cap", func(t *testing.T) {
		t.Parallel()
		d := fullDevice(t)
		d.Ops[fakepanos.MappingPageCmd(2, 1)] = page(6, entry("198.51.100.1", `example.com\alice`), entry("198.51.100.2", `example.com\bob`))
		d.Ops[fakepanos.MappingPageCmd(2, 3)] = page(6, entry("198.51.100.3", `example.com\carol`), entry("198.51.100.4", `example.com\dave`))
		s, _ := fetched(t, d, pageSize(2), capAt(4))
		if got := pagesAsked(d); !slices.Equal(got, []string{fakepanos.MappingPageCmd(2, 1), fakepanos.MappingPageCmd(2, 3)}) {
			t.Errorf("pages %q", got)
		}
		if f := identityFile(t, s); len(f.Mappings) != 4 || !f.MappingsPartial || codes(s) != "note.identity-mappings-cut" {
			t.Errorf("mappings %q, partial %v, notes %s", addresses(f), f.MappingsPartial, codes(s))
		}
	})
}

// An empty table still takes one page (SG1): no mapping and no note. The
// answer has the layout of fw02's empty table (as observed on fw02, PAN-OS
// 12.2.3, spec 2026-10-17 C7).
func TestIdentityStepEmptyTable(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Ops[fakepanos.MappingPageCmd(10000, 1)] = fakepanos.Success("<count>0</count>\n<total>0</total>\n")
	s, steps := fetched(t, d)
	if got := pagesAsked(d); !slices.Equal(got, []string{fakepanos.MappingPageCmd(10000, 1)}) {
		t.Errorf("pages %q", got)
	}
	if f := identityFile(t, s); len(f.Mappings) != 0 || f.MappingsPartial || codes(s) != "" {
		t.Errorf("mappings %q, partial %v, notes %s", addresses(f), f.MappingsPartial, codes(s))
	}
	if r := steps["identity"]; r.Detail != "9 calls: 4 users, 8 groups, 0 mappings in 1 page, 2 sources" {
		t.Errorf("identity step = %+v", r)
	}
}

// expectNoIdentity checks a fetch that skipped the identity data: no identity
// command reached the device, no file, and the one note.
func expectNoIdentity(t *testing.T, d *fakepanos.Device, s State, steps map[string]task.Record, code, text string) {
	t.Helper()
	for _, c := range opCmds(d) {
		if slices.Contains(identityCmds, c) {
			t.Errorf("the device got %s", c)
		}
	}
	if s.Result.Identity != nil {
		t.Error("an identity file")
	}
	r := steps["identity"]
	if r.Status != task.Skipped || len(r.Notes) != 1 || r.Notes[0].Code != reason.Code(code) ||
		r.Notes[0].Text != text || !slices.Contains(s.Result.Notes, r.Notes[0]) {
		t.Errorf("step %+v, notes %+v", r, s.Result.Notes)
	}
}

// A device that runs several vsys gets no identity data, and a note (spec
// 2026-10-17 D10, §3.4).
func TestIdentityStepSkipsAMultiVsysDevice(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Ops["<show><system><info/></system></show>"] = fakepanos.Success(
		"<system><hostname>lab</hostname><app-version>8000-1000</app-version><multi-vsys>on</multi-vsys></system>")
	s, steps := fetched(t, d)
	expectNoIdentity(t, d, s, steps, "note.identity-multi-vsys",
		"the device runs several vsys, so the identity data is not fetched and rules that name a user stay in doubt")
}

// The step runs only on a device whose system info says that it runs one
// vsys, in any case. A system info that did not arrive, or that does not name
// the mode, gives no identity data, with the note: a device of several vsys
// would give one file that mixes the tables of its vsys (spec 2026-10-17 D10,
// ruling T7-I2).
func TestIdentityStepNeedsAKnownSingleVsys(t *testing.T) {
	t.Parallel()
	const info = "<show><system><info/></system></show>"
	for name, answer := range map[string]string{
		"a refused system info": fakepanos.Refusal("17", "show -> system is unexpected"),
		"no mode":               fakepanos.Success("<system><hostname>lab</hostname><app-version>8000-1000</app-version></system>"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := fullDevice(t)
			d.Ops[info] = answer
			s, steps := fetched(t, d)
			expectNoIdentity(t, d, s, steps, "note.identity-multi-vsys",
				"the system info does not show that the device runs one vsys, so the identity data is not fetched and rules that name a user stay in doubt")
		})
	}
	t.Run("off in another case", func(t *testing.T) {
		t.Parallel()
		d := fullDevice(t)
		d.Ops[info] = fakepanos.Success("<system><hostname>lab</hostname><app-version>8000-1000</app-version><multi-vsys>OFF</multi-vsys></system>")
		s, steps := fetched(t, d)
		if s.Result.Identity == nil || steps["identity"].Status != task.OK {
			t.Errorf("step %+v", steps["identity"])
		}
	})
}

// identity: false in the inventory turns the identity data off for the
// device, with a note (spec 2026-10-17 D4, §3.4).
func TestIdentityStepIsOffInTheInventory(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	s, steps := fetched(t, d, func(s *State) { s.Target.Identity = false })
	expectNoIdentity(t, d, s, steps, "note.identity-off",
		"the inventory turns the identity data off for the device, so rules that name a user stay in doubt")
}

// partSize is the number of entries of a part in a file.
func partSize(f identity.File, part string) int {
	n := 0
	switch part {
	case identity.PartLDAP:
		n = len(f.Sources.LDAP)
	case identity.PartCIE:
		n = len(f.Sources.CIE)
	case identity.PartUserGroups:
		for _, u := range f.Users {
			n += len(u.Groups)
		}
	case identity.PartUserNames:
		for _, u := range f.Users {
			n += len(u.Alt) + min(len(u.Email), 1)
		}
	case identity.PartGroups:
		n = len(f.Groups) + len(f.DUGs)
	case identity.PartTags:
		n = len(f.Tags)
	case identity.PartMappings:
		n = len(f.Mappings)
	}
	return n
}

// defaultSizes are the sizes of the parts of the fake device's answers.
var defaultSizes = map[string]int{
	identity.PartLDAP: 2, identity.PartCIE: 0, identity.PartUserGroups: 9, identity.PartUserNames: 5,
	identity.PartGroups: 10, identity.PartTags: 2, identity.PartMappings: 6,
}

// expectMissingParts checks a file that misses the parts and keeps every other
// part whole, and the one note that names each missing part with its cause.
func expectMissingParts(t *testing.T, s State, steps map[string]task.Record, missing map[string]string) {
	t.Helper()
	f := identityFile(t, s)
	var names, causes []string
	for _, p := range slices.Sorted(maps.Keys(missing)) {
		names = append(names, p)
		causes = append(causes, p+" ("+missing[p]+")")
	}
	if !slices.Equal(f.PartsMissing, names) {
		t.Errorf("parts missing %v, want %v", f.PartsMissing, names)
	}
	for p, n := range defaultSizes {
		if _, gone := missing[p]; gone {
			n = 0
		}
		if got := partSize(f, p); got != n {
			t.Errorf("%s: %d entries, want %d", p, got, n)
		}
	}
	want := "these parts of the identity data are missing, so answers that need them stay in doubt: " + strings.Join(causes, ", ")
	if r := steps["identity"]; r.Status != task.OK || len(r.Notes) != 1 || codes(s) != "note.identity-part-missing" || s.Result.Notes[0].Text != want {
		t.Errorf("step %+v, notes %+v\nwant %s", r, s.Result.Notes, want)
	}
}

// A command the device refuses leaves its part empty, and parts_missing and
// one note name it. The other parts stay, the step asks every command, and
// the file is written (spec 2026-10-17 §3.4).
func TestIdentityStepRefusedPartIsMissing(t *testing.T) {
	t.Parallel()
	for i, cmd := range identityCmds {
		part := identity.PartMappings
		if i < len(identityCalls) {
			part = identityCalls[i].part
		}
		t.Run(fmt.Sprintf("%d %s", i+1, part), func(t *testing.T) {
			t.Parallel()
			d := fullDevice(t)
			d.Ops[cmd] = fakepanos.Refusal("17", "show -> user is unexpected")
			s, steps := fetched(t, d)
			expectMissingParts(t, s, steps, map[string]string{part: "the device refused the command"})
			cmds := opCmds(d)
			if got := cmds[slices.Index(cmds, fakepanos.ContainersCmd)+1:]; !slices.Equal(got, identityCmds) {
				t.Errorf("commands %q", got)
			}
		})
	}
}

// An answer that does not read leaves its part empty, as a refusal does: a U3
// table whose total differs from its users (spec §3.4, O3), a dynamic list
// that differs from its total, which also empties the full list of its part,
// and two group-mapping answers that name different profiles. One note names
// every missing part.
func TestIdentityStepUnreadableAnswerIsMissing(t *testing.T) {
	t.Parallel()
	badTotal := strings.Replace(fakepanos.UserIDs, "Total: 3", "Total: 4", 1)
	for name, tc := range map[string]struct {
		ops     map[string]string
		missing map[string]string
	}{
		"the total of U3": {
			map[string]string{fakepanos.UserIDsCmd: badTotal},
			map[string]string{identity.PartUserGroups: "line 14: the table lists 3 users and its total is 4"},
		},
		"the total of the dynamic list": {
			map[string]string{fakepanos.DUGListCmd: strings.Replace(fakepanos.DUGList, "Total: 2", "Total: 3", 1)},
			map[string]string{identity.PartGroups: "line 5: the list holds 2 groups and its total is 3"},
		},
		"two parts": {
			map[string]string{fakepanos.UserIDsCmd: badTotal, fakepanos.RegisteredUsersCmd: fakepanos.Refusal("17", "show -> object is unexpected")},
			map[string]string{
				identity.PartUserGroups: "line 14: the table lists 3 users and its total is 4",
				identity.PartTags:       "the device refused the command",
			},
		},
		"a profile without a base": {
			map[string]string{fakepanos.GroupMappingStateCmd: strings.Replace(fakepanos.GroupMappingState, "): branch \n", "): other \n", 1)},
			map[string]string{identity.PartLDAP: "the statistics and the state name different group-mapping profiles"},
		},
		"a profile without statistics": {
			map[string]string{fakepanos.GroupMappingStatsCmd: fakepanos.Success("<entry><name>example.com</name><vsys>vsys1</vsys>" +
				"<groups>3</groups><last>60 secs ago(took 0 secs)</last><next>In 3540 secs</next></entry>\n")},
			map[string]string{identity.PartLDAP: "the statistics and the state name different group-mapping profiles"},
		},
		"a profile twice": {
			map[string]string{fakepanos.GroupMappingStatsCmd: strings.Replace(fakepanos.GroupMappingStats, "<name>branch</name>", "<name>example.com</name>", 1)},
			map[string]string{identity.PartLDAP: "the statistics and the state name different group-mapping profiles"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := fullDevice(t)
			maps.Copy(d.Ops, tc.ops)
			s, steps := fetched(t, d)
			expectMissingParts(t, s, steps, tc.missing)
		})
	}
}

// A mapping that does not read, such as one with the timeout Never, makes the
// part mappings missing, and the other parts stay. The note names the entry,
// never its address (Review focus 2, spec §3.5).
func TestIdentityStepUnreadableMappingsIsAMissingPart(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	never := strings.Replace(entry("198.51.100.7", `example.com\alice`), "<timeout>14400</timeout>", "<timeout>Never</timeout>", 1)
	d.Ops[fakepanos.MappingPageCmd(10000, 1)] = page(2, entry("198.51.100.6", `example.com\bob`), never)
	s, steps := fetched(t, d)
	expectMissingParts(t, s, steps, map[string]string{identity.PartMappings: "entry 2: the timeout is no number of seconds"})
	if strings.Contains(s.Result.Notes[0].Text, "198.51.100") {
		t.Errorf("the note quotes an address: %s", s.Result.Notes[0].Text)
	}
}

// A transport error stops the step: no file, an outcome named identity that
// names the part, and the step is partial. The fetch returns no error, so the
// snapshot is stored (spec 2026-10-17 §3.4, PD4). No later command reaches the
// device.
func TestIdentityStepTransportFailureIsPartial(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ cmd, part, after string }{
		{fakepanos.UserIDsCmd, identity.PartUserGroups, fakepanos.UserAttributesCmd},
		{fakepanos.MappingPageCmd(10000, 1), identity.PartMappings, ""},
	} {
		t.Run(tc.part, func(t *testing.T) {
			t.Parallel()
			d := fullDevice(t)
			d.DropCmd = map[string]int{tc.cmd: 2}
			s, steps := fetched(t, d)
			i := slices.IndexFunc(s.Result.Outcomes, func(o Outcome) bool { return o.Name == "identity" })
			if i < 0 || s.Result.Outcomes[i].Err == nil || !strings.HasPrefix(s.Result.Outcomes[i].Err.Error(), tc.part+": ") {
				t.Fatalf("outcomes %+v", s.Result.Outcomes)
			}
			r := steps["identity"]
			if r.Status != task.Partial || !strings.HasPrefix(r.Detail, "no identity data: "+tc.part+": ") || s.Result.Identity != nil || codes(s) != "" {
				t.Errorf("step %+v, file %v, notes %s", r, s.Result.Identity != nil, codes(s))
			}
			if tc.after != "" && sent(d, tc.after) != 0 {
				t.Errorf("the step went on after the failure: %q", opCmds(d))
			}
		})
	}
}

// cieStatus is a U7 answer in the layout of X1, with one row per profile.
func cieStatus(profiles ...string) string {
	var b strings.Builder
	b.WriteString("Name\t\tVsys\tGroups\t\tLast-Action\t\tNext-Action\n" + strings.Repeat("-", 78) + "\n")
	for _, p := range profiles {
		fmt.Fprintf(&b, "%-10s\tvsys1 \t    1\t\t120 secs ago\t\t\tIn 3480 secs\t\n", p)
	}
	return fakepanos.Success(b.String())
}

// cieGroup is the group of cie-a that the CIE devices list.
const cieGroup = `example-cie\cloud-team`

// cieDevice is the full device with the CIE profile cie-a in U7 and its group
// in U5.
func cieDevice(t *testing.T) *fakepanos.Device {
	t.Helper()
	d := fullDevice(t)
	d.Ops[fakepanos.CIEStatusCmd] = cieStatus("cie-a")
	d.Ops[fakepanos.GroupListCmd] = strings.Replace(fakepanos.GroupList, "dug-ab \n\nTotal: 8", "dug-ab \n"+cieGroup+" \n\nTotal: 9", 1)
	return d
}

// U7 has no domain column, so the step reads the domain of each CIE profile
// from the configuration of the snapshot: the running configuration merged
// with the pushed template, which alone holds cie-a (spec 2026-10-17 §3.2,
// SG2, C1). A group <domain>\<group> of that domain is a group of the profile
// (§3.3).
func TestIdentityStepReadsCIEDomainsFromTheTemplate(t *testing.T) {
	t.Parallel()
	d := cieDevice(t)
	d.Template = string(readFile(t, templateFile))
	s, steps := fetched(t, d)
	f := identityFile(t, s)
	if want := []identity.CIESource{{Name: "cie-a", Domain: "example-cie", Groups: 1, Last: "120 secs ago"}}; !slices.Equal(f.Sources.CIE, want) {
		t.Errorf("cie = %+v", f.Sources.CIE)
	}
	if got := sourceOf(f, cieGroup); got != "cie:cie-a" {
		t.Errorf("%s: source %q", cieGroup, got)
	}
	if len(f.PartsMissing) != 0 || codes(s) != "" || steps["identity"].Detail != "9 calls: 4 users, 9 groups, 6 mappings in 1 page, 3 sources" {
		t.Errorf("missing %v, notes %s, step %+v", f.PartsMissing, codes(s), steps["identity"])
	}
}

// Without the domain of a CIE profile, sources.cie is missing, and a group
// <domain>\<group> that is no LDAP group and no DUG is a CIE group of an
// unknown profile, so it stays in doubt (spec 2026-10-17 SG2, D1). So it is
// when the device refuses its pushed template, which alone holds the profile,
// and when no configuration arrived.
func TestIdentityStepWithoutCIEDomainsIsConservative(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*testing.T, *fakepanos.Device){
		"a refused template": func(t *testing.T, d *fakepanos.Device) {
			d.Template = string(readFile(t, templateFile))
			d.Ops[fakepanos.PushedTemplateCmd] = fakepanos.Refusal("17", "show -> pushed-template is unexpected")
		},
		"no configuration": func(_ *testing.T, d *fakepanos.Device) { d.DropCmd = map[string]int{fakepanos.RunningConfigCmd: 2} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := cieDevice(t)
			change(t, d)
			s, steps := fetched(t, d)
			f := identityFile(t, s)
			if !slices.Equal(f.PartsMissing, []string{identity.PartCIE}) || sourceOf(f, cieGroup) != identity.SourceCIE ||
				len(f.Sources.CIE) != 1 || f.Sources.CIE[0].Domain != "" {
				t.Errorf("missing %v, source %q, cie %+v", f.PartsMissing, sourceOf(f, cieGroup), f.Sources.CIE)
			}
			want := "these parts of the identity data are missing, so answers that need them stay in doubt: " +
				"sources.cie (a CIE profile has no domain in the configuration)"
			if n := steps["identity"].Notes; len(n) != 1 || n[0].Code != "note.identity-part-missing" || n[0].Text != want {
				t.Errorf("notes %+v", n)
			}
		})
	}
}

// The domain of a group-mapping profile comes from the configuration as well
// (ruling Q1, AGENTS.md R1). A profile that names none has an unknown domain,
// and no part is missing: the base still gives each LDAP group its profile.
func TestIdentityStepReadsLDAPDomainsFromTheConfiguration(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Config = strings.Replace(d.Config, `<entry name="vsys1">`, `<entry name="vsys1"><group-mapping>`+
		`<entry name="example.com"><server-profile>ldap-a</server-profile><domain>example.com</domain></entry>`+
		`<entry name="branch"><server-profile>ldap-b</server-profile></entry></group-mapping>`, 1)
	s, _ := fetched(t, d)
	f := identityFile(t, s)
	want := []identity.LDAPSource{
		{Name: "branch", Base: "ou=branch,dc=example,dc=com", Groups: 1},
		{Name: "example.com", Domain: "example.com", Base: "dc=example,dc=com", Groups: 3},
	}
	if !slices.Equal(f.Sources.LDAP, want) || len(f.PartsMissing) != 0 || codes(s) != "" {
		t.Errorf("ldap %+v, missing %v, notes %s", f.Sources.LDAP, f.PartsMissing, codes(s))
	}
}

// The run log holds the calls of the identity data with their times, the
// counts, and why each missing part is missing. It never holds a user, a
// group, an address of a mapping or a tag of the answers (spec 2026-10-17
// §3.5).
func TestIdentityStepLogsNoNames(t *testing.T) {
	t.Parallel()
	d := cieDevice(t)
	d.Ops[fakepanos.UserIDsCmd] = strings.Replace(fakepanos.UserIDs, "Total: 3", "Total: 4", 1)
	d.Ops[fakepanos.MappingPageCmd(10000, 1)] = page(1,
		strings.Replace(entry("198.51.100.7", `example.com\alice`), "<timeout>14400</timeout>", "<timeout>Never</timeout>", 1))
	d.Ops[fakepanos.RegisteredUsersCmd] = fakepanos.Refusal("17", "show -> refusal-text is unexpected")
	l, err := runlog.Open(runlog.Options{Dir: t.TempDir(), Command: "fetch", Level: runlog.Debug})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run(context.Background(), target(d.Start(t)), Documents, ActiveOptions{}, l); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	got := string(readFile(t, l.Path()))
	for _, want := range []string{
		"[DEBUG] [API] lab: op " + fakepanos.UserIDsCmd + " -> HTTP 200, ",
		"[DEBUG] [API] lab: op " + fakepanos.MappingPageCmd(10000, 1) + " -> HTTP 200, ",
		"[WARN] [API] lab: identity: users.groups is missing: line 14: the table lists 3 users and its total is 4\n",
		"[WARN] [API] lab: identity: mappings is missing: entry 1: the timeout is no number of seconds\n",
		"[WARN] [API] lab: identity: sources.cie is missing: a CIE profile has no domain in the configuration\n",
		"[WARN] [API] lab: identity: tags is missing: the device refused the command\n",
		"[INFO] [API] lab: identity: 9 calls: 4 users, 9 groups, 0 mappings in 0 pages, 3 sources, ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, name := range []string{
		"alice", "bob", "carol", "dave", "ghost", "domain users", "payroll", "branch staff", "engineering",
		"team-x", "dug-a", "cloud-team", "tag-a", "tag-b", "198.51.100.", "2001:db8",
	} {
		if strings.Contains(got, name) {
			t.Errorf("the log names %q", name)
		}
	}
	// A warning gives the fixed cause of a refusal, not the device's text
	// (ruling T7-M3).
	for line := range strings.SplitSeq(got, "\n") {
		if strings.Contains(line, "[WARN]") && strings.Contains(line, "refusal-text") {
			t.Errorf("a warning quotes the device: %s", line)
		}
	}
	if t.Failed() {
		t.Logf("log:\n%s", got)
	}
}
