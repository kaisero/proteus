package fetch

import (
	"bytes"
	"cmp"
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/fakepanos"
	"github.com/kaisero/proteus/internal/runlog"
	"github.com/kaisero/proteus/internal/schema"
	"github.com/kaisero/proteus/internal/task"
)

var update = flag.Bool("update", false, "rewrite testdata/config/firewall-lab-merged.xml")

// The fixtures of the merge: the base, its indented copy, the template that
// Panorama pushed for it, and the expected merge.
const (
	labFile      = "../../testdata/config/firewall-lab.xml"
	indentedFile = "../../testdata/config/firewall-lab-indented.xml"
	templateFile = "../../testdata/config/firewall-lab-template.xml"
	mergedFile   = "../../testdata/config/firewall-lab-merged.xml"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// templateConfig is the config element of the template fixture, as the fetch
// unwraps it from the device's answer (C9).
func templateConfig(t *testing.T) []byte {
	t.Helper()
	b, err := unwrapTemplate([]byte(fakepanos.Success(string(readFile(t, templateFile)))))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// digestRoot is the root of the embedded schema digest, which carries the tlo
// marks (R1).
func digestRoot(t *testing.T) *schema.Node {
	t.Helper()
	root, err := config.SchemaRoot()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// The hand-built schema of the row tests. The device entry and the vsys entry
// have no tlo mark, as in the digest (C11); a case marks a template object
// where it needs one.
func seq(name string, kids ...*schema.Node) *schema.Node {
	return &schema.Node{Kind: schema.KindSequence, Name: name, Children: kids}
}

func list(name string, entry *schema.Node) *schema.Node {
	return &schema.Node{Kind: schema.KindArray, Name: name, Children: []*schema.Node{entry}}
}

func leaf(name string) *schema.Node { return &schema.Node{Kind: schema.KindElement, Name: name} }

func members(name string) *schema.Node { return list(name, leaf("member")) }

func choice(kids ...*schema.Node) *schema.Node {
	return &schema.Node{Kind: schema.KindChoice, Children: kids}
}

func tlo(n *schema.Node) *schema.Node { n.TemplateObject = true; return n }

func rowSchema() *schema.Node {
	return seq("config",
		list("devices", seq("entry",
			seq("deviceconfig",
				seq("system", leaf("hostname"), leaf("timezone"),
					seq("update-schedule", tlo(seq("threats", seq("recurring", choice(
						seq("daily", leaf("at"), leaf("action")),
						seq("every-30-mins", leaf("at"), leaf("action")))))))),
				seq("plugins")),
			seq("network", seq("profiles", list("interface-management-profile",
				tlo(seq("entry", leaf("ping"), leaf("ssh"), leaf("https")))))),
			list("vsys", seq("entry",
				seq("import", seq("network", members("interface"))),
				list("zone", tlo(seq("entry", seq("network", members("layer3"))))),
				list("cloud-identity-engine", tlo(seq("entry", leaf("domain")))))))))
}

// inDevice and inVsys wrap a part of the base or the template in the paths of
// firewall-lab.xml; mark gives each template element ptpl, as the device does.
func inDevice(attr, body string) string {
	return `<config` + attr + `><devices` + attr + `><entry name="localhost.localdomain"` + attr + `>` +
		body + `</entry></devices></config>`
}

func inVsys(attr, body string) string {
	return inDevice(attr, `<vsys`+attr+`><entry name="vsys1"`+attr+`>`+body+`</entry></vsys>`)
}

const mark = ` ptpl="000000000001"`

func mergeOf(t *testing.T, base, tpl string, root *schema.Node) (string, MergeStats) {
	t.Helper()
	got, st, err := MergeTemplate([]byte(base), []byte(tpl), root)
	if err != nil {
		t.Fatal(err)
	}
	return string(got), st
}

// withoutInserted removes from a merge result each element that carries ptpl
// under a parent without it, with the space before it: the ranges the merge
// inserted, because every template element of these tests carries ptpl and no
// base element does.
func withoutInserted(t *testing.T, b []byte) []byte {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(b))
	var out []byte
	keep, space := 0, -1
	var marked []bool
	for {
		off := int(dec.InputOffset())
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return append(out, b[keep:]...)
		}
		if err != nil {
			t.Fatal(err)
		}
		switch tk := tok.(type) {
		case xml.CharData:
			space = -1
			if len(bytes.TrimSpace(tk)) == 0 {
				space = off
			}
			continue
		case xml.StartElement:
			m := slices.ContainsFunc(tk.Attr, func(a xml.Attr) bool { return a.Name.Local == "ptpl" })
			if m && (len(marked) == 0 || !marked[len(marked)-1]) {
				start := off
				if space >= 0 {
					start = space
				}
				out = append(out, b[keep:start]...)
				if err := dec.Skip(); err != nil {
					t.Fatal(err)
				}
				keep = int(dec.InputOffset())
			} else {
				marked = append(marked, m)
			}
		case xml.EndElement:
			marked = marked[:len(marked)-1]
		}
		space = -1
	}
}

// The golden merge of firewall-lab.xml and its template (spec §2.2): every byte
// of the base, in order, and the template elements the base lacks. -update
// writes it; read the diff before it is committed.
func TestMergeTemplateMatchesTheGolden(t *testing.T) {
	t.Parallel()
	got, st, err := MergeTemplate(readFile(t, labFile), templateConfig(t), digestRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(mergedFile, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if want := readFile(t, mergedFile); !bytes.Equal(got, want) {
		t.Errorf("the merge differs from %s; run go test ./internal/fetch -run TestMergeTemplate -update and read the diff", mergedFile)
	}
	if st != (MergeStats{Added: 7, KeptLocal: 1}) {
		t.Errorf("stats = %+v", st)
	}
}

// The merge keeps every byte of the base: without the ranges it inserted, the
// result is the base, for the fixture, its compact form and the indented form
// that show config running answers (spec §2.2, C12).
func TestMergeKeepsEveryBaseByte(t *testing.T) {
	t.Parallel()
	lab := readFile(t, labFile)
	for name, base := range map[string][]byte{
		"fixture":  lab,
		"compact":  regexp.MustCompile(`>\s+<`).ReplaceAll(lab, []byte("><")),
		"indented": readFile(t, indentedFile),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, st, err := MergeTemplate(base, templateConfig(t), digestRoot(t))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(withoutInserted(t, got), base) {
				t.Errorf("the result without its template ranges is not the base:\n%s", got)
			}
			if st.Added == 0 || len(got) <= len(base) {
				t.Errorf("nothing was inserted: %+v", st)
			}
		})
	}
}

// A local interface management profile hides the template entry of its name,
// with the template's extra leaves: the entry is a template object (as
// observed on fw01, PAN-OS 11.2.5, spec 2026-10-17 C6, C11; Review focus 6).
func TestMergeKeepsATemplateObjectWhole(t *testing.T) {
	t.Parallel()
	base := inDevice("", `<network><profiles><interface-management-profile><entry name="mgmt">`+
		`<ping>yes</ping></entry></interface-management-profile></profiles></network>`)
	tpl := inDevice(mark, `<network`+mark+`><profiles`+mark+`><interface-management-profile`+mark+`><entry name="mgmt"`+mark+`>`+
		`<ping`+mark+`>no</ping><ssh`+mark+`>yes</ssh><https`+mark+`>yes</https></entry></interface-management-profile></profiles></network>`)
	got, st := mergeOf(t, base, tpl, rowSchema())
	if got != base || st != (MergeStats{KeptLocal: 1}) {
		t.Errorf("got %s, %+v; want the base entry only", got, st)
	}
}

// A local threats schedule with the option daily of the choice recurring
// hides the template's other option: the schedule is a template object, so
// the result never holds two options of one choice (C11; Review focus 6).
func TestMergeKeepsTheLocalOptionOfAChoice(t *testing.T) {
	t.Parallel()
	base := inDevice("", `<deviceconfig><system><update-schedule><threats><recurring><daily><at>01:00</at>`+
		`<action>download-only</action></daily></recurring></threats></update-schedule></system></deviceconfig>`)
	tpl := inDevice(mark, `<deviceconfig`+mark+`><system`+mark+`><update-schedule`+mark+`><threats`+mark+`><recurring`+mark+`>`+
		`<every-30-mins`+mark+`><at`+mark+`>5</at></every-30-mins></recurring></threats></update-schedule></system></deviceconfig>`)
	got, st := mergeOf(t, base, tpl, rowSchema())
	if got != base || strings.Contains(got, "every-30-mins") || st != (MergeStats{KeptLocal: 1}) {
		t.Errorf("got %s, %+v; want daily only", got, st)
	}
}

// The template and the base both hold the device entry and the vsys entry.
// Neither has a tlo mark, so the merge goes on in their children, and the
// template's zone and CIE entry join the base's (C11). With a mark on the
// device entry, the merge of §2.2 as first written, the base entry would hide
// every template value below it.
func TestMergeMergesTheDeviceAndVsysEntries(t *testing.T) {
	t.Parallel()
	base := inVsys("", `<zone><entry name="inside"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone>`)
	tpl := inVsys(mark, `<zone`+mark+`><entry name="tpl-zone"`+mark+`/></zone>`+
		`<cloud-identity-engine`+mark+`><entry name="cie-a"`+mark+`><domain`+mark+`>example-cie</domain></entry></cloud-identity-engine>`)
	want := inVsys("", `<zone><entry name="inside"><network><layer3><member>ethernet1/1</member></layer3></network></entry>`+
		`<entry name="tpl-zone"`+mark+`/></zone>`+
		`<cloud-identity-engine`+mark+`><entry name="cie-a"`+mark+`><domain`+mark+`>example-cie</domain></entry></cloud-identity-engine>`)
	got, st := mergeOf(t, base, tpl, rowSchema())
	if got != want || st != (MergeStats{Added: 2}) {
		t.Errorf("got  %s\nwant %s\n%+v", got, want, st)
	}
	root := rowSchema()
	tlo(root.Step("devices").Step("entry"))
	if got, st := mergeOf(t, base, tpl, root); got != base || st != (MergeStats{KeptLocal: 1}) {
		t.Errorf("a marked device entry: got %s, %+v", got, st)
	}
}

// A leaf and a member list that both hold keep the base value, whole; a leaf
// the base lacks joins it. A member list that the base leaves empty takes the
// template's members: the base holds no member to keep (spec §2.2).
func TestMergeKeepsALocalLeafAndList(t *testing.T) {
	t.Parallel()
	system := `<deviceconfig` + mark + `><system` + mark + `><hostname` + mark + `>fw-template</hostname>` +
		`<timezone` + mark + `>UTC</timezone></system></deviceconfig>`
	tplMembers := `<member` + mark + `>ethernet1/2</member><member` + mark + `>ethernet1/3</member>`
	tpl := inDevice(mark, system+`<vsys`+mark+`><entry name="vsys1"`+mark+`><import`+mark+`><network`+mark+`>`+
		`<interface`+mark+`>`+tplMembers+`</interface></network></import></entry></vsys>`)
	base := inDevice("", `<deviceconfig><system><hostname>fw-local</hostname></system></deviceconfig>`+
		`<vsys><entry name="vsys1"><import><network><interface><member>ethernet1/1</member></interface></network></import></entry></vsys>`)
	want := inDevice("", `<deviceconfig><system><hostname>fw-local</hostname><timezone`+mark+`>UTC</timezone></system></deviceconfig>`+
		`<vsys><entry name="vsys1"><import><network><interface><member>ethernet1/1</member></interface></network></import></entry></vsys>`)
	got, st := mergeOf(t, base, tpl, rowSchema())
	if got != want || st != (MergeStats{Added: 1, KeptLocal: 2}) {
		t.Errorf("got  %s\nwant %s\n%+v", got, want, st)
	}
	empty := inDevice("", `<vsys><entry name="vsys1"><import><network><interface/></network></import></entry></vsys>`)
	want = inDevice("", `<vsys><entry name="vsys1"><import><network><interface>`+tplMembers+`</interface></network></import></entry></vsys>`+
		system)
	if got, st := mergeOf(t, empty, tpl, rowSchema()); got != want || st != (MergeStats{Added: 3}) {
		t.Errorf("an empty list: got  %s\nwant %s\n%+v", got, want, st)
	}
}

// The template elements that the base lacks are in the result with their
// subtrees: each after the base children of its parent, in the order of the
// template (spec §2.2).
func TestMergeAddsTemplateSubtrees(t *testing.T) {
	t.Parallel()
	got, st, err := MergeTemplate(readFile(t, labFile), templateConfig(t), digestRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, got, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// children names the children of the first element at a path: an entry by
	// its name. The first vsys entry is vsys1.
	children := func(path string) string {
		el := cfg.Root()
		if path != "" {
			el = el.Find(strings.Split(path, "/")...)[0]
		}
		var out []string
		for _, c := range el.Children {
			out = append(out, cmp.Or(c.Attr("name"), c.Name))
		}
		return strings.Join(out, " ")
	}
	for path, want := range map[string]string{
		"":                                   "shared devices mgt-config",
		"shared":                             "address pre-rulebase post-rulebase local-user-database log-settings",
		"shared/log-settings/profiles":       "tpl-logs",
		"devices/entry":                      "vsys deviceconfig network",
		"devices/entry/deviceconfig/plugins": "dlp example_plugin",
		"devices/entry/vsys/entry":           "address address-group rulebase cloud-identity-engine zone",
		"devices/entry/vsys/entry/address":   "net-home net-labor dc01",
		"devices/entry/vsys/entry/zone":      "tpl-zone",
		"devices/entry/vsys/entry/cloud-identity-engine": "cie-a",
	} {
		if got := children(path); got != want {
			t.Errorf("%s: %s, want %s", cmp.Or(path, "config"), got, want)
		}
	}
	// The base entry net-home hides the template's: its value and no description.
	home := cfg.Root().Find("devices", "entry", "vsys", "entry", "address", "entry")[0]
	if home.Child("ip-netmask").Text != "198.18.1.0/24" || home.Child("description") != nil || home.Attr("ptpl") != "" {
		t.Errorf("net-home: %+v", home)
	}
	if st != (MergeStats{Added: 7, KeptLocal: 1}) {
		t.Errorf("stats = %+v; want the 7 subtrees above added", st)
	}
}

// An empty base element gets an end tag, and the template's children go in
// it, also when its tag ends with a space. An element that holds space only
// takes them after its start tag (spec §2.2).
func TestMergeOpensAnEmptyBaseElement(t *testing.T) {
	t.Parallel()
	tpl := inVsys(mark, `<cloud-identity-engine`+mark+`><entry name="cie-a"`+mark+`><domain`+mark+`>example-cie</domain></entry></cloud-identity-engine>`)
	cie := `<entry name="cie-a"` + mark + `><domain` + mark + `>example-cie</domain></entry>`
	for base, want := range map[string]string{
		inVsys("", `<cloud-identity-engine/>`):  inVsys("", `<cloud-identity-engine>`+cie+`</cloud-identity-engine>`),
		inVsys("", `<cloud-identity-engine />`): inVsys("", `<cloud-identity-engine >`+cie+`</cloud-identity-engine>`),
		inVsys("", "<cloud-identity-engine>\n  </cloud-identity-engine>"): inVsys("",
			"<cloud-identity-engine>"+cie+"\n  </cloud-identity-engine>"),
	} {
		if got, st := mergeOf(t, base, tpl, rowSchema()); got != want || st != (MergeStats{Added: 1}) {
			t.Errorf("got  %s\nwant %s\n%+v", got, want, st)
		}
	}
}

// An element that both hold and the schema does not describe has no tlo mark:
// it merges by its children, an entry of its list by its name (spec §2.2).
func TestMergeOfAnUndescribedElement(t *testing.T) {
	t.Parallel()
	base := inDevice("", `<deviceconfig><plugins><example_plugin><enabled>no</enabled>`+
		`<list><entry name="a"><v>1</v></entry></list></example_plugin></plugins></deviceconfig>`)
	tpl := inDevice(mark, `<deviceconfig`+mark+`><plugins`+mark+`><example_plugin`+mark+`><enabled`+mark+`>yes</enabled>`+
		`<list`+mark+`><entry name="a"`+mark+`><v`+mark+`>2</v><w`+mark+`>3</w></entry><entry name="b"`+mark+`><v`+mark+`>4</v></entry></list>`+
		`<mode`+mark+`>fast</mode></example_plugin></plugins></deviceconfig>`)
	want := inDevice("", `<deviceconfig><plugins><example_plugin><enabled>no</enabled>`+
		`<list><entry name="a"><v>1</v><w`+mark+`>3</w></entry><entry name="b"`+mark+`><v`+mark+`>4</v></entry></list>`+
		`<mode`+mark+`>fast</mode></example_plugin></plugins></deviceconfig>`)
	got, st := mergeOf(t, base, tpl, rowSchema())
	if got != want || st != (MergeStats{Added: 3, KeptLocal: 2}) {
		t.Errorf("got  %s\nwant %s\n%+v", got, want, st)
	}
	if got, _ := mergeOf(t, base, tpl, nil); got != want {
		t.Errorf("without a schema: got %s", got)
	}
}

// The result's root is the base's, with its attributes, so the loaded result
// reads the base's version (spec §2.1, SG3). The merge adds no attribute.
func TestMergeKeepsTheBaseRoot(t *testing.T) {
	t.Parallel()
	base := `<config version="11.2.0" urldb="paloaltonetworks" detail-version="11.2.5"><shared/></config>`
	tpl := `<config` + mark + ` version="10.1.0"><shared` + mark + `><log-settings` + mark + `/></shared></config>`
	got, st := mergeOf(t, base, tpl, digestRoot(t))
	want := `<config version="11.2.0" urldb="paloaltonetworks" detail-version="11.2.5"><shared><log-settings` + mark + `/></shared></config>`
	if got != want || st != (MergeStats{Added: 1}) {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(path)
	if err != nil || cfg.Version() != "11.2.0" || cfg.DetailVersion() != "11.2.5" {
		t.Errorf("loaded: %v", err)
	}
}

// A base or a template that is no configuration element is no merge: the
// error names no value of either (spec §3.5).
func TestMergeRefusesWhatIsNoConfiguration(t *testing.T) {
	t.Parallel()
	good := `<config><shared/></config>`
	for name, tc := range map[string]struct{ base, tpl string }{
		"a cut base":       {`<config><shared><address><entry name="secret-name">`, good},
		"a cut template":   {good, `<config><shared><entry name="secret-name">`},
		"an empty base":    {"", good},
		"an empty answer":  {good, " \n"},
		"another root":     {`<response status="success"><result/></response>`, good},
		"another template": {good, `<template><name>secret-name</name><config/></template>`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, st, err := MergeTemplate([]byte(tc.base), []byte(tc.tpl), digestRoot(t))
			if err == nil || got != nil || st != (MergeStats{}) {
				t.Fatalf("got %s, %+v, %v", got, st, err)
			}
			if strings.Contains(err.Error(), "secret-name") {
				t.Errorf("the error names a value: %v", err)
			}
		})
	}
}

// The template sits at response/result/template/config (C9): unwrapTemplate
// returns that element byte for byte, indented as the device sends it. An
// answer without it is no template.
func TestUnwrapTemplateKeepsTheDeviceBytes(t *testing.T) {
	t.Parallel()
	cfg := "<config" + mark + ">\n    <shared" + mark + ">\n      <log-settings" + mark + "/>\n    </shared>\n  </config>"
	answer := fakepanos.Success(`<template cfg-version="11.2.0" detail-version="11.2.5" urldb="paloaltonetworks">` +
		"\n  <name>tpl-stack</name>\n  " + cfg + "\n</template>")
	got, err := unwrapTemplate([]byte(answer))
	if err != nil || string(got) != cfg {
		t.Errorf("got %q, %v", got, err)
	}
	for _, a := range []string{
		fakepanos.NoTemplate,
		`<response status="success"><result/></response>`,
		fakepanos.Success(`<config/>`),
		fakepanos.Success(`<template><name>tpl-stack</name></template>`),
		`not xml`,
	} {
		if _, err := unwrapTemplate([]byte(a)); !errors.Is(err, errNoTemplate) {
			t.Errorf("%s: %v", a, err)
		}
	}
	if err := holdsTemplate([]byte(answer)); err != nil {
		t.Errorf("a template: %v", err)
	}
	if err := holdsTemplate([]byte(fakepanos.NoTemplate)); err != nil {
		t.Errorf("no template (C7): %v", err)
	}
}

// fetched runs a fetch of the device and returns its state and its steps.
func fetched(t *testing.T, d *fakepanos.Device, opts ...func(*State)) (State, map[string]task.Record) {
	t.Helper()
	s := NewState(target(d.Start(t)), Documents, ActiveOptions{}, nil)
	for _, o := range opts {
		o(&s)
	}
	recs, err := task.Run(context.Background(), "lab", &s, Steps(), task.Options{})
	if err != nil {
		t.Fatal(err)
	}
	steps := map[string]task.Record{}
	for _, r := range recs {
		steps[r.Slug] = r
	}
	return s, steps
}

// sent counts the device's requests of a type, or of an op command.
func sent(d *fakepanos.Device, what string) int {
	n := 0
	for _, r := range d.Requests() {
		if r.Type == what || r.Cmd == what {
			n++
		}
	}
	return n
}

// codes is the codes of the notes.
func codes(s State) string {
	var out []string
	for _, n := range s.Result.Notes {
		out = append(out, string(n.Code))
	}
	return strings.Join(out, ",")
}

// A device with a pushed template: the fetch reads show config running and the
// template, exports nothing, and keeps the merge as the configuration and the
// template config as the document template (spec §2.1). The merge equals the
// golden but for the last newline, which the running answer has not: it is no
// byte of the config element.
func TestFetchMergesThePushedTemplate(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Template = string(readFile(t, templateFile))
	s, steps := fetched(t, d)
	if sent(d, fakepanos.RunningConfigCmd) != 1 || sent(d, fakepanos.PushedTemplateCmd) != 1 || sent(d, "export") != 0 {
		t.Errorf("requests: %+v", d.Requests())
	}
	if want := bytes.TrimSuffix(readFile(t, mergedFile), []byte("\n")); !bytes.Equal(s.Result.Docs["config"], want) {
		t.Errorf("config:\n%s", s.Result.Docs["config"])
	}
	if !bytes.Equal(s.Result.Docs["template"], templateConfig(t)) {
		t.Errorf("template:\n%s", s.Result.Docs["template"])
	}
	tpl := steps["template"]
	if s.Result.ConfigSource != "running+template" || tpl.Status != task.OK ||
		tpl.Detail != "7 template elements added, 1 local element kept" || codes(s) != "" {
		t.Errorf("source %q, step %+v, notes %s", s.Result.ConfigSource, tpl, codes(s))
	}
	if !arrived(s.Result, "template") || steps["documents"].Status != task.OK {
		t.Errorf("outcomes %+v, documents %+v", s.Result.Outcomes, steps["documents"])
	}
}

// A refused show config running exports the configuration, and the template
// merges into the export (spec §2.1).
func TestTheExportFallbackMergesTheTemplate(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Template = string(readFile(t, templateFile))
	d.Ops[fakepanos.RunningConfigCmd] = fakepanos.Refusal("17", "show -> config is unexpected")
	s, steps := fetched(t, d)
	if s.Result.ConfigSource != "export+template" || codes(s) != "note.config-not-running" || steps["template"].Status != task.OK {
		t.Errorf("source %q, notes %s, step %+v", s.Result.ConfigSource, codes(s), steps["template"])
	}
	if !bytes.Equal(s.Result.Docs["config"], readFile(t, mergedFile)) {
		t.Errorf("config:\n%s", s.Result.Docs["config"])
	}
}

// fw02's answer, No template pushed to device, is a device without a template,
// as one that Panorama does not manage: no note, the base as the
// configuration, and no document template (as observed on fw02, PAN-OS
// 12.2.3, spec 2026-10-17 C7).
func TestNoTemplateTextHasNoNote(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	s, steps := fetched(t, d)
	if s.Result.ConfigSource != "running" || codes(s) != "" ||
		steps["template"].Status != task.OK || steps["template"].Detail != "no template pushed to the device" {
		t.Errorf("source %q, notes %s, step %+v", s.Result.ConfigSource, codes(s), steps["template"])
	}
	if want := strings.TrimSuffix(d.Config, "\n"); string(s.Result.Docs["config"]) != want {
		t.Errorf("config:\n%s", s.Result.Docs["config"])
	}
	if _, ok := s.Result.Docs["template"]; ok || slices.ContainsFunc(s.Result.Outcomes, func(o Outcome) bool { return o.Name == "template" }) {
		t.Errorf("a template document: %+v", s.Result.Outcomes)
	}
	if sent(d, fakepanos.PushedTemplateCmd) != 1 {
		t.Error("the template was not asked")
	}
}

// A template config that holds no element counts as no template (spec §2.1).
func TestATemplateWithoutAnElementIsNoTemplate(t *testing.T) {
	t.Parallel()
	for _, tpl := range []string{
		`<template><name>tpl-stack</name><config` + mark + `/></template>`,
		"<template>\n  <name>tpl-stack</name>\n  <config" + mark + ">\n  </config>\n</template>",
	} {
		d := fullDevice(t)
		d.Template = tpl
		s, steps := fetched(t, d)
		if s.Result.ConfigSource != "running" || codes(s) != "" || steps["template"].Detail != "the template holds no element" {
			t.Errorf("source %q, notes %s, step %+v", s.Result.ConfigSource, codes(s), steps["template"])
		}
		if _, ok := s.Result.Docs["template"]; ok || arrived(s.Result, "template") {
			t.Error("a template document")
		}
	}
	if holdsElement([]byte("<config")) {
		t.Error("a cut element holds nothing")
	}
}

// A refused template command keeps the base, with the note, and every step is
// ok (spec §2.1).
func TestARefusedTemplateKeepsTheBase(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Ops[fakepanos.PushedTemplateCmd] = fakepanos.Refusal("17", "show -> pushed-template is unexpected")
	s, steps := fetched(t, d)
	if s.Result.ConfigSource != "running" || codes(s) != "note.config-no-template" {
		t.Errorf("source %q, notes %s", s.Result.ConfigSource, codes(s))
	}
	if want := strings.TrimSuffix(d.Config, "\n"); string(s.Result.Docs["config"]) != want {
		t.Errorf("config:\n%s", s.Result.Docs["config"])
	}
	if _, ok := s.Result.Docs["template"]; ok || arrived(s.Result, "template") {
		t.Error("a template document")
	}
	for slug, r := range steps {
		if r.Status != task.OK && r.Status != task.Skipped {
			t.Errorf("%s: %+v", slug, r)
		}
	}
	if steps["template"].Detail != "no template arrived" {
		t.Errorf("template: %+v", steps["template"])
	}
}

// A success answer with neither the template config nor the text of a device
// without a template is a refusal (spec §2.1).
func TestATemplateAnswerWithoutConfigIsARefusal(t *testing.T) {
	t.Parallel()
	for _, answer := range []string{
		`<response status="success"><result/></response>`,
		fakepanos.Success("No template is configured"),
		fakepanos.Success(`<template><name>tpl-stack</name></template>`),
	} {
		d := fullDevice(t)
		d.Ops[fakepanos.PushedTemplateCmd] = answer
		s, steps := fetched(t, d)
		if s.Result.ConfigSource != "running" || codes(s) != "note.config-no-template" || steps["documents"].Status != task.OK {
			t.Errorf("%s: source %q, notes %s, documents %+v", answer, s.Result.ConfigSource, codes(s), steps["documents"])
		}
	}
}

// A transport error fails the document template: the step documents is
// partial, and the base is the configuration (spec §2.1, PD1).
func TestATransportErrorFailsTheTemplateDocument(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Template = string(readFile(t, templateFile))
	d.DropCmd = map[string]int{fakepanos.PushedTemplateCmd: 2}
	s, steps := fetched(t, d)
	i := slices.IndexFunc(s.Result.Outcomes, func(o Outcome) bool { return o.Name == "template" })
	if i < 0 || s.Result.Outcomes[i].Err == nil || steps["documents"].Status != task.Partial {
		t.Fatalf("outcomes %+v, documents %+v", s.Result.Outcomes, steps["documents"])
	}
	if want := strings.TrimSuffix(d.Config, "\n"); string(s.Result.Docs["config"]) != want || s.Result.ConfigSource != "running" || codes(s) != "" {
		t.Errorf("source %q, notes %s", s.Result.ConfigSource, codes(s))
	}
}

// A digest that does not load, or a merge that fails, keeps the base and makes
// the step partial; the log names no value of the configuration (spec §3.5).
func TestAFailedMergeKeepsTheBase(t *testing.T) {
	t.Parallel()
	t.Run("digest", func(t *testing.T) {
		t.Parallel()
		d := fullDevice(t)
		d.Template = string(readFile(t, templateFile))
		s, steps := fetched(t, d, func(s *State) {
			s.schemaRoot = func() (*schema.Node, error) { return nil, errors.New("config: no schema digest") }
		})
		if r := steps["template"]; r.Status != task.Partial || !strings.Contains(r.Detail, "no schema digest") {
			t.Errorf("step %+v", r)
		}
		if want := strings.TrimSuffix(d.Config, "\n"); string(s.Result.Docs["config"]) != want || s.Result.ConfigSource != "running" {
			t.Errorf("source %q", s.Result.ConfigSource)
		}
		if !bytes.Equal(s.Result.Docs["template"], templateConfig(t)) {
			t.Error("the template that arrived is kept")
		}
	})
	t.Run("merge", func(t *testing.T) {
		t.Parallel()
		d := fullDevice(t)
		d.Template = string(readFile(t, templateFile))
		d.Ops[fakepanos.RunningConfigCmd] = fakepanos.Refusal("17", "show -> config is unexpected")
		d.Config = `<config><shared><address><entry name="secret-name"><ip-netmask>192.0.2.1</ip-netmask>`
		l, err := runlog.Open(runlog.Options{Dir: t.TempDir(), Command: "fetch", Level: runlog.Debug})
		if err != nil {
			t.Fatal(err)
		}
		s, steps := fetched(t, d, func(s *State) { s.Log = l })
		_ = l.Close()
		if r := steps["template"]; r.Status != task.Partial || !strings.HasPrefix(r.Detail, "the template was not merged: ") {
			t.Errorf("step %+v", r)
		}
		if string(s.Result.Docs["config"]) != d.Config || s.Result.ConfigSource != "export" {
			t.Errorf("source %q, config %s", s.Result.ConfigSource, s.Result.Docs["config"])
		}
		b := readFile(t, l.Path())
		if !strings.Contains(string(b), "[WARN] [API] lab: template not merged: ") ||
			strings.Contains(string(b), "secret-name") || strings.Contains(string(b), "192.0.2.1") {
			t.Errorf("log:\n%s", b)
		}
	})
}
