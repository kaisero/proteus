package appid_test

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/appid"
	"github.com/okaiser/proteus/internal/testconfig"
)

const fixtures = "../../testdata/appid/"

// trimFile trims one answer fixture and returns the trimmed bytes and the
// number of entries.
func trimFile(t *testing.T, name string) ([]byte, int) {
	t.Helper()
	f, err := os.Open(fixtures + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var b bytes.Buffer
	n, err := appid.Trim(f, &b)
	if err != nil {
		t.Fatal(err)
	}
	return b.Bytes(), n
}

// element is a generic tree of trimmed XML.
type element struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Text    string     `xml:",chardata"`
	Kids    []element  `xml:",any"`
}

// entries reads the entries of a trimmed fragment.
func entries(t *testing.T, trimmed []byte) []element {
	t.Helper()
	var root element
	if err := xml.Unmarshal([]byte("<root>"+string(trimmed)+"</root>"), &root); err != nil {
		t.Fatalf("the trimmed output is no XML: %v\n%s", err, trimmed)
	}
	return root.Kids
}

func (e element) kid(name string) (element, bool) {
	for _, k := range e.Kids {
		if k.XMLName.Local == name {
			return k, true
		}
	}
	return element{}, false
}

// keptFields is the §3.2 table of spec 2026-10-16, for TrimVersion 1.
var keptFields = []string{
	"category", "subcategory", "technology", "risk",
	"evasive-behavior", "consume-big-bandwidth", "used-by-malware", "able-to-transfer-file",
	"has-known-vulnerability", "tunnel-other-application", "prone-to-misuse", "pervasive-use",
	"is-saas", "new-appid",
	"tag", "saas", "default",
	"implicit-use-applications", "use-applications", "tunnel-applications",
	"application-container", "parent-app",
	"ident-by-dport", "ident-by-sport",
	"obsolete", "description", "functions",
}

// Spec 2026-10-16 §3.2: the trim keeps every kept field and drops the rest.
func TestTrimKeepsOnlyTheKeptFields(t *testing.T) {
	t.Parallel()
	trimmed, _ := trimFile(t, "answer-applications.xml")
	seen := map[string]bool{}
	for _, e := range entries(t, trimmed) {
		for _, k := range e.Kids {
			seen[k.XMLName.Local] = true
			if !appid.Kept(k.XMLName.Local) {
				t.Errorf("%s keeps %s, which is no kept field", e.Attrs, k.XMLName.Local)
			}
		}
	}
	for _, f := range keptFields {
		if f != "functions" && !seen[f] {
			t.Errorf("the trim lost the kept field %s", f)
		}
	}
	for _, f := range []string{"icon", "references", "decoder", "timeout", "link"} {
		if seen[f] || bytes.Contains(trimmed, []byte("<"+f)) {
			t.Errorf("the trim kept %s", f)
		}
	}
	if bytes.Contains(trimmed, []byte("<!--")) {
		t.Error("the trim kept a comment")
	}
}

// F7, §3.3: the entry's @name is the only attribute the trim keeps.
func TestTrimDropsTheAttributes(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"answer-applications.xml", "answer-containers.xml"} {
		trimmed, _ := trimFile(t, name)
		dec := xml.NewDecoder(bytes.NewReader([]byte("<root>" + string(trimmed) + "</root>")))
		depth := 0
		for {
			tok, err := dec.Token()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			switch tok := tok.(type) {
			case xml.StartElement:
				depth++
				want := 0
				if depth == 2 {
					want = 1
					if tok.Name.Local != "entry" || len(tok.Attr) != 1 || tok.Attr[0].Name.Local != "name" {
						t.Errorf("%s: entry %v, want only @name", name, tok.Attr)
					}
				}
				if len(tok.Attr) != want {
					t.Errorf("%s: <%s> keeps %v", name, tok.Name.Local, tok.Attr)
				}
			case xml.EndElement:
				depth--
			}
		}
		for _, a := range []string{"id=", "minver", "ori_country", "ori_language", "pre_ottawa_name"} {
			if bytes.Contains(trimmed, []byte(a)) {
				t.Errorf("%s: the trim kept %s", name, a)
			}
		}
	}
}

// S9, §3.2: a container keeps its description and its functions.
func TestTrimKeepsContainerFunctions(t *testing.T) {
	t.Parallel()
	trimmed, _ := trimFile(t, "answer-containers.xml")
	es := entries(t, trimmed)
	if len(es) != 1 {
		t.Fatalf("%d containers, want 1", len(es))
	}
	if d, ok := es[0].kid("description"); !ok || d.Text != "Dummy description of office-suite." {
		t.Errorf("description %q, %v", d.Text, ok)
	}
	fn, _ := es[0].kid("functions")
	var members []string
	for _, m := range fn.Kids {
		members = append(members, m.Text)
	}
	if !slices.Equal(members, []string{"office-docs", "office-mail"}) {
		t.Errorf("functions %v", members)
	}
}

// F1: Trim counts the entries it writes.
func TestTrimCountsEntries(t *testing.T) {
	t.Parallel()
	if _, n := trimFile(t, "answer-applications.xml"); n != 11 {
		t.Errorf("%d applications, want 11", n)
	}
	if _, n := trimFile(t, "answer-containers.xml"); n != 1 {
		t.Errorf("%d containers, want 1", n)
	}
}

// §2.2: an error answer is a refusal, with the device's code and message.
func TestTrimRefusal(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	_, err := appid.Trim(strings.NewReader(
		`<response status="error" code="17"><msg><line>dummy  refusal</line></msg></response>`), &b)
	refused, ok := errors.AsType[*appid.RefusedError](err)
	if !ok {
		t.Fatalf("err %v, want a *RefusedError", err)
	}
	if refused.Code != "17" || refused.Message != "dummy refusal" {
		t.Errorf("refusal %+v", refused)
	}
	if got := refused.Error(); got != "the device refused the App-ID data (code 17): dummy refusal" {
		t.Errorf("Error() = %q", got)
	}
	if b.Len() != 0 {
		t.Errorf("a refusal wrote %q", b.String())
	}
	bare := &appid.RefusedError{}
	if got := bare.Error(); got != "the device refused the App-ID data: no message" {
		t.Errorf("Error() = %q", got)
	}
}

// §2.2: a success answer without an entry gives ErrNoEntries (F16: "No data found").
func TestTrimNoEntries(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		`<response status="success"><result><msg>No data found</msg></result></response>`,
		`<response status="success"><result><application/></result></response>`,
		// An entry outside result/application is no application.
		`<response status="success"><result><other><entry name="x"/></other></result></response>`,
	} {
		if _, err := appid.Trim(strings.NewReader(in), io.Discard); !errors.Is(err, appid.ErrNoEntries) {
			t.Errorf("%s: err %v, want ErrNoEntries", in, err)
		}
	}
}

// An answer that is not a PAN-OS response is an error, not an empty answer.
func TestTrimRefusesOtherInput(t *testing.T) {
	t.Parallel()
	for _, in := range []string{`<config/>`, `<response status="success"><result>`, `not xml`} {
		if _, err := appid.Trim(strings.NewReader(in), io.Discard); err == nil || errors.Is(err, appid.ErrNoEntries) {
			t.Errorf("%s: err %v", in, err)
		}
	}
}

// A write error reaches the caller.
func TestTrimWriteError(t *testing.T) {
	t.Parallel()
	f, err := os.Open(fixtures + "answer-applications.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := appid.Trim(f, failWriter{}); !errors.Is(err, errWrite) {
		t.Errorf("err %v, want the write error", err)
	}
}

var errWrite = errors.New("dummy write error")

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errWrite }

// encodeFixtures trims both answers and encodes them as one content file.
func encodeFixtures(t *testing.T, withContainers bool) []byte {
	t.Helper()
	apps, _ := trimFile(t, "answer-applications.xml")
	var containers []byte
	if withContainers {
		containers, _ = trimFile(t, "answer-containers.xml")
	}
	var b bytes.Buffer
	if err := appid.Encode(&b, "8000-1000", apps, containers); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// §3.2: Parse reads what Encode writes.
func TestEncodeParseRoundTrip(t *testing.T) {
	t.Parallel()
	d, err := appid.Parse(bytes.NewReader(encodeFixtures(t, true)))
	if err != nil {
		t.Fatal(err)
	}
	if d.Version() != "8000-1000" || !d.HasContainers() {
		t.Errorf("version %q, containers %v", d.Version(), d.HasContainers())
	}
	var names []string
	for _, a := range d.Apps() {
		names = append(names, a.Name)
	}
	want := []string{
		"app-media", "app-new", "app-nodefault", "app-old", "app-parent", "app-remote",
		"app-saas-a", "dns", "office-docs", "ssl", "web-browsing",
	}
	if !slices.Equal(names, want) {
		t.Errorf("apps %v\nwant %v", names, want)
	}
	if c, ok := d.Container("office-suite"); !ok || len(c.Functions) != 2 {
		t.Errorf("container %+v, %v", c, ok)
	}
}

// §2.2: Encode without containers records that they are missing.
func TestEncodeRecordsMissingContainers(t *testing.T) {
	t.Parallel()
	d, err := appid.Parse(bytes.NewReader(encodeFixtures(t, false)))
	if err != nil {
		t.Fatal(err)
	}
	if d.HasContainers() {
		t.Error("HasContainers is true for a file without containers")
	}
	if _, ok := d.Container("office-suite"); ok {
		t.Error("a file without containers finds a container")
	}
	// An empty, non-nil list is a container answer with nothing in it.
	var b bytes.Buffer
	if err := appid.Encode(&b, "8000-1000", nil, []byte{}); err != nil {
		t.Fatal(err)
	}
	if d, err := appid.Parse(&b); err != nil || !d.HasContainers() || len(d.Apps()) != 0 {
		t.Errorf("empty lists: %v, %v", d, err)
	}
}

func TestEncodeRefusesABadVersion(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	if err := appid.Encode(&b, "../x", nil, nil); err == nil || b.Len() != 0 {
		t.Errorf("err %v, wrote %d bytes", err, b.Len())
	}
	if err := appid.Encode(failWriter{}, "8000-1000", nil, nil); !errors.Is(err, errWrite) {
		t.Errorf("err %v, want the write error", err)
	}
}

// §2.2: a content version becomes a file name only in the shape ^[0-9]+-[0-9]+$.
func TestValidVersion(t *testing.T) {
	t.Parallel()
	for v, want := range map[string]bool{
		"9159-10287": true, "8000-1000": true,
		"": false, "../x": false, "1-2-3": false, "9159-": false, "-1": false, "a-1": false,
	} {
		if got := appid.ValidVersion(v); got != want {
			t.Errorf("ValidVersion(%q) = %v", v, got)
		}
	}
}

// §3.1: the file name carries the content version and the trim version.
func TestFileName(t *testing.T) {
	t.Parallel()
	if got := appid.FileName("8000-1000"); got != "8000-1000.v1.xml.gz" {
		t.Errorf("FileName = %q", got)
	}
}

// §3.2: a change to the kept fields must increment TrimVersion, so the old
// files give a miss. Update the pinned list and TrimVersion together.
func TestTrimVersionGuardsTheKeptFields(t *testing.T) {
	t.Parallel()
	if appid.TrimVersion != 1 {
		t.Fatalf("TrimVersion %d: pin the kept fields of the new version here", appid.TrimVersion)
	}
	got := appid.KeptFields()
	if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(keptFields))) {
		t.Errorf("kept fields %v\npinned for TrimVersion 1: %v", got, keptFields)
	}
	for _, f := range keptFields {
		if !appid.Kept(f) {
			t.Errorf("Kept(%q) is false", f)
		}
	}
	if appid.Kept("icon") {
		t.Error("Kept(icon) is true")
	}
}

// loadFixture gzips content.xml and loads it.
func loadFixture(t *testing.T) *appid.Data {
	t.Helper()
	path := filepath.Join(t.TempDir(), appid.FileName("8000-1000"))
	testconfig.Content(t, path)
	d, err := appid.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// I1, S9: the fixture parses, with implicit use and container functions.
func TestParseReadsTheFixture(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	if d.Version() != "8000-1000" || !d.HasContainers() {
		t.Errorf("version %q, containers %v", d.Version(), d.HasContainers())
	}
	remote, ok := d.App("app-remote")
	if !ok || !slices.Equal(remote.ImplicitUse, []string{"ssl", "web-browsing"}) || !slices.Equal(remote.Use, []string{"dns"}) {
		t.Errorf("app-remote %+v, %v", remote, ok)
	}
	c, ok := d.Container("office-suite")
	if !ok || c.Name != "office-suite" || !slices.Equal(c.Functions, []string{"office-docs", "office-mail"}) {
		t.Errorf("office-suite %+v, %v", c, ok)
	}
	if docs, _ := d.App("office-docs"); docs.Container != "office-suite" {
		t.Errorf("office-docs container %q", docs.Container)
	}
	// The applications of the plan's fixture table.
	for _, name := range []string{
		"ssl", "web-browsing", "app-ldap", "app-remote", "app-remote-b", "app-other", "dns",
		"app-media", "app-collab", "app-range", "app-dyn-tcp", "app-dyn-udp", "app-tcp-mixed",
		"app-tcp-any", "ospf", "ping", "ping6", "app-icmp-any", "app-nodefault", "app-saas-a",
		"app-saas-b", "app-saas-c", "app-new", "app-old", "app-parent", "office-docs", "office-mail",
	} {
		if _, ok := d.App(name); !ok {
			t.Errorf("the fixture lacks %s", name)
		}
	}
	if !slices.IsSortedFunc(d.Apps(), func(a, b appid.App) int { return strings.Compare(a.Name, b.Name) }) {
		t.Error("Apps is not sorted by name")
	}
	if _, ok := d.App("no-such-app"); ok {
		t.Error("an unknown name is found")
	}
}

// F8, F9, F12, F13, F15, P6: the parser reads each shape of the content answer.
func TestParseReadsTheShapes(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	app := func(name string) appid.App {
		t.Helper()
		a, ok := d.App(name)
		if !ok {
			t.Fatalf("no %s", name)
		}
		return a
	}
	saasA := app("app-saas-a").SaaS
	if !slices.Equal(saasA.Risks, []string{"is-data-breaches", "is-poor-terms-of-service"}) ||
		!slices.Equal(saasA.Certifications, []string{"is-soc2"}) {
		t.Errorf("app-saas-a saas %+v", saasA)
	}
	for _, name := range []string{"app-saas-b", "app-saas-c"} {
		if s := app(name).SaaS; len(s.Risks) != 0 || len(s.Certifications) != 0 {
			t.Errorf("%s saas %+v, want empty", name, s)
		}
		if !app(name).Flags["is-saas"] {
			t.Errorf("%s is no SaaS app", name)
		}
	}
	media := app("app-media")
	if !slices.Equal(media.Tags, []string{"[Web App]", "[Streaming]"}) {
		t.Errorf("app-media tags %q", media.Tags)
	}
	if media.Category != "media" || media.Subcategory != "sub-a" || media.Technology != "tech-a" || media.Risk != 4 {
		t.Errorf("app-media %+v", media)
	}
	if !media.Flags["evasive-behavior"] || media.Flags["used-by-malware"] {
		t.Errorf("app-media flags %v", media.Flags)
	}
	if _, ok := media.Flags["used-by-malware"]; !ok {
		t.Error("a flag that holds no is absent from Flags")
	}
	ssl := app("ssl")
	if !ssl.Flags["ident-by-dport"] || ssl.Description != "Dummy description of ssl." {
		t.Errorf("ssl %+v", ssl)
	}
	if !app("dns").Flags["ident-by-sport"] || !app("app-new").Flags["new-appid"] {
		t.Error("ident-by-sport or new-appid is lost")
	}
	if !app("app-old").Obsolete || app("ssl").Obsolete {
		t.Error("obsolete is wrong")
	}
	if !app("app-nodefault").Default.None || app("ssl").Default.None {
		t.Error("Default.None is wrong")
	}
	parent := app("app-parent")
	if parent.Parent != "not-an-app" || !slices.Equal(parent.Tunnel, []string{"unknown-tunnel"}) {
		t.Errorf("app-parent %+v", parent)
	}
	if app("ssl").Custom {
		t.Error("a content application is custom")
	}
}

// F10, F11, P3-P5, P11: the parser reads every form of a default block.
func TestParseReadsTheDefaults(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	tcp := func(lo, hi uint16) appid.PortRange { return appid.PortRange{Protocol: "tcp", Low: lo, High: hi} }
	for name, want := range map[string]appid.Default{
		"ssl":        {Ports: []appid.PortRange{tcp(443, 443)}},
		"app-remote": {Ports: []appid.PortRange{tcp(80, 80), tcp(443, 443), tcp(8090, 8090)}},
		"web-browsing": {Ports: []appid.PortRange{
			tcp(80, 80), tcp(80, 80), {Protocol: "tcp", Low: 443, High: 443, Secure: true},
		}},
		"app-ldap": {Ports: []appid.PortRange{
			tcp(389, 389), {Protocol: "tcp", Low: 636, High: 636, Secure: true}, {Protocol: "tcp", Low: 3269, High: 3269, Secure: true},
		}},
		"app-range":     {Ports: []appid.PortRange{tcp(1024, 1030), {Protocol: "udp", Low: 1024, High: 1030}}},
		"app-dyn-udp":   {Ports: []appid.PortRange{{Protocol: "udp", AnyPort: true}}},
		"app-tcp-mixed": {Ports: []appid.PortRange{tcp(80, 80), {Protocol: "tcp", AnyPort: true}}},
		"app-tcp-any":   {Ports: []appid.PortRange{{Protocol: "tcp", AnyPort: true}}},
		"app-icmp-any":  {Ports: []appid.PortRange{{Protocol: "icmp", AnyPort: true}, {Protocol: "icmp6", AnyPort: true}}},
		"ospf":          {IPProtocol: 89},
		"ping":          {ICMP: true},
		"ping6":         {ICMP6: true},
		"app-nodefault": {None: true},
	} {
		got, _ := d.App(name)
		if !slices.Equal(got.Default.Ports, want.Ports) || got.Default.IPProtocol != want.IPProtocol ||
			got.Default.ICMP != want.ICMP || got.Default.ICMP6 != want.ICMP6 || got.Default.None != want.None {
			t.Errorf("%s default %+v\nwant %+v", name, got.Default, want)
		}
	}
}

// gz gzips a content document.
func gz(t *testing.T, doc string) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(doc)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return &b
}

// F7: an answer never holds two children of one name; if a file does, the
// first one counts. Lookups take any case (P14) and keep the content name.
func TestParseTakesTheFirstOfAName(t *testing.T) {
	t.Parallel()
	d, err := appid.Parse(gz(t, `<content version="8000-1000" trim="1"><application>`+
		`<entry name="Dup"><risk>1</risk><risk>5</risk></entry><entry name="dup"><risk>3</risk></entry>`+
		`</application><application-container><entry name="c"><functions><member>Dup</member></functions></entry>`+
		`<entry name="C"/></application-container></content>`))
	if err != nil {
		t.Fatal(err)
	}
	a, ok := d.App("DUP")
	if !ok || a.Name != "Dup" || a.Risk != 1 || len(d.Apps()) != 1 {
		t.Errorf("App(DUP) %+v, %v; %d apps", a, ok, len(d.Apps()))
	}
	if c, ok := d.Container("C"); !ok || c.Name != "c" || len(c.Functions) != 1 {
		t.Errorf("Container(C) %+v, %v", c, ok)
	}
}

// A damaged file is an error, never a partial answer (spec 2026-10-16 §3.4).
func TestParseRefusesADamagedFile(t *testing.T) {
	t.Parallel()
	const head = `<content version="8000-1000" trim="1"><application>`
	const tail = `</application></content>`
	for name, doc := range map[string]string{
		"no xml":            `not xml`,
		"other root":        `<config/>`,
		"bad version":       `<content version="../x" trim="1"/>`,
		"other trim":        `<content version="8000-1000" trim="2"/>`,
		"no name":           head + `<entry><risk>1</risk></entry>` + tail,
		"bad risk":          head + `<entry name="a"><risk>high</risk></entry>` + tail,
		"bad protocol":      head + `<entry name="a"><default><port><member>gre/1</member></port></default></entry>` + tail,
		"no port":           head + `<entry name="a"><default><port><member>tcp</member></port></default></entry>` + tail,
		"bad port":          head + `<entry name="a"><default><port><member>tcp/http</member></port></default></entry>` + tail,
		"port zero":         head + `<entry name="a"><default><port><member>tcp/0</member></port></default></entry>` + tail,
		"bad range":         head + `<entry name="a"><default><port><member>tcp/90-80</member></port></default></entry>` + tail,
		"bad range end":     head + `<entry name="a"><default><port><member>tcp/80-x</member></port></default></entry>` + tail,
		"secure in port":    head + `<entry name="a"><default><port><member>tcp/443/secure</member></port></default></entry>` + tail,
		"other suffix":      head + `<entry name="a"><default><extended-port><member>tcp/443/x</member></extended-port></default></entry>` + tail,
		"bad ip protocol":   head + `<entry name="a"><default><ident-by-ip-protocol>300</ident-by-ip-protocol></default></entry>` + tail,
		"unknown default":   head + `<entry name="a"><default><ident-by-other>1</ident-by-other></default></entry>` + tail,
		"container no name": `<content version="8000-1000" trim="1"><application-container><entry/></application-container></content>`,
	} {
		if _, err := appid.Parse(gz(t, doc)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := appid.Parse(strings.NewReader("not gzip")); err == nil {
		t.Error("plain text: no error")
	}
	// A truncated file fails its gzip check.
	whole := encodeFixtures(t, true)
	if _, err := appid.Parse(bytes.NewReader(whole[:len(whole)-4])); err == nil {
		t.Error("a truncated file: no error")
	}
	if _, err := appid.Load(filepath.Join(t.TempDir(), "missing.xml.gz")); err == nil {
		t.Error("a missing file: no error")
	}
	damaged := filepath.Join(t.TempDir(), "damaged.xml.gz")
	if err := os.WriteFile(damaged, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := appid.Load(damaged); err == nil || !strings.Contains(err.Error(), damaged) {
		t.Errorf("a damaged file: %v, want an error that names it", err)
	}
}

// An empty default block names no form; it counts as no default block (P6).
func TestParseReadsAnEmptyDefault(t *testing.T) {
	t.Parallel()
	d, err := appid.Parse(gz(t, `<content version="8000-1000" trim="1"><application>`+
		`<entry name="a"><default/></entry></application></content>`))
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := d.App("a"); !a.Default.None {
		t.Errorf("default %+v", a.Default)
	}
}
