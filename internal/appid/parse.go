package appid

import (
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
)

// App is one application: a predefined application of the content file, or a
// custom application that the caller builds from the configuration. Callers
// must not change its slices or its map: they belong to the Data.
type App struct {
	Name, Category, Subcategory, Technology string
	Risk                                    int
	// Flags holds every yes/no child of the entry by its content name:
	// evasive-behavior, is-saas, new-appid, ident-by-dport, ident-by-sport, …
	// A child that holds no is false and present.
	Flags map[string]bool
	// Tags are the tag members verbatim, with their brackets: "[Web App]" (F9).
	Tags []string
	SaaS SaaS
	// Default is the application-default of the application.
	Default Default
	// ImplicitUse, Use and Tunnel are the members of implicit-use-applications,
	// use-applications and tunnel-applications. Tunnel is as written: its names
	// can be unknown (F15).
	ImplicitUse, Use, Tunnel []string
	// Container names the application's container, if any (S9). Parent is
	// parent-app as written: it can name no application (F15).
	Container, Parent, Description string
	Obsolete                       bool // obsolete yes (F13)
	Custom                         bool // a custom application of the configuration
}

// SaaS holds the children of an application's saas block that hold yes (F8).
type SaaS struct {
	Risks          []string // children of saas, such as is-data-breaches
	Certifications []string // children of saas/certifications, such as is-soc2
	Block          bool     // the application has a saas block (F17)
}

// Container is an application container and its functions (S9).
type Container struct {
	Name      string
	Functions []string
}

// Default is the default block of an application (F10, P1-P6).
type Default struct {
	Ports      []PortRange
	IPProtocol int // ident-by-ip-protocol; 0 for none (P4)
	// IPProtocolHigh is the end of an ident-by-ip-protocol range such as
	// "253-254"; 0 for a single protocol. Content 9160-10295 on fw02 holds
	// that form (docs/lab/app-id-lab.md).
	IPProtocolHigh int
	ICMP, ICMP6    bool // ident-by-icmp-type, ident-by-icmp6-type (P5)
	None           bool // no default block, custom or predefined (P6)
}

// PortRange is one port or port range of a default/port or
// default/extended-port member.
type PortRange struct {
	Protocol  string // tcp, udp, sctp, icmp, icmp6
	Low, High uint16
	AnyPort   bool // dynamic or any (P3, P11)
	Secure    bool // an extended-port member with /secure (P2)
}

// Data is the parsed content file of one content version. It is read-only
// once parsed (AGENTS.md R2).
type Data struct {
	version    string
	containers bool
	apps       []App          // by name
	byName     map[string]int // lower-case name -> index in apps
	conts      map[string]Container
	// The reverse maps, built at parse time, by lower-case application name:
	// the containers that hold a function (S9) and the content applications
	// whose implicit-use-applications hold an application (I1).
	containerOf map[string][]string
	impliedBy   map[string][]string
}

// Version is the content version of the file, such as 8000-1000.
func (d *Data) Version() string { return d.version }

// HasContainers reports whether the file holds the containers. It is false
// when the device answered the applications and not the containers (§2.2).
func (d *Data) HasContainers() bool { return d.containers }

// App finds an application by name in any case: the device matches a flow's
// application without regard to case (P14). App.Name is the content name,
// which is lower case (F14).
func (d *Data) App(name string) (App, bool) {
	i, ok := d.byName[strings.ToLower(name)]
	if !ok {
		return App{}, false
	}
	return d.apps[i], true
}

// Container finds a container by name in any case (P14, F14).
func (d *Data) Container(name string) (Container, bool) {
	c, ok := d.conts[strings.ToLower(name)]
	return c, ok
}

// Apps returns every application, by name.
func (d *Data) Apps() []App { return slices.Clone(d.apps) }

// Load reads a content file.
func Load(path string) (*Data, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	d, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

// node is a generic element of the content file.
type node struct {
	XMLName    xml.Name
	Name       string `xml:"name,attr"`
	Version    string `xml:"version,attr"`
	Trim       string `xml:"trim,attr"`
	Containers string `xml:"containers,attr"`
	Text       string `xml:",chardata"`
	Kids       []node `xml:",any"`
}

// Parse reads a gzipped content file, as Encode writes it. A damaged file is
// an error, never a partial answer.
func Parse(r io.Reader) (*Data, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("read the content file: %w", err)
	}
	var root node
	if err := xml.NewDecoder(zr).Decode(&root); err != nil {
		return nil, fmt.Errorf("read the content file: %w", err)
	}
	// Read to the end, so that the gzip checksum catches a damaged file.
	//nolint:gosec // G110: the file is the store's own content file, written by Encode
	if _, err := io.Copy(io.Discard, zr); err != nil {
		return nil, fmt.Errorf("read the content file: %w", err)
	}
	switch {
	case root.XMLName.Local != "content":
		return nil, fmt.Errorf("the root is <%s>, not <content>", root.XMLName.Local)
	case !ValidVersion(root.Version):
		return nil, fmt.Errorf("content version %q is not of the form <number>-<number>", root.Version)
	case root.Trim != strconv.Itoa(TrimVersion):
		return nil, fmt.Errorf("trim version %q, want %d", root.Trim, TrimVersion)
	}
	d := &Data{
		version:    root.Version,
		containers: root.Containers != "missing",
		byName:     map[string]int{},
		conts:      map[string]Container{},
	}
	for _, list := range root.Kids {
		for _, e := range list.Kids {
			if e.Name == "" {
				return nil, fmt.Errorf("a <%s> entry has no name", list.XMLName.Local)
			}
			key := strings.ToLower(e.Name)
			switch list.XMLName.Local {
			case "application":
				// The device filters by release, so an answer never holds two
				// entries of one name (F7). If a file does, the first counts.
				if _, dup := d.byName[key]; dup {
					continue
				}
				a, err := readApp(e)
				if err != nil {
					return nil, fmt.Errorf("application %s: %w", e.Name, err)
				}
				d.byName[key] = len(d.apps)
				d.apps = append(d.apps, a)
			case "application-container":
				if _, dup := d.conts[key]; !dup {
					d.conts[key] = Container{Name: e.Name, Functions: members(first(e)["functions"])}
				}
			}
		}
	}
	slices.SortFunc(d.apps, func(a, b App) int { return strings.Compare(a.Name, b.Name) })
	for i, a := range d.apps {
		d.byName[strings.ToLower(a.Name)] = i
	}
	d.reverse()
	return d, nil
}

// reverse builds the reverse maps. The applications are sorted by name, so
// each list of implying applications is too.
func (d *Data) reverse() {
	d.containerOf = map[string][]string{}
	d.impliedBy = map[string][]string{}
	for _, c := range d.conts {
		for _, fn := range c.Functions {
			key := strings.ToLower(fn)
			if !slices.Contains(d.containerOf[key], c.Name) {
				d.containerOf[key] = append(d.containerOf[key], c.Name)
			}
		}
	}
	for _, names := range d.containerOf {
		slices.Sort(names)
	}
	for _, a := range d.apps {
		for _, m := range a.ImplicitUse {
			key := strings.ToLower(m)
			if !slices.Contains(d.impliedBy[key], a.Name) {
				d.impliedBy[key] = append(d.impliedBy[key], a.Name)
			}
		}
	}
}

// ContainersOf returns the containers whose functions hold app, by name. The
// name takes any case (P14). A container in a rule matches each of its
// functions (S9). The content data puts no app in two containers (F15). The
// answer is nil when the file lacks the containers (§2.2).
func (d *Data) ContainersOf(app string) []string {
	return slices.Clone(d.containerOf[strings.ToLower(app)])
}

// ImpliedBy returns the content applications whose implicit-use-applications
// hold app, by name (I1). An allow rule that names one of them also matches
// app. The reverse does not hold (I3): use-applications do not count. Only
// content applications imply: as observed on fw02, PAN-OS 12.2.3, a custom
// application refuses implicit-use-applications (spec 2026-10-16 I9), and the
// file holds no custom application.
func (d *Data) ImpliedBy(app string) []string {
	return slices.Clone(d.impliedBy[strings.ToLower(app)])
}

// Suggest returns up to n application names for a name that is no
// application. For a container, they are its functions: the device refuses a
// container as the flow's application (P10). Otherwise they are the names
// nearest to name, in any case: the names within a small edit distance and
// the names that hold name, nearest first.
func (d *Data) Suggest(name string, n int) []string {
	if n <= 0 {
		return nil
	}
	if c, ok := d.Container(name); ok {
		return slices.Clone(c.Functions[:min(n, len(c.Functions))])
	}
	q := strings.ToLower(name)
	limit := max(2, len(q)/3)
	type near struct {
		name string
		dist int
	}
	var found []near
	for _, a := range d.apps {
		lower := strings.ToLower(a.Name)
		if dist := distance(q, lower); dist <= limit || strings.Contains(lower, q) {
			found = append(found, near{a.Name, dist})
		}
	}
	slices.SortStableFunc(found, func(a, b near) int { return a.dist - b.dist })
	var out []string
	for _, f := range found[:min(n, len(found))] {
		out = append(out, f.name)
	}
	return out
}

// distance is the Levenshtein distance of two names, by byte. It only ranks
// suggestions, so a multi-byte letter that counts as several edits does no
// harm.
func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// first returns the first child of each name. The device filters by release,
// so an answer never holds two children of one name (F7); if a file does, the
// first counts.
func first(e node) map[string]node {
	out := make(map[string]node, len(e.Kids))
	for _, k := range e.Kids {
		if _, dup := out[k.XMLName.Local]; !dup {
			out[k.XMLName.Local] = k
		}
	}
	return out
}

// members returns the text of each member child, verbatim.
func members(n node) []string {
	var out []string
	for _, m := range n.Kids {
		if m.XMLName.Local == "member" {
			out = append(out, m.Text)
		}
	}
	return out
}

// readApp reads one application entry.
func readApp(e node) (App, error) {
	a := App{Name: e.Name, Flags: map[string]bool{}, Default: Default{None: true}}
	for name, k := range first(e) {
		text := strings.TrimSpace(k.Text)
		switch name {
		case "category":
			a.Category = text
		case "subcategory":
			a.Subcategory = text
		case "technology":
			a.Technology = text
		case "description":
			a.Description = text
		case "risk":
			r, err := strconv.Atoi(text)
			if err != nil {
				return App{}, fmt.Errorf("risk %q: %w", text, err)
			}
			a.Risk = r
		case "tag":
			a.Tags = members(k)
		case "saas":
			a.SaaS = readSaaS(k)
		case "default":
			def, err := readDefault(k)
			if err != nil {
				return App{}, err
			}
			a.Default = def
		case "implicit-use-applications":
			a.ImplicitUse = members(k)
		case "use-applications":
			a.Use = members(k)
		case "tunnel-applications":
			a.Tunnel = members(k)
		case "application-container":
			a.Container = text
		case "parent-app":
			a.Parent = text
		case "obsolete":
			a.Obsolete = text == "yes"
		default:
			if text == "yes" || text == "no" {
				a.Flags[name] = text == "yes"
			}
		}
	}
	return a, nil
}

// readSaaS reads the children of a saas block that hold yes (F8, S6).
func readSaaS(n node) SaaS {
	s := SaaS{Block: true}
	for name, k := range first(n) {
		if name == "certifications" {
			for cert, c := range first(k) {
				if strings.TrimSpace(c.Text) == "yes" {
					s.Certifications = append(s.Certifications, cert)
				}
			}
			continue
		}
		if strings.TrimSpace(k.Text) == "yes" {
			s.Risks = append(s.Risks, name)
		}
	}
	slices.Sort(s.Risks)
	slices.Sort(s.Certifications)
	return s
}

// readDefault reads a default block in the forms of F10 and F11. A block
// that names no form counts as no block: the two captures hold no such block,
// and the device expands an app without a default to any (P6).
func readDefault(n node) (Default, error) {
	kids := first(n)
	for name := range kids {
		if !defaultForms[name] {
			return Default{}, fmt.Errorf("default holds the unknown form <%s>", name)
		}
	}
	var ipProtocol *string
	if k, ok := kids["ident-by-ip-protocol"]; ok {
		ipProtocol = &k.Text
	}
	_, icmp := kids["ident-by-icmp-type"]
	_, icmp6 := kids["ident-by-icmp6-type"]
	return makeDefault(members(kids["port"]), members(kids["extended-port"]), ipProtocol, icmp, icmp6)
}

// CustomDefault reads the default block of a custom application from the
// configuration: the members of default/port, the text of
// default/ident-by-ip-protocol ("" for none), and whether
// default/ident-by-icmp-type and default/ident-by-icmp6-type are present. A
// custom application takes its default ports from that block, in the forms
// of P1-P5 (spec 2026-10-16 P7). A block that names no form, or no block,
// allows every protocol and port (P6).
func CustomDefault(ports []string, ipProtocol string, icmp, icmp6 bool) (Default, error) {
	var ip *string
	if ipProtocol != "" {
		ip = &ipProtocol
	}
	return makeDefault(ports, nil, ip, icmp, icmp6)
}

// makeDefault builds a default from its forms. ipProtocol is nil when the
// block holds no ident-by-ip-protocol.
func makeDefault(port, extended []string, ipProtocol *string, icmp, icmp6 bool) (Default, error) {
	var d Default
	for i, list := range [][]string{port, extended} {
		for _, m := range list {
			ports, err := parsePorts(m, i == 1)
			if err != nil {
				return Default{}, err
			}
			d.Ports = append(d.Ports, ports...)
		}
	}
	if ipProtocol != nil {
		lo, hi, err := parseIPProtocol(*ipProtocol)
		if err != nil {
			return Default{}, err
		}
		d.IPProtocol, d.IPProtocolHigh = lo, hi
	}
	d.ICMP, d.ICMP6 = icmp, icmp6
	d.None = len(d.Ports) == 0 && d.IPProtocol == 0 && !d.ICMP && !d.ICMP6
	return d, nil
}

// parseIPProtocol reads an ident-by-ip-protocol value: one protocol number,
// or a range "N-M" with N < M. hi is 0 for one protocol.
func parseIPProtocol(v string) (lo, hi int, err error) {
	v = strings.TrimSpace(v)
	first, last, isRange := strings.Cut(v, "-")
	l, err := strconv.ParseUint(strings.TrimSpace(first), 10, 8)
	if err != nil {
		return 0, 0, fmt.Errorf("ident-by-ip-protocol %q: %w", v, err)
	}
	if !isRange {
		return int(l), 0, nil
	}
	h, err := strconv.ParseUint(strings.TrimSpace(last), 10, 8)
	if err != nil {
		return 0, 0, fmt.Errorf("ident-by-ip-protocol %q: %w", v, err)
	}
	if h <= l {
		return 0, 0, fmt.Errorf("ident-by-ip-protocol %q: the range is empty", v)
	}
	return int(l), int(h), nil
}

// defaultForms are the children a default block can hold (F10, F11, P4, P5).
var defaultForms = map[string]bool{
	"port": true, "extended-port": true, "ident-by-ip-protocol": true,
	"ident-by-icmp-type": true, "ident-by-icmp6-type": true,
}

// portProtocols are the protocols a port member names (F10, P5: content
// writes icmp6).
var portProtocols = map[string]bool{"tcp": true, "udp": true, "sctp": true, "icmp": true, "icmp6": true}

// parsePorts reads one port member: tcp/80,443 and tcp/80, 443 (F10), a range
// tcp/1024-1030, dynamic and any (P3, P11), and in extended-port a /secure
// suffix that can hold a list: tcp/636,3269/secure (P2, F11).
func parsePorts(member string, extended bool) ([]PortRange, error) {
	parts := strings.Split(strings.TrimSpace(member), "/")
	secure := false
	switch {
	case len(parts) == 3 && extended && parts[2] == "secure":
		secure = true
	case len(parts) != 2:
		return nil, fmt.Errorf("port member %q has no form of F10", member)
	}
	proto := strings.ToLower(strings.TrimSpace(parts[0]))
	if !portProtocols[proto] {
		return nil, fmt.Errorf("port member %q: unknown protocol %q", member, proto)
	}
	var out []PortRange
	for item := range strings.SplitSeq(parts[1], ",") {
		item = strings.TrimSpace(item)
		if item == "dynamic" || item == "any" {
			out = append(out, PortRange{Protocol: proto, AnyPort: true, Secure: secure})
			continue
		}
		lo, hi, isRange := strings.Cut(item, "-")
		low, err := port(lo)
		high := low
		if err == nil && isRange {
			high, err = port(hi)
		}
		if err == nil && high < low {
			err = errors.New("the range ends below its start")
		}
		if err != nil {
			return nil, fmt.Errorf("port member %q: %w", member, err)
		}
		out = append(out, PortRange{Protocol: proto, Low: low, High: high, Secure: secure})
	}
	return out, nil
}

// port reads a port number, 1-65535.
func port(s string) (uint16, error) {
	p, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, err
	}
	if p == 0 {
		return 0, errors.New("port 0")
	}
	return uint16(p), nil
}
