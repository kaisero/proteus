package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/store"
)

// The lab files, relative to the repository root.
const (
	// VarsFile holds the real values of the placeholders: local, untracked,
	// KEY=value lines (spec 2026-10-16 §9.1).
	VarsFile = "docs/lab/app-id-lab.vars"
	// FlowsFile is the flow list.
	FlowsFile = "docs/lab/app-id-flows.tsv"
)

// vsysXPath is the vsys of a firewall that runs one vsys: a PAN-OS default
// name, not lab data. Every line of the set file is below it.
const vsysXPath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"

// Flow is one line of the flow list, with its placeholders filled.
type Flow struct {
	Case, Fact                    string // "S1-or-ssl"; "S1,I6"
	Source, Destination, From, To string // the placeholders filled
	Protocol                      string // the IP protocol number, "6"
	Port                          int    // 1 for a protocol without ports (P9)
	Application                   string // "" for no application
	Expect                        string // "", "doubt" or "refused"
}

// The expectations a flow can carry.
const (
	expectDoubt   = "doubt"
	expectRefused = "refused"
)

var varKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// ReadVars reads KEY=value lines. A blank line and a line that starts with #
// are skipped. A line without = is an error, and so is a key given twice.
func ReadVars(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case !ok:
			return nil, fmt.Errorf("variables line %d: want KEY=value", n)
		case !varKey.MatchString(k):
			return nil, fmt.Errorf("variables line %d: key %q: want upper case letters, digits and _", n, k)
		case out[k] != "":
			return nil, fmt.Errorf("variables line %d: %s is given twice", n, k)
		}
		out[k] = v
	}
	return out, sc.Err()
}

// placeholder is ${KEY} in a lab file.
var placeholder = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)\}`)

// Fill replaces each ${KEY} with its value from vars. An unknown key is an
// error. A value is not read again for placeholders.
func Fill(s string, vars map[string]string) (string, error) {
	var missing []string
	out := placeholder.ReplaceAllStringFunc(s, func(m string) string {
		k := placeholder.FindStringSubmatch(m)[1]
		v, ok := vars[k]
		if !ok {
			missing = append(missing, k)
			return m
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("no value for %s in %s", strings.Join(missing, ", "), VarsFile)
	}
	return out, nil
}

// flowColumns are the columns of the flow list, in order.
var flowColumns = []string{"case", "fact", "from", "to", "source", "destination", "protocol", "port", "application", "expected"}

// safeCase is a case name that can name an output file.
var safeCase = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ReadFlows reads the flow list: a header line, then one tab-separated flow
// per line. A blank line and a line that starts with # are skipped. - is an
// empty port, application or expectation. A protocol without ports takes port
// 1, as the device command needs (P9).
func ReadFlows(r io.Reader, vars map[string]string) ([]Flow, error) {
	var out []Flow
	seen := map[string]bool{}
	header := false
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !header {
			if line != strings.Join(flowColumns, "\t") {
				return nil, fmt.Errorf("flows line %d: want the header %q", n, strings.Join(flowColumns, " "))
			}
			header = true
			continue
		}
		filled, err := Fill(line, vars)
		if err != nil {
			return nil, fmt.Errorf("flows line %d: %w", n, err)
		}
		f, err := parseFlow(strings.Split(filled, "\t"))
		if err != nil {
			return nil, fmt.Errorf("flows line %d: %w", n, err)
		}
		if seen[f.Case] {
			return nil, fmt.Errorf("flows line %d: case %s is given twice", n, f.Case)
		}
		seen[f.Case] = true
		out = append(out, f)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !header {
		return nil, errors.New("flows: no header line")
	}
	return out, nil
}

func parseFlow(cols []string) (Flow, error) {
	if len(cols) != len(flowColumns) {
		return Flow{}, fmt.Errorf("%d columns, want %d", len(cols), len(flowColumns))
	}
	dash := func(s string) string {
		if s == "-" {
			return ""
		}
		return s
	}
	f := Flow{
		Case: cols[0], Fact: cols[1], From: cols[2], To: cols[3], Source: cols[4], Destination: cols[5],
		Application: dash(cols[8]), Expect: dash(cols[9]),
	}
	if !safeCase.MatchString(f.Case) {
		return Flow{}, fmt.Errorf("case %q: want letters, digits, '.', '_' or '-'", f.Case)
	}
	for _, v := range []string{f.Fact, f.From, f.To, f.Source, f.Destination} {
		if v == "" {
			return Flow{}, fmt.Errorf("%s: a column is empty", f.Case)
		}
	}
	proto, ok := protocolNumber(cols[6])
	if !ok {
		return Flow{}, fmt.Errorf("%s: protocol %q: want a name or a number 0-255", f.Case, cols[6])
	}
	f.Protocol = proto
	switch port := dash(cols[7]); {
	case portless(proto) && (port == "" || port == "1"):
		f.Port = 1
	case portless(proto):
		return Flow{}, fmt.Errorf("%s: protocol %s has no ports: give - as the port", f.Case, proto)
	case port == "":
		return Flow{}, fmt.Errorf("%s: protocol %s needs a port", f.Case, proto)
	default:
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return Flow{}, fmt.Errorf("%s: port %q: want 1-65535", f.Case, port)
		}
		f.Port = p
	}
	switch f.Expect {
	case "", expectDoubt:
	case expectRefused:
		if f.Application == "" {
			return Flow{}, fmt.Errorf("%s: a refusal needs an application", f.Case)
		}
	default:
		return Flow{}, fmt.Errorf("%s: expected %q: want -, doubt or refused", f.Case, f.Expect)
	}
	return f, nil
}

// protocolNames are the protocol names the flow list may use, by IANA number.
var protocolNames = map[string]string{"tcp": "6", "udp": "17", "sctp": "132", "icmp": "1", "icmp6": "58", "ipv6-icmp": "58"}

// protocolNumber returns the IP protocol number of a name or a number.
func protocolNumber(p string) (string, bool) {
	if n, ok := protocolNames[strings.ToLower(p)]; ok {
		return n, true
	}
	n, err := strconv.ParseUint(p, 10, 8)
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(n, 10), true
}

// portless reports whether a protocol number has no ports: all but TCP, UDP
// and SCTP.
func portless(proto string) bool {
	return proto != "6" && proto != "17" && proto != "132"
}

// DeviceCmd is the device's test security-policy-match command for a flow.
// The command needs a destination port in 1-65535, also for a protocol
// without ports, so such a flow gets port 1, as observed on the lab VM,
// PAN-OS 12.1.9 (spec 2026-10-16 P9). A flow without an application leaves
// the element out.
func DeviceCmd(f Flow) string {
	port := f.Port
	if port < 1 || portless(f.Protocol) {
		port = 1
	}
	var b strings.Builder
	b.WriteString("<test><security-policy-match>")
	el := func(name, v string) {
		b.WriteString("<" + name + ">")
		_ = xml.EscapeText(&b, []byte(v))
		b.WriteString("</" + name + ">")
	}
	el("from", f.From)
	el("to", f.To)
	el("source", f.Source)
	el("destination", f.Destination)
	el("protocol", f.Protocol)
	el("destination-port", strconv.Itoa(port))
	if f.Application != "" {
		el("application", f.Application)
	}
	b.WriteString("</security-policy-match></test>")
	return b.String()
}

// ProteusArgs are the arguments of proteus simulate policy for a flow, on the
// copied configuration. proteus gets the flow's protocol number. It gets no
// port for a protocol without ports: such a flow matches no custom service
// and no service group (P13), and an application default decides it by the
// protocol alone (§4.4), so port 1 would mean nothing there.
func ProteusArgs(f Flow, configFile, vsys string) []string {
	args := []string{
		"simulate", "policy", f.Source, f.Destination, "--file", configFile, "--vsys", vsys,
		"--from-zone", f.From, "--to-zone", f.To, "--protocol", f.Protocol, "--no-dns", "--output", "json",
	}
	if !portless(f.Protocol) {
		args = append(args, "--port", strconv.Itoa(f.Port))
	}
	if f.Application != "" {
		args = append(args, "--application", f.Application)
	}
	return args
}

// Answer is what one side says about a flow: the rule and its action, whether
// the rule matches through implicit use, whether it is a default rule, and
// whether the side refused the application. A device answer with no rule has
// Rule "".
type Answer struct {
	Rule, Action               string
	Implicit, Default, Refused bool
}

func (a Answer) String() string {
	switch {
	case a.Refused:
		return "refused"
	case a.Rule == "":
		return "no rule"
	}
	s := a.Rule + " (" + a.Action
	if a.Implicit {
		s += ", implicit"
	}
	if a.Default {
		s += ", default rule"
	}
	return s + ")"
}

// unrecognized is the device's refusal of a container or an unknown name as
// the flow's application, as observed on the lab VM, PAN-OS 12.1.9 (spec
// 2026-10-16 P10).
const unrecognized = "Unrecognized application"

// implicitMarker is how the device marks a rule that matches the flow's
// application through implicit use: "ssl/application-default(implicit)", as
// observed on the lab VM, PAN-OS 12.1.9 (spec 2026-10-16 I1).
const implicitMarker = "(implicit)"

// implicitElement is the XML API form of the same mark: an <Implicit>
// element right before the entry that matches through implicit use, as
// observed on fw02, PAN-OS 12.2.3 (docs/lab/app-id-lab.md).
const implicitElement = "Implicit"

// ParseDevice reads the device's answer to DeviceCmd. err is the error of the
// call; an "Unrecognized application" refusal, in the answer or in err, gives
// Refused. An answer without a rule gives Rule "": the command never lists the
// default rules (spec 2026-10-16 I6).
func ParseDevice(b []byte, err error) (Answer, error) {
	if bytes.Contains(b, []byte(unrecognized)) || err != nil && strings.Contains(err.Error(), unrecognized) {
		return Answer{Refused: true}, nil
	}
	if err != nil {
		return Answer{}, err
	}
	var r struct {
		Status string `xml:"status,attr"`
		// PAN-OS writes a message as <msg>text</msg> or as
		// <msg><line>text</line></msg>.
		Msg struct {
			Text  string   `xml:",chardata"`
			Lines []string `xml:"line"`
		} `xml:"msg"`
		// Items keeps the children of rules in order, so an <Implicit>
		// element marks the entry after it.
		Result struct {
			Rules struct {
				Items []struct {
					XMLName xml.Name
					Name    string `xml:"name,attr"`
					Text    string `xml:",chardata"`
					Action  string `xml:"action"`
					Inner   string `xml:",innerxml"`
				} `xml:",any"`
			} `xml:"rules"`
		} `xml:"result"`
	}
	if err := xml.Unmarshal(b, &r); err != nil {
		return Answer{}, fmt.Errorf("the device answer is not XML: %w", err)
	}
	if r.Status != "success" {
		msg := strings.Join(strings.Fields(strings.Join(append(r.Msg.Lines, r.Msg.Text), " ")), " ")
		return Answer{}, fmt.Errorf("the device refused the command: %s", msg)
	}
	// The first entry is the first match: on fw02 the answer can list more.
	first, implicit := -1, false
	items := r.Result.Rules.Items
	for i, it := range items {
		if it.XMLName.Local == "entry" {
			first = i
			implicit = i > 0 && items[i-1].XMLName.Local == implicitElement
			break
		}
	}
	if first < 0 {
		return Answer{}, nil
	}
	e := items[first]
	name := e.Name
	if name == "" {
		// An older answer gives the rule as text: "name; index: 3".
		name, _, _ = strings.Cut(strings.TrimSpace(e.Text), ";")
	}
	a := Answer{Rule: strings.TrimSpace(name), Action: strings.TrimSpace(e.Action), Implicit: implicit || strings.Contains(e.Inner, implicitMarker)}
	if a.Rule == "" || a.Action == "" {
		return Answer{}, fmt.Errorf("the device answer names no rule or no action: %.200s", e.Inner)
	}
	return a, nil
}

// ParseProteus reads proteus simulate policy --output json. b is the
// standard output for exit 0 and 3, and the standard error otherwise (see
// proteusOutput). The bool says whether proteus decided. Exit 3 is an
// incomplete answer, such as an undecided one: its answer is on the standard
// output. Exit 2 for the application is a refusal (spec 2026-10-16 §4.1,
// P10); any other exit is an error.
func ParseProteus(b []byte, exit int) (Answer, bool, error) {
	switch exit {
	case 0, 3:
	case 2:
		msg := lastError(b)
		if strings.HasPrefix(msg, "--application ") {
			return Answer{Refused: true}, true, nil
		}
		return Answer{}, false, fmt.Errorf("proteus refused the flow (exit 2): %s", msg)
	default:
		return Answer{}, false, fmt.Errorf("proteus exit %d: %s", exit, lastError(b))
	}
	var env struct {
		Results []struct {
			Verdict       string `json:"verdict"`
			Rule          string `json:"rule"`
			Default       string `json:"default"`
			DefaultAction string `json:"default_action"`
			FirstMatch    *struct {
				Name   string `json:"name"`
				Action string `json:"action"`
			} `json:"first_match"`
			Implicit json.RawMessage `json:"implicit"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return Answer{}, false, fmt.Errorf("the proteus answer is not JSON: %w", err)
	}
	if len(env.Results) == 0 {
		return Answer{}, false, errors.New("the proteus answer holds no result")
	}
	r := env.Results[0]
	switch {
	case r.Verdict == "undecided":
		return Answer{}, false, nil
	case r.Default != "" && r.Rule == r.Default:
		return Answer{Rule: r.Rule, Action: r.DefaultAction, Default: true}, true, nil
	case r.FirstMatch == nil || r.FirstMatch.Name != r.Rule:
		return Answer{}, false, fmt.Errorf("the proteus answer names rule %q without its first match", r.Rule)
	}
	implicit := len(r.Implicit) > 0 && string(r.Implicit) != "null"
	return Answer{Rule: r.Rule, Action: r.FirstMatch.Action, Implicit: implicit}, true, nil
}

// proteusOutput is the output ParseProteus reads: the standard output for
// an answer, exit 0 or 3, the standard error for a refusal or an error.
func proteusOutput(stdout, stderr []byte, exit int) []byte {
	if exit == 0 || exit == 3 {
		return stdout
	}
	return stderr
}

// lastError is the error of the last JSON line of proteus's standard error,
// or the last line as it stands.
func lastError(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	last := lines[len(lines)-1]
	var line struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(last), &line) == nil && line.Error != "" {
		return line.Error
	}
	return last
}

// Compare checks proteus's answer against the device's (spec 2026-10-16 §9.1).
// A difference in rule, action or implicit marker fails. A device answer with
// no rule equals a proteus answer by a default rule (I6). A refusal equals a
// refusal only on a flow marked refused (P10). An undecided proteus answer
// fails unless the flow is marked doubt; a decided answer on a flow marked
// doubt fails too, so the marks stay true.
func Compare(f Flow, device, proteus Answer, decided bool) error {
	switch {
	case f.Expect == expectRefused || device.Refused || proteus.Refused:
		if f.Expect == expectRefused && device.Refused && proteus.Refused {
			return nil
		}
		return fmt.Errorf("%s: want both to refuse on a flow marked refused: marked %q, device %s, proteus %s",
			f.Case, f.Expect, device, proteus)
	case !decided && f.Expect == expectDoubt:
		return nil
	case !decided:
		return fmt.Errorf("%s: proteus is undecided on a flow not marked doubt", f.Case)
	case f.Expect == expectDoubt:
		return fmt.Errorf("%s: proteus decided %s on a flow marked doubt", f.Case, proteus)
	case device.Rule == "":
		if proteus.Default {
			return nil
		}
		return fmt.Errorf("%s: the device lists no rule, proteus answers %s", f.Case, proteus)
	case proteus.Default:
		return fmt.Errorf("%s: the device answers %s, proteus a default rule", f.Case, device)
	case device.Rule != proteus.Rule || device.Action != proteus.Action || device.Implicit != proteus.Implicit:
		return fmt.Errorf("%s: the device answers %s, proteus %s", f.Case, device, proteus)
	}
	return nil
}

// checkOp refuses every op command but a <show> command and a
// <test><security-policy-match> command, before it is sent. The command must
// be one XML element: a second element after it would run too. This is the
// R2 amendment for the lab tool (AGENTS.md R2, plan C7).
func checkOp(cmd string) error {
	refuse := func(why string) error {
		return fmt.Errorf("applab: refusing op command %.80q: %s; only <show> and <test><security-policy-match> are allowed", cmd, why)
	}
	dec := xml.NewDecoder(strings.NewReader(cmd))
	var root struct {
		XMLName xml.Name
		Kids    []struct {
			XMLName xml.Name
		} `xml:",any"`
	}
	if err := dec.Decode(&root); err != nil {
		return refuse("not one XML element")
	}
	// Nothing may follow the element, and nothing may come before it.
	if tok, err := dec.Token(); !errors.Is(err, io.EOF) || tok != nil || !strings.HasPrefix(cmd, "<") {
		return refuse("more than one XML element")
	}
	switch {
	case root.XMLName.Local == "show":
		return nil
	case root.XMLName.Local == "test" && len(root.Kids) == 1 && root.Kids[0].XMLName.Local == "security-policy-match":
		return nil
	}
	return refuse("not a read-only command")
}

// errForbidden is a 403 from the device: the key is not valid, or its account
// lacks the rights. The run stops at once.
var errForbidden = errors.New("the device answered 403 Forbidden: the API key is not valid or its account " +
	"lacks the op rights; renew the key header file")

// device sends op commands to one firewall's XML API with an API key header.
type device struct {
	base   string
	http   *http.Client
	header string
	key    string
}

// newDevice returns a client for the device at host. insecure skips the TLS
// certificate check, as the inventory's insecure_tls says. timeout 0 means
// 60 s.
func newDevice(host string, insecure bool, timeout time.Duration, header, key string) *device {
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	//nolint:gosec // G402: the inventory's insecure_tls opts out per device, for self-signed lab certificates.
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}
	return &device{base: "https://" + host + "/api/", http: &http.Client{Transport: tr, Timeout: timeout}, header: header, key: key}
}

// op sends one op command. checkOp runs first, so a refused command never
// leaves this process. The answer comes back with an error for an HTTP error
// status; a 403 is errForbidden. The key is in a header only, never in a URL
// or an error.
func (d *device) op(ctx context.Context, cmd string) ([]byte, error) {
	if err := checkOp(cmd); err != nil {
		return nil, err
	}
	form := url.Values{"type": {"op"}, "cmd": {cmd}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(d.header, d.key)
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	switch {
	case err != nil:
		return nil, err
	case resp.StatusCode == http.StatusForbidden:
		return nil, errForbidden
	case resp.StatusCode >= 300:
		return b, fmt.Errorf("the device answered HTTP %d", resp.StatusCode)
	}
	return b, nil
}

var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// ReadKeyHeader reads the API key header file: one line "X-PAN-KEY: <key>".
// An error never quotes the file, so the key cannot reach a log.
func ReadKeyHeader(r io.Reader) (name, value string, err error) {
	b, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	bad := errors.New("the key header file must hold one line: X-PAN-KEY: <key>")
	if len(lines) != 1 {
		return "", "", bad
	}
	name, value, ok := strings.Cut(lines[0], ":")
	name, value = strings.TrimSpace(name), strings.TrimSpace(value)
	if !ok || value == "" || !headerName.MatchString(name) {
		return "", "", bad
	}
	return name, value, nil
}

// insideRepo reports whether dir is root or below it.
func insideRepo(dir, root string) bool {
	rel, err := filepath.Rel(root, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// copySnapshot copies the latest snapshot of device in the store at root into
// dst, for file mode (plan D18): the configuration as config.xml, the
// predefined services as predefined.xml and the content file as apps.xml.gz.
// It returns the content version.
func copySnapshot(root, device, dst string) (string, error) {
	sn, err := store.At(root).Latest(device)
	if err != nil {
		return "", err
	}
	content := sn.ContentPath()
	if content == "" {
		return "", fmt.Errorf("the snapshot of %s names no content version, so it has no application data", device)
	}
	for src, name := range map[string]string{
		sn.Path(store.ConfigDoc):                     "config.xml",
		filepath.Join(sn.Dir, config.PredefinedFile): config.PredefinedFile,
		content: estate.AppsFile,
	} {
		b, err := os.ReadFile(src)
		if err != nil {
			return "", fmt.Errorf("the snapshot of %s lacks a file: %w", device, err)
		}
		//nolint:gosec // G703: name is one of the three fixed file names above.
		if err := os.WriteFile(filepath.Join(dst, name), b, 0o600); err != nil {
			return "", err
		}
	}
	return sn.Meta.AppVersion, nil
}

// opSender sends one op command to the device.
type opSender interface {
	op(ctx context.Context, cmd string) ([]byte, error)
}

// proteusRunner runs proteus with args and returns its standard output, its
// standard error and its exit code. The error is for a proteus that did not
// run.
type proteusRunner func(ctx context.Context, args []string) (stdout, stderr []byte, exit int, err error)

// checkFlows runs each flow on the device and in proteus, prints one line per
// flow and writes both answers to out. It returns the number of flows that
// differ or fail. A 403, a proteus that cannot run and a cancelled context
// stop the run.
func checkFlows(ctx context.Context, w io.Writer, out string, dev opSender, run proteusRunner,
	flows []Flow, configFile, vsys string,
) (int, error) {
	diffs := 0
	for _, f := range flows {
		if err := ctx.Err(); err != nil {
			return diffs, err
		}
		b, derr := dev.op(ctx, DeviceCmd(f))
		if errors.Is(derr, errForbidden) {
			return diffs, derr
		}
		if err := os.WriteFile(filepath.Join(out, f.Case+".device.xml"), b, 0o600); err != nil {
			return diffs, err
		}
		stdout, stderr, exit, err := run(ctx, ProteusArgs(f, configFile, vsys))
		if err != nil {
			return diffs, fmt.Errorf("%s: proteus: %w", f.Case, err)
		}
		body := proteusOutput(stdout, stderr, exit)
		if err := os.WriteFile(filepath.Join(out, f.Case+".proteus.json"), body, 0o600); err != nil {
			return diffs, err
		}
		dAns, derr := ParseDevice(b, derr)
		pAns, decided, perr := ParseProteus(body, exit)
		pText := pAns.String()
		if !decided && perr == nil && !pAns.Refused {
			pText = "undecided"
		}
		status := "ok"
		switch {
		case derr != nil:
			status = "DIFF: device: " + derr.Error()
		case perr != nil:
			status = "DIFF: " + perr.Error()
		default:
			if err := Compare(f, dAns, pAns, decided); err != nil {
				status = "DIFF: " + err.Error()
			}
		}
		if status != "ok" {
			diffs++
		}
		fmt.Fprintf(w, "%-22s %-12s device: %-36s proteus: %-36s %s\n", f.Case, f.Fact, dAns, pText, status)
	}
	return diffs, nil
}
