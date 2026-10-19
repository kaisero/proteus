// Package labkit is the device side of the lab tools (plan PD16): the guarded
// device client, the variables file, the API key header file, the output
// directory, the snapshot copy, the lab-data check and the parser of a
// test security-policy-match answer. internal/tools/applab and
// internal/tools/uidlab share it, so one test holds the read-only rule for
// both (AGENTS.md R2).
//
// Device sends op commands only: <show> and <test><security-policy-match>.
// CheckOp refuses any other command before it is sent. The API key comes from
// a header file and goes in a request header only, never in a URL, an error
// or a log.
package labkit

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/store"
)

// VsysXPath is the vsys of a firewall that runs one vsys: a PAN-OS default
// name, not lab data. Every line of a lab set file is below it.
const VsysXPath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"

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

// ReadVarsFile reads the variables file. A missing file is no error for a
// lab file without placeholders, so it reads as empty.
func ReadVarsFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ReadVars(f)
}

// placeholder is ${KEY} in a lab file.
var placeholder = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)\}`)

// Fill replaces each ${KEY} with its value from vars. An unknown key is an
// error that names the key. A value is not read again for placeholders.
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
		return "", fmt.Errorf("no value for %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// CheckOp refuses every op command but a <show> command and a
// <test><security-policy-match> command, before it is sent. The command must
// be one XML element: a second element after it would run too. This is the
// R2 amendment for the lab tools (AGENTS.md R2, plan C7).
func CheckOp(cmd string) error {
	refuse := func(why string) error {
		return fmt.Errorf("refusing op command %.80q: %s; only <show> and <test><security-policy-match> are allowed", cmd, why)
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

// ErrForbidden is a 403 from the device: the key is not valid, or its account
// lacks the rights. A lab run stops at once.
var ErrForbidden = errors.New("the device answered 403 Forbidden: the API key is not valid or its account " +
	"lacks the op rights; renew the key header file")

// Device sends op commands to one firewall's XML API with an API key header.
type Device struct {
	base   string
	client *http.Client
	header string
	key    string
}

// NewDevice returns a client for the device at host. insecure skips the TLS
// certificate check, as the inventory's insecure_tls says. timeout 0 means
// 60 s.
func NewDevice(host string, insecure bool, timeout time.Duration, header, key string) *Device {
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	//nolint:gosec // G402: the inventory's insecure_tls opts out per device, for self-signed lab certificates.
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}
	return &Device{base: "https://" + host + "/api/", client: &http.Client{Transport: tr, Timeout: timeout}, header: header, key: key}
}

// Op sends one op command. CheckOp runs first, so a refused command never
// leaves this process. The answer comes back with an error for an HTTP error
// status; a 403 is ErrForbidden. The key is in a header only, never in a URL
// or an error.
func (d *Device) Op(ctx context.Context, cmd string) ([]byte, error) {
	if err := CheckOp(cmd); err != nil {
		return nil, err
	}
	form := url.Values{"type": {"op"}, "cmd": {cmd}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(d.header, d.key)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	switch {
	case err != nil:
		return nil, err
	case resp.StatusCode == http.StatusForbidden:
		return nil, ErrForbidden
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

// KeyHeader reads the key header file at path. An error names the path, not
// the key.
func KeyHeader(path string) (name, value string, err error) {
	if path == "" {
		return "", "", errors.New("give the API key header file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }()
	name, value, err = ReadKeyHeader(f)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", path, err)
	}
	return name, value, nil
}

// Lookup finds the device in the proteus inventory at inventoryPath, or at
// proteus's default path when it is "": its host, its TLS setting and its
// time-out. The password is cleared: it stays with proteus fetch.
func Lookup(inventoryPath, name string) (inventory.Target, error) {
	if inventoryPath == "" {
		p, err := inventory.DefaultPath(os.Getenv)
		if err != nil {
			return inventory.Target{}, err
		}
		inventoryPath = p
	}
	inv, err := inventory.Load(inventoryPath)
	if err != nil {
		return inventory.Target{}, err
	}
	t, err := inv.Resolve(name, os.Getenv)
	t.Password = ""
	return t, err
}

// OutDir returns the output directory: the one given, or a new temporary one
// named after the tool, such as applab-out-123. It refuses a directory in the
// repository, so no answer of the lab device lands in git.
func OutDir(dir string) (string, error) {
	if dir == "" {
		tool := filepath.Base(os.Args[0])
		return os.MkdirTemp("", strings.TrimSuffix(tool, filepath.Ext(tool))+"-out-")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if wd, err := os.Getwd(); err == nil {
		if root, ok := repoRoot(wd); ok && insideRepo(abs, root) {
			return "", fmt.Errorf("-out %s is inside the repository %s; give a directory outside it", abs, root)
		}
	}
	return abs, os.MkdirAll(abs, 0o700)
}

// insideRepo reports whether dir is root or below it.
func insideRepo(dir, root string) bool {
	rel, err := filepath.Rel(root, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// repoRoot is the nearest directory at or above dir that holds go.mod.
func repoRoot(dir string) (string, bool) {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// Command runs one command with extra environment, its output to w.
func Command(ctx context.Context, w io.Writer, env []string, name string, args ...string) error {
	//nolint:gosec // G204: the command and its arguments come from the lab tool.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env, cmd.Stdout, cmd.Stderr = append(os.Environ(), env...), w, w
	return cmd.Run()
}

// CopySnapshot copies files of the latest snapshot of device in the store at
// root into dst, for file mode (plan D18), and returns the snapshot's content
// version. Each name in files is a file name: estate.AppsFile is the
// snapshot's content file, and any other name is the file of that name in the
// snapshot directory, such as config.xml, predefined.xml or identity.json.gz.
// A missing file is an error, found before the first copy, so nothing is
// copied then.
func CopySnapshot(root, device, dst string, files []string) (string, error) {
	sn, err := store.At(root).Latest(device)
	if err != nil {
		return "", err
	}
	src := make([]string, len(files))
	for i, name := range files {
		switch {
		case name != filepath.Base(name) || !filepath.IsLocal(name):
			return "", fmt.Errorf("copy %q: not a file name", name)
		case name == estate.AppsFile:
			if src[i] = sn.ContentPath(); src[i] == "" {
				return "", fmt.Errorf("the snapshot of %s names no content version, so it has no application data", device)
			}
		default:
			src[i] = filepath.Join(sn.Dir, name)
		}
		if _, err := os.Stat(src[i]); err != nil {
			return "", fmt.Errorf("the snapshot of %s lacks a file: %w", device, err)
		}
	}
	for i, name := range files {
		b, err := os.ReadFile(src[i])
		if err != nil {
			return "", fmt.Errorf("the snapshot of %s lacks a file: %w", device, err)
		}
		//nolint:gosec // G703: name is a plain file name, checked above.
		if err := os.WriteFile(filepath.Join(dst, name), b, 0o600); err != nil {
			return "", err
		}
	}
	return sn.Meta.AppVersion, nil
}

var (
	ipv4   = regexp.MustCompile(`\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b`)
	ipv6   = regexp.MustCompile(`[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:]*`)
	serial = regexp.MustCompile(`\b[0-9]{12,}\b`)
)

// LabDataIn returns what in a file's text looks like lab data: an IPv4 or
// IPv6 address outside the ranges in nets, or a serial number. Each tool
// gives its own ranges.
func LabDataIn(text string, nets []netip.Prefix) []string {
	var out []string
	outside := func(s string) {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return
		}
		if !slices.ContainsFunc(nets, func(p netip.Prefix) bool { return p.Contains(a) }) {
			out = append(out, "address "+s)
		}
	}
	for _, s := range ipv4.FindAllString(text, -1) {
		outside(s)
	}
	// A time such as 12:30:35 holds colons too; it reads as no address.
	for _, s := range ipv6.FindAllString(text, -1) {
		outside(ipv6Within(s))
	}
	for _, s := range serial.FindAllString(text, -1) {
		out = append(out, "serial "+s)
	}
	return out
}

// ipv6Within is the address in a run of hex digits and colons. Hex letters
// can touch an address, as in cafe2001:db8::1, so a run that does not read
// loses up to four characters at its start, then at its end, until it reads.
// The address found can then be longer than the one in the text, as in
// 2001:db8::1beef: that still reports lab data.
func ipv6Within(s string) string {
	if _, err := netip.ParseAddr(s); err == nil {
		return s
	}
	for i := 1; i <= 4 && i < len(s); i++ {
		if _, err := netip.ParseAddr(s[i:]); err == nil {
			return s[i:]
		}
	}
	for i := 1; i <= 4 && i < len(s); i++ {
		if _, err := netip.ParseAddr(s[:len(s)-i]); err == nil {
			return s[:len(s)-i]
		}
	}
	return s
}

var (
	// domainName is a dotted name whose last label starts with a letter and
	// has two characters or more: 11.2.5 and e.g. are no domains.
	domainName = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]\b`)
	// dnDomain is the run of dc= components of a distinguished name.
	dnDomain = regexp.MustCompile(`(?i)\bdc=[a-z0-9-]+(?:\s*,\s*dc=[a-z0-9-]+)*`)
	dnLabel  = regexp.MustCompile(`(?i)dc=([a-z0-9-]+)`)
)

// fileExtensions are the last labels of the file names that lab files name,
// such as user-id-flows.tsv: no domain ends with them. md, sh and py are
// also country domains, so a name with them is a file only in a path, after
// a /.
var fileExtensions = map[string]bool{
	"go": true, "gz": true, "json": true, "key": true, "log": true,
	"tsv": true, "txt": true, "vars": true, "xml": true, "yaml": true,
}

// pathExtensions are file extensions that are also country domains.
var pathExtensions = map[string]bool{"md": true, "py": true, "sh": true}

// panosDomain is the device name of every PAN-OS firewall in its
// configuration, as VsysXPath names it: a default, not lab data.
const panosDomain = "localhost.localdomain"

// LabDomainsIn returns each domain name in a file's text that is none of
// allowed and below none of them: a dotted name, as in an email or a
// <domain>\<user> name, and the dc= components of a distinguished name. A
// file name and the PAN-OS device name localhost.localdomain are no
// domains. Gaps: a NetBIOS name without a dot, such as example\alice, is not
// found, and a domain that ends with a file extension of fileExtensions
// passes. Each tool gives its own allowed domains.
func LabDomainsIn(text string, allowed []string) []string {
	var out []string
	check := func(name string) {
		lower := strings.ToLower(name)
		if lower == panosDomain || slices.ContainsFunc(allowed, func(d string) bool {
			d = strings.ToLower(d)
			return lower == d || strings.HasSuffix(lower, "."+d)
		}) {
			return
		}
		out = append(out, "domain "+lower)
	}
	for _, loc := range domainName.FindAllStringIndex(text, -1) {
		s := text[loc[0]:loc[1]]
		ext := strings.ToLower(s[strings.LastIndex(s, ".")+1:])
		inPath := loc[0] > 0 && text[loc[0]-1] == '/'
		if !fileExtensions[ext] && (!pathExtensions[ext] || !inPath) {
			check(s)
		}
	}
	for _, s := range dnDomain.FindAllString(text, -1) {
		var labels []string
		for _, m := range dnLabel.FindAllStringSubmatch(s, -1) {
			labels = append(labels, m[1])
		}
		check(strings.Join(labels, "."))
	}
	return out
}

// PolicyAnswer is the device's answer to a test security-policy-match
// command: the first rule that matches and its action, and whether the rule
// matches through implicit use. An answer with no rule has Rule "".
type PolicyAnswer struct {
	Rule, Action string
	Implicit     bool
}

// implicitMarker is how the device marks a rule that matches the flow's
// application through implicit use: "ssl/application-default(implicit)", as
// observed on the lab VM, PAN-OS 12.1.9 (spec 2026-10-16 I1).
const implicitMarker = "(implicit)"

// implicitElement is the XML API form of the same mark: an <Implicit>
// element right before the entry that matches through implicit use, as
// observed on fw02, PAN-OS 12.2.3 (docs/lab/app-id-lab.md).
const implicitElement = "Implicit"

// ParsePolicyMatch reads the device's answer to a test security-policy-match
// command. err is the error of the call, and it is returned. An answer
// without a rule gives Rule "": the command never lists the default rules
// (spec 2026-10-16 I6).
func ParsePolicyMatch(b []byte, err error) (PolicyAnswer, error) {
	if err != nil {
		return PolicyAnswer{}, err
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
		return PolicyAnswer{}, fmt.Errorf("the device answer is not XML: %w", err)
	}
	if r.Status != "success" {
		msg := strings.Join(strings.Fields(strings.Join(append(r.Msg.Lines, r.Msg.Text), " ")), " ")
		return PolicyAnswer{}, fmt.Errorf("the device refused the command: %s", msg)
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
		return PolicyAnswer{}, nil
	}
	e := items[first]
	name := e.Name
	if name == "" {
		// An older answer gives the rule as text: "name; index: 3".
		name, _, _ = strings.Cut(strings.TrimSpace(e.Text), ";")
	}
	a := PolicyAnswer{Rule: strings.TrimSpace(name), Action: strings.TrimSpace(e.Action), Implicit: implicit || strings.Contains(e.Inner, implicitMarker)}
	if a.Rule == "" || a.Action == "" {
		return PolicyAnswer{}, fmt.Errorf("the device answer names no rule or no action: %.200s", e.Inner)
	}
	return a, nil
}

// ProteusOutput is the output a lab tool reads from proteus: the standard
// output for an answer, exit 0 or 3, the standard error for a refusal or an
// error.
func ProteusOutput(stdout, stderr []byte, exit int) []byte {
	if exit == 0 || exit == 3 {
		return stdout
	}
	return stderr
}

// LastError is the error of the last JSON line of proteus's standard error,
// or the last line as it stands.
func LastError(b []byte) string {
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
