package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/okaiser/proteus/internal/tools/labkit"
)

// The lab files, relative to the repository root.
const (
	// VarsFile holds the real values of the placeholders: local, untracked,
	// KEY=value lines (spec 2026-10-16 §9.1).
	VarsFile = "docs/lab/app-id-lab.vars"
	// FlowsFile is the flow list.
	FlowsFile = "docs/lab/app-id-flows.tsv"
)

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

// fill is labkit.Fill with the name of the variables file in its error.
func fill(s string, vars map[string]string) (string, error) {
	out, err := labkit.Fill(s, vars)
	if err != nil {
		return "", fmt.Errorf("%w in %s", err, VarsFile)
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
		filled, err := fill(line, vars)
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

// ParseDevice reads the device's answer to DeviceCmd. err is the error of the
// call; an "Unrecognized application" refusal, in the answer or in err, gives
// Refused. An answer without a rule gives Rule "": the command never lists the
// default rules (spec 2026-10-16 I6).
func ParseDevice(b []byte, err error) (Answer, error) {
	if bytes.Contains(b, []byte(unrecognized)) || err != nil && strings.Contains(err.Error(), unrecognized) {
		return Answer{Refused: true}, nil
	}
	p, err := labkit.ParsePolicyMatch(b, err)
	return Answer{Rule: p.Rule, Action: p.Action, Implicit: p.Implicit}, err
}

// ParseProteus reads proteus simulate policy --output json. b is the
// standard output for exit 0 and 3, and the standard error otherwise (see
// labkit.ProteusOutput). The bool says whether proteus decided. Exit 3 is an
// incomplete answer, such as an undecided one: its answer is on the standard
// output. Exit 2 for the application is a refusal (spec 2026-10-16 §4.1,
// P10); any other exit is an error.
func ParseProteus(b []byte, exit int) (Answer, bool, error) {
	switch exit {
	case 0, 3:
	case 2:
		msg := labkit.LastError(b)
		if strings.HasPrefix(msg, "--application ") {
			return Answer{Refused: true}, true, nil
		}
		return Answer{}, false, fmt.Errorf("proteus refused the flow (exit 2): %s", msg)
	default:
		return Answer{}, false, fmt.Errorf("proteus exit %d: %s", exit, labkit.LastError(b))
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

// opSender sends one op command to the device.
type opSender interface {
	Op(ctx context.Context, cmd string) ([]byte, error)
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
		b, derr := dev.Op(ctx, DeviceCmd(f))
		if errors.Is(derr, labkit.ErrForbidden) {
			return diffs, derr
		}
		if err := os.WriteFile(filepath.Join(out, f.Case+".device.xml"), b, 0o600); err != nil {
			return diffs, err
		}
		stdout, stderr, exit, err := run(ctx, ProteusArgs(f, configFile, vsys))
		if err != nil {
			return diffs, fmt.Errorf("%s: proteus: %w", f.Case, err)
		}
		body := labkit.ProteusOutput(stdout, stderr, exit)
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
