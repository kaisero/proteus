package main

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kaisero/proteus/internal/identity"
	"github.com/kaisero/proteus/internal/tools/labkit"
)

// The lab files, relative to the repository root (spec 2026-10-17 §10.3).
const (
	// VarsFile holds the real values of the placeholders: local, untracked,
	// KEY=value lines, named in .gitignore.
	VarsFile = "docs/lab/user-id-lab.vars"
	// FlowsFile is the flow list: tracked, placeholders only (SG7).
	FlowsFile = "docs/lab/user-id-flows.tsv"
	// SetFile is the lab configuration, one XML API set per line: tracked.
	SetFile = "docs/lab/user-id-lab-set.tsv"
	// DeleteFile removes the lab configuration: tracked.
	DeleteFile = "docs/lab/user-id-lab-delete.tsv"
	// LoginFile holds the User-ID messages of the lab: tracked.
	LoginFile = "docs/lab/user-id-lab-login.xml"
	// LogoutFile removes the User-ID data of the lab: tracked.
	LogoutFile = "docs/lab/user-id-lab-logout.xml"
)

// Flow is one line of the flow list, with its placeholders filled.
type Flow struct {
	Case, Fact, Check                   string // Check: policy, user, ip or group
	From, To, Source, Destination, User string
	// Subject is the UPN of a user check (U8, N5), the address of an ip
	// check, the group of a group check, and, on a policy flow marked
	// resolved, the name the device gets.
	Subject string
	Expect  string // "", resolved, unknown-inferred or doubt (§10.3)
}

// The checks of §10.3.
const (
	checkPolicy = "policy"
	checkUser   = "user"
	checkIP     = "ip"
	checkGroup  = "group"
)

// The marks of a policy flow where proteus differs from the test command on
// purpose (§10.3).
const (
	// expectResolved: proteus resolves a UPN or an alternate name in --user,
	// the test command does not resolve its source-user (N3, §5.2).
	expectResolved = "resolved"
	// expectUnknown: no user and no mapping (M4, §5.4).
	expectUnknown = "unknown-inferred"
	// expectDoubt: a CIE group (§5.3, §5.6).
	expectDoubt = "doubt"
)

// The service of every policy flow: TCP port 443, as lab round 3 tested
// (docs/lab/user-id-poc.md, R3.7). Every lab rule has the service any.
const (
	flowProtocol = "6"
	flowPort     = "443"
)

// missingValue is the error of a placeholder without a value; the caller
// names the variables file it read.
type missingValue struct{ err error }

func (e missingValue) Error() string { return e.err.Error() }

// fill is labkit.Fill with an error that the caller can name the variables
// file in (inVars).
func fill(s string, vars map[string]string) (string, error) {
	out, err := labkit.Fill(s, vars)
	if err != nil {
		return "", missingValue{err}
	}
	return out, nil
}

// inVars names the variables file in the error of a placeholder without a
// value.
func inVars(err error, path string) error {
	if _, ok := errors.AsType[missingValue](err); ok {
		return fmt.Errorf("%w in %s", err, path)
	}
	return err
}

// refuseXMLAPIMembers refuses a user check and a resolved flow that names a
// member of a lab XML API group of the login file, with the values filled.
// The groups message rewrites the U8 block of each member until the next
// group-mapping refresh, as observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17
// U18), so such a check would compare a rewritten block.
func refuseXMLAPIMembers(flows []Flow, login []byte, vars map[string]string) error {
	filled, err := fill(string(login), vars)
	if err != nil {
		return err
	}
	var msg struct {
		Groups []struct {
			Members []struct {
				Name string `xml:"name,attr"`
			} `xml:"members>entry"`
		} `xml:"payload>groups>entry"`
	}
	if err := xml.Unmarshal([]byte(filled), &msg); err != nil {
		return fmt.Errorf("the login file is no User-ID message: %w", err)
	}
	members := map[string]bool{}
	for _, g := range msg.Groups {
		for _, m := range g.Members {
			members[strings.ToLower(m.Name)] = true
		}
	}
	for _, f := range flows {
		if f.Check != checkUser && f.Expect != expectResolved {
			continue
		}
		for _, n := range []string{f.User, f.Subject} {
			if members[strings.ToLower(n)] {
				return fmt.Errorf("%s names %s, a member of the lab XML API group: its U8 block is rewritten (U18)", f.Case, n)
			}
		}
	}
	return nil
}

// flowColumns are the columns of the flow list, in order.
var flowColumns = []string{"case", "fact", "check", "from", "to", "source", "destination", "user", "subject", "expected"}

// safeCase is a case name that can name an output file.
var safeCase = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ReadFlows reads the flow list: a header line, then one tab-separated flow
// per line. A blank line and a line that starts with # are skipped. - is an
// empty column.
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
	for i, c := range cols {
		if c == "-" {
			cols[i] = ""
		}
	}
	f := Flow{
		Case: cols[0], Fact: cols[1], Check: cols[2], From: cols[3], To: cols[4], Source: cols[5],
		Destination: cols[6], User: cols[7], Subject: cols[8], Expect: cols[9],
	}
	if !safeCase.MatchString(f.Case) {
		return Flow{}, fmt.Errorf("case %q: want letters, digits, '.', '_' or '-'", f.Case)
	}
	if f.Fact == "" {
		return Flow{}, fmt.Errorf("%s: no fact", f.Case)
	}
	flow := []string{f.From, f.To, f.Source, f.Destination}
	none := func(vs ...string) bool { return !slices.ContainsFunc(vs, func(v string) bool { return v != "" }) }
	switch f.Check {
	case checkPolicy:
		switch {
		case slices.Contains(flow, ""):
			return Flow{}, fmt.Errorf("%s: a policy flow needs from, to, source and destination", f.Case)
		case f.Expect == expectResolved && (f.User == "" || f.Subject == ""):
			return Flow{}, fmt.Errorf("%s: a resolved flow needs the user and the subject the device gets", f.Case)
		case f.Expect != expectResolved && f.Subject != "":
			return Flow{}, fmt.Errorf("%s: a subject on a policy flow needs the mark resolved", f.Case)
		case f.Expect == expectUnknown && f.User != "":
			return Flow{}, fmt.Errorf("%s: a flow marked unknown-inferred has no user", f.Case)
		case !slices.Contains([]string{"", expectResolved, expectUnknown, expectDoubt}, f.Expect):
			return Flow{}, fmt.Errorf("%s: expected %q: want -, resolved, unknown-inferred or doubt", f.Case, f.Expect)
		}
	case checkUser:
		if f.User == "" || f.Subject == "" || !none(append(flow, f.Expect)...) {
			return Flow{}, fmt.Errorf("%s: a user check has the primary name as user and the UPN as subject, and nothing else", f.Case)
		}
	case checkIP, checkGroup:
		if f.Subject == "" || !none(append(flow, f.User, f.Expect)...) {
			return Flow{}, fmt.Errorf("%s: an %s check has a subject and nothing else", f.Case, f.Check)
		}
	default:
		return Flow{}, fmt.Errorf("%s: check %q: want policy, user, ip or group", f.Case, f.Check)
	}
	return f, nil
}

// el writes <name>v</name> with v escaped.
func el(b *strings.Builder, name, v string) {
	b.WriteString("<" + name + ">")
	_ = xml.EscapeText(b, []byte(v))
	b.WriteString("</" + name + ">")
}

// show is the <show><user>…</user></show> command with one value: path names
// the elements from the outer to the inner one.
func show(v string, path ...string) string {
	var b strings.Builder
	b.WriteString("<show><user>")
	for _, p := range path[:len(path)-1] {
		b.WriteString("<" + p + ">")
	}
	el(&b, path[len(path)-1], v)
	for _, p := range slices.Backward(path[:len(path)-1]) {
		b.WriteString("</" + p + ">")
	}
	b.WriteString("</user></show>")
	return b.String()
}

// DeviceCmds are the device's op commands for a flow (§10.3):
//
//   - policy: test security-policy-match with source-user when the flow has
//     a user; a flow marked resolved sends the subject, the primary name;
//   - user: user-attributes by the UPN, the subject, and user-ids match-user
//     by the primary name, the user: user-attributes by the primary name
//     answers nothing, and match-user by the UPN too, as observed on fw01,
//     PAN-OS 11.2.5 (spec 2026-10-17 U8, N5);
//   - ip: ip-user-mapping-mp by the address (U1);
//   - group: group name (U4).
func DeviceCmds(f Flow) []string {
	switch f.Check {
	case checkPolicy:
		user := f.User
		if f.Expect == expectResolved {
			user = f.Subject
		}
		var b strings.Builder
		b.WriteString("<test><security-policy-match>")
		el(&b, "from", f.From)
		el(&b, "to", f.To)
		el(&b, "source", f.Source)
		el(&b, "destination", f.Destination)
		el(&b, "protocol", flowProtocol)
		el(&b, "destination-port", flowPort)
		if user != "" {
			el(&b, "source-user", user)
		}
		b.WriteString("</security-policy-match></test>")
		return []string{b.String()}
	case checkUser:
		return []string{show(f.Subject, "user-attributes", "user"), show(f.User, "user-ids", "match-user")}
	case checkIP:
		return []string{show(f.Subject, "ip-user-mapping-mp", "ip")}
	case checkGroup:
		return []string{show(f.Subject, "group", "name")}
	}
	return nil
}

// ProteusArgs are the arguments of proteus for a flow, on the copied
// configuration with the identity file next to it (§10.3, §7): simulate
// policy for a policy flow, lookup for a user and a group, search for an
// address. A flow marked resolved gives proteus the user as written.
func ProteusArgs(f Flow, configFile, vsys string) []string {
	file := []string{"--file", configFile, "--vsys", vsys, "--output", "json"}
	switch f.Check {
	case checkPolicy:
		args := []string{
			"simulate", "policy", f.Source, f.Destination, "--file", configFile, "--vsys", vsys,
			"--from-zone", f.From, "--to-zone", f.To, "--protocol", flowProtocol, "--port", flowPort, "--no-dns", "--output", "json",
		}
		if f.User != "" {
			args = append(args, "--user", f.User)
		}
		return args
	case checkUser:
		return append([]string{"lookup", f.User, "--kind", "identity-user"}, file...)
	case checkIP:
		return append([]string{"search", f.Subject}, file...)
	case checkGroup:
		return append([]string{"lookup", f.Subject, "--kind", "identity-group", "--full"}, file...)
	}
	return nil
}

// Answer is what one side says about a flow. A policy answer with Rule ""
// is no rule on the device and an undecided answer in proteus.
type Answer struct {
	Rule, Action string // policy
	// Default: proteus decided by a default rule, which the test command
	// never lists (spec 2026-10-16 I6).
	Default bool
	// Inferred: proteus is inferred with note.user-unknown-inferred; Doubt:
	// proteus names doubt.user-cie-group. Policy, proteus side.
	Inferred, Doubt bool
	Name            string // user: the primary name; ip: the mapped user
	Source          string // ip: the type of the mapping; group: its source
	// Names are the alternate names and the email of a user, and the
	// members of a group; Groups the groups and DUGs of a user; IPs the
	// mapped address of an ip check.
	Names, Groups, IPs []string
}

// describe is an answer in one line, for the output of a run.
func describe(f Flow, a Answer) string {
	switch f.Check {
	case checkPolicy:
		if a.Rule == "" {
			return "no rule"
		}
		s := a.Rule + " (" + a.Action
		for _, m := range []struct {
			on   bool
			text string
		}{{a.Default, "default rule"}, {a.Inferred, "inferred"}, {a.Doubt, "CIE doubt"}} {
			if m.on {
				s += ", " + m.text
			}
		}
		return s + ")"
	case checkUser:
		if a.Name == "" {
			return "no user"
		}
		return fmt.Sprintf("%s, %s, %s", a.Name, plural(len(a.Names), "name"), plural(len(a.Groups), "group"))
	case checkIP:
		if a.Name == "" {
			return "no mapping"
		}
		return a.Name + " (" + a.Source + ")"
	case checkGroup:
		src := a.Source
		if src == "" {
			src = "no source"
		}
		return src + ", " + identity.MembersText(len(a.Names))
	}
	return ""
}

// plural is a count with its noun: "1 name", "2 names".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// ParseDevice reads the device's answers to DeviceCmds, in their order,
// with the parsers of the identity file (U1, U3, U4, U8) and the parser of a
// test security-policy-match answer.
func ParseDevice(f Flow, answers [][]byte) (Answer, error) {
	if want := len(DeviceCmds(f)); want == 0 || len(answers) != want {
		return Answer{}, fmt.Errorf("%s: %d device answers for the %s check", f.Case, len(answers), f.Check)
	}
	switch f.Check {
	case checkPolicy:
		p, err := labkit.ParsePolicyMatch(answers[0], nil)
		return Answer{Rule: p.Rule, Action: p.Action}, err
	case checkUser:
		// Two answers, checked above: U8, then match-user.
		return deviceUser(answers[0], answers[len(answers)-1])
	case checkIP:
		page, err := identity.ParseMappings(answers[0])
		switch {
		case err != nil:
			return Answer{}, err
		case len(page.Entries) > 1:
			return Answer{}, fmt.Errorf("the device maps %d entries to one address", len(page.Entries))
		case len(page.Entries) == 0:
			return Answer{}, nil
		}
		m := page.Entries[0]
		return Answer{Name: m.User, Source: m.Type, IPs: []string{m.IP.String()}}, nil
	}
	g, err := identity.ParseGroupName(answers[0])
	return Answer{Source: deviceGroupSource(g), Names: g.Members}, err
}

// deviceUser reads the U8 block of a user by the UPN and the U3 table of
// match-user (U8, X1).
func deviceUser(u8, u3 []byte) (Answer, error) {
	attrs, err := identity.ParseUserAttributes(u8)
	if err != nil {
		return Answer{}, err
	}
	if len(attrs) > 1 {
		return Answer{}, fmt.Errorf("user-attributes answers %d users, want one", len(attrs))
	}
	var a Answer
	if len(attrs) == 1 {
		a.Name = attrs[0].Primary
		a.Names = slices.Clone(attrs[0].Alt)
		if attrs[0].Email != "" {
			a.Names = append(a.Names, attrs[0].Email)
		}
	}
	ids, err := identity.ParseUserIDsMatch(u3)
	if err != nil {
		return Answer{}, err
	}
	if len(ids) > 1 {
		return Answer{}, fmt.Errorf("match-user answers %d users, want one", len(ids))
	}
	for _, groups := range ids {
		a.Groups = groups
	}
	return a, nil
}

// deviceGroupSource is the source of a U4 answer in the form of the identity
// file (§3.3): a DUG answers source type xmlapi and Group type Dynamic, an
// LDAP group source type ldap and the profile as its source, as observed on
// fw01, PAN-OS 11.2.5 (spec 2026-10-17 U4, U10). A group without members
// names no source.
func deviceGroupSource(g identity.GroupAnswer) string {
	switch {
	case strings.EqualFold(g.Type, "Dynamic"):
		return identity.SourceDUG
	case g.SourceType == identity.SourceLDAP && g.Source != "":
		return identity.SourceLDAP + ":" + g.Source
	}
	return g.SourceType
}

// Codes that the marks of §10.3 read in a proteus answer.
const (
	codeUnknown = "note.user-unknown-inferred"
	codeCIE     = "doubt.user-cie-group"
)

// card is a card of lookup.
type card struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Sections []struct {
		Title string `json:"title"`
		Rows  []struct {
			Text  string `json:"text"`
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		} `json:"rows"`
	} `json:"sections"`
}

// texts are the texts of a section's rows, and items the names of its items.
func (c card) section(title string) (texts, items []string) {
	for _, s := range c.Sections {
		if s.Title != title {
			continue
		}
		for _, r := range s.Rows {
			if r.Text != "" {
				texts = append(texts, r.Text)
			}
			for _, it := range r.Items {
				items = append(items, it.Name)
			}
		}
	}
	return texts, items
}

// ParseProteus reads the JSON answer of proteus for a flow. b is the
// standard output for exit 0 and 3, and the standard error otherwise (see
// labkit.ProteusOutput); any other exit is an error.
func ParseProteus(f Flow, b []byte, exit int) (Answer, error) {
	if exit != 0 && exit != 3 {
		return Answer{}, fmt.Errorf("proteus exit %d: %s", exit, labkit.LastError(b))
	}
	switch f.Check {
	case checkPolicy:
		return proteusPolicy(b)
	case checkUser, checkGroup:
		var env struct {
			Results []struct {
				Card card `json:"card"`
			} `json:"results"`
		}
		if err := json.Unmarshal(b, &env); err != nil {
			return Answer{}, fmt.Errorf("the proteus answer is not JSON: %w", err)
		}
		kind := "identity-" + f.Check
		for _, r := range env.Results {
			if r.Card.Kind != kind {
				continue
			}
			if f.Check == checkGroup {
				src, _ := r.Card.section("source")
				_, members := r.Card.section("members")
				return Answer{Source: strings.Join(src, " "), Names: members}, nil
			}
			_, alt := r.Card.section("alternate names")
			email, _ := r.Card.section("email")
			_, groups := r.Card.section("groups")
			return Answer{Name: r.Card.Name, Names: append(alt, email...), Groups: groups}, nil
		}
		return Answer{}, nil
	case checkIP:
		return proteusMapping(b)
	}
	return Answer{}, fmt.Errorf("%s: no check %q", f.Case, f.Check)
}

// proteusPolicy reads simulate policy --output json.
func proteusPolicy(b []byte) (Answer, error) {
	var env struct {
		Results []struct {
			Verdict       string `json:"verdict"`
			Rule          string `json:"rule"`
			Default       string `json:"default"`
			DefaultAction string `json:"default_action"`
			Fidelity      struct {
				Level string `json:"level"`
			} `json:"fidelity"`
			FirstMatch *struct {
				Name   string `json:"name"`
				Action string `json:"action"`
			} `json:"first_match"`
		} `json:"results"`
	}
	var doc any
	if err := json.Unmarshal(b, &env); err != nil {
		return Answer{}, fmt.Errorf("the proteus answer is not JSON: %w", err)
	}
	_ = json.Unmarshal(b, &doc)
	if len(env.Results) == 0 {
		return Answer{}, errors.New("the proteus answer holds no result")
	}
	r := env.Results[0]
	a := Answer{Doubt: hasCode(doc, codeCIE), Inferred: r.Fidelity.Level == "inferred" && hasCode(doc, codeUnknown)}
	switch {
	case r.Verdict == "undecided":
		return a, nil
	case r.Default != "" && r.Rule == r.Default:
		a.Rule, a.Action, a.Default = r.Rule, r.DefaultAction, true
		return a, nil
	case r.FirstMatch == nil || r.FirstMatch.Name != r.Rule:
		return Answer{}, fmt.Errorf("the proteus answer names rule %q without its first match", r.Rule)
	}
	a.Rule, a.Action = r.Rule, r.FirstMatch.Action
	return a, nil
}

// hasCode reports whether a reason with the code is anywhere in a JSON
// document: in a result's reasons, its fidelity, its doubts, or the notes.
func hasCode(v any, code string) bool {
	switch v := v.(type) {
	case map[string]any:
		if v["code"] == code {
			return true
		}
		for _, c := range v {
			if hasCode(c, code) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(v, func(c any) bool { return hasCode(c, code) })
	}
	return false
}

// mappingVia reads the via of a mapping finding of search: "user <name>,
// <type>, timeout <n> s" (internal/search mappingVia).
var mappingVia = regexp.MustCompile(`^user (.+), ([^,]*), timeout [0-9]+ s$`)

// proteusMapping reads search --output json: the finding of kind mapping,
// next to the other findings of the address.
func proteusMapping(b []byte) (Answer, error) {
	var env struct {
		Results []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
			Via  string `json:"via"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return Answer{}, fmt.Errorf("the proteus answer is not JSON: %w", err)
	}
	var out Answer
	for _, r := range env.Results {
		if r.Kind != "mapping" {
			continue
		}
		m := mappingVia.FindStringSubmatch(r.Via)
		switch {
		case m == nil:
			return Answer{}, fmt.Errorf("the mapping finding %s does not read: %q", r.Name, r.Via)
		case out.Name != "":
			return Answer{}, fmt.Errorf("proteus finds two mappings: %s and %s", out.IPs[0], r.Name)
		}
		out = Answer{Name: m[1], Source: m[2], IPs: []string{r.Name}}
	}
	return out, nil
}

// foldSet is a set of names in any case (N1): lower case, sorted, each once.
func foldSet(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.ToLower(n)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Compare checks proteus's answer against the device's (spec 2026-10-17
// §10.3):
//
//   - policy without a mark, and resolved: the rule and the action agree; no
//     device rule equals a proteus default rule (I6);
//   - unknown-inferred: proteus is inferred with note.user-unknown-inferred;
//     the device answer is recorded only (M4, §5.4);
//   - doubt: proteus is undecided or names doubt.user-cie-group; the device
//     answer is recorded only (§5.6);
//   - user: the primary name, the alternate names, the email and the groups
//     agree, in any case (N1);
//   - ip: the mapped user and the type agree;
//   - group: the source and the member set agree. U4 names no source for a
//     group without members, so then the members decide.
func Compare(f Flow, device, proteus Answer) error {
	differ := func(what string) error {
		return fmt.Errorf("%s: %s: the device answers %s, proteus %s", f.Case, what, describe(f, device), describe(f, proteus))
	}
	switch f.Check {
	case checkPolicy:
		switch {
		case f.Expect == expectUnknown:
			if proteus.Rule == "" || !proteus.Inferred {
				return differ("want proteus inferred with " + codeUnknown)
			}
		case f.Expect == expectDoubt:
			if proteus.Rule != "" && !proteus.Doubt {
				return differ("want proteus undecided or in " + codeCIE)
			}
		case proteus.Rule == "":
			return differ("proteus is undecided")
		case device.Rule == "" && !proteus.Default:
			return differ("the device lists no rule, proteus names a lab rule")
		case device.Rule != "" && proteus.Default:
			return differ("proteus takes a default rule, which the device never lists")
		case device.Rule != "" && (device.Rule != proteus.Rule || device.Action != proteus.Action):
			return differ("other rule or action")
		}
	case checkUser:
		switch {
		case device.Name == "":
			return differ("the device knows no user")
		case !strings.EqualFold(device.Name, proteus.Name):
			return differ("other primary name")
		case !slices.Equal(foldSet(device.Names), foldSet(proteus.Names)):
			return differ(fmt.Sprintf("other names: %q against %q", device.Names, proteus.Names))
		case !slices.Equal(foldSet(device.Groups), foldSet(proteus.Groups)):
			return differ(fmt.Sprintf("other groups: %q against %q", device.Groups, proteus.Groups))
		}
	case checkIP:
		if device.Name != proteus.Name || device.Source != proteus.Source || !slices.Equal(device.IPs, proteus.IPs) {
			return differ("other mapping")
		}
	case checkGroup:
		switch {
		case device.Source != "" && device.Source != proteus.Source:
			return differ("other source")
		case !slices.Equal(foldSet(device.Names), foldSet(proteus.Names)):
			return differ(fmt.Sprintf("other members: %q against %q", device.Names, proteus.Names))
		}
	default:
		return fmt.Errorf("%s: no check %q", f.Case, f.Check)
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

// policyTries is how often a policy flow is tried: after a User-ID message,
// the test command can keep its earlier answer for a few minutes, as
// observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17 M18). A flow counts as a
// difference only when every try differs.
const policyTries = 3

// wait waits d, or until ctx ends.
func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// checkFlows runs each flow in proteus and on the device, prints one line per
// flow and writes the answers to out. A policy flow that differs is tried
// again on the device, retry apart, up to policyTries tries (M18). It
// returns the number of flows that differ or fail. A 403, a proteus that
// cannot run and a cancelled context stop the run.
func checkFlows(ctx context.Context, w io.Writer, out string, dev opSender, run proteusRunner,
	flows []Flow, configFile, vsys string, retry time.Duration,
) (int, error) {
	diffs := 0
	for _, f := range flows {
		if err := ctx.Err(); err != nil {
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
		pAns, perr := ParseProteus(f, body, exit)
		var dAns Answer
		status, try := "", 1
		for ; ; try++ {
			dAns, status, err = deviceTry(ctx, out, dev, f, try)
			if err != nil {
				return diffs, err
			}
			switch {
			case perr != nil:
				status = "DIFF: " + perr.Error()
			case status == "":
				if err := Compare(f, dAns, pAns); err != nil {
					status = "DIFF: " + err.Error()
				}
			}
			if status == "" || !deviceDecides(f, pAns, perr) || try == policyTries {
				break
			}
			if err := wait(ctx, retry); err != nil {
				return diffs, err
			}
		}
		switch {
		case status != "":
			diffs++
		case try > 1:
			status = fmt.Sprintf("ok after %d tries", try)
		default:
			status = "ok"
		}
		fmt.Fprintf(w, "%-22s %-18s %-6s device: %-36s proteus: %-36s %s\n", f.Case, f.Fact, f.Check,
			describe(f, dAns), describe(f, pAns), status)
	}
	return diffs, nil
}

// deviceDecides reports whether Compare reads the device answer of a policy
// flow: a flow without a mark or marked resolved, with a proteus rule. Only
// then can another try change the outcome (M18).
func deviceDecides(f Flow, proteus Answer, perr error) bool {
	return f.Check == checkPolicy && perr == nil && proteus.Rule != "" && (f.Expect == "" || f.Expect == expectResolved)
}

// deviceTry sends the device commands of a flow, writes each answer of the
// try to out and reads them. A device that refuses or fails a command gives a DIFF
// status; a 403 is an error that stops the run.
func deviceTry(ctx context.Context, out string, dev opSender, f Flow, try int) (Answer, string, error) {
	cmds := DeviceCmds(f)
	answers := make([][]byte, len(cmds))
	for i, cmd := range cmds {
		b, err := dev.Op(ctx, cmd)
		if errors.Is(err, labkit.ErrForbidden) {
			return Answer{}, "", err
		}
		if werr := os.WriteFile(filepath.Join(out, fmt.Sprintf("%s.try-%d.device-%d.xml", f.Case, try, i+1)), b, 0o600); werr != nil {
			return Answer{}, "", werr
		}
		if err != nil {
			return Answer{}, "DIFF: device: " + err.Error(), nil
		}
		answers[i] = b
	}
	a, err := ParseDevice(f, answers)
	if err != nil {
		return Answer{}, "DIFF: device: " + err.Error(), nil
	}
	return a, "", nil
}
