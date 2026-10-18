package securitypolicy

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/rulebase"
)

// Implicit says that the deciding rule matches the flow's application only
// through the implicit use of the rule's applications (spec 2026-10-16 §4.3).
type Implicit struct {
	App string   `json:"app"` // the flow's application
	Via []string `json:"via"` // the rule's applications whose implicit-use-applications hold it
}

// suggestions is how many names a refused flow application suggests (P10).
const suggestions = 5

// flowApplication finds the flow's application among the custom applications
// of the scope and in the content data. The device matches a flow's
// application without regard to case, as observed on the lab VM, PAN-OS
// 12.1.9 (spec 2026-10-16 P14): a custom application of that name in any case
// is the flow's, with its configured name, and otherwise a content
// application, with its content name. A custom application wins, as it does
// in the index (index.appResolver). An obsolete application is valid (P15).
//
// The device refuses a container and an unknown name as the flow's
// application ("Unrecognized application", P10). The refusal is a
// ChoiceError of kind ChoiceApplication without options: its texts name the
// content version and end with the suggestions, the functions of a container
// or the nearest names (spec 2026-10-16 D13).
//
// The answer for a content application holds only App.
func flowApplication(cfg *config.Config, sc config.Scope, data *appid.Data, name string) (resolve.Application, *simulate.ChoiceError) {
	custom := resolve.Applications(cfg, sc)
	at := slices.IndexFunc(custom, func(a resolve.Application) bool { return a.Name == name })
	if at < 0 {
		at = slices.IndexFunc(custom, func(a resolve.Application) bool { return strings.EqualFold(a.Name, name) })
	}
	if at >= 0 {
		return custom[at], nil
	}
	if a, ok := data.App(name); ok {
		return resolve.Application{App: a}, nil
	}
	sugg := strings.Join(data.Suggest(name, suggestions), ", ")
	if c, ok := data.Container(name); ok {
		what := fmt.Sprintf("%s is an application container in content %s, not an application; name one of its functions: %s",
			c.Name, data.Version(), sugg)
		return resolve.Application{}, &simulate.ChoiceError{
			Kind: simulate.ChoiceApplication, Question: "--application " + what, ToolText: "application " + what,
		}
	}
	what := fmt.Sprintf("%s: no application of that name in content %s or in the configuration", name, data.Version())
	if sugg != "" {
		what += "; nearest: " + sugg
	}
	return resolve.Application{}, &simulate.ChoiceError{
		Kind: simulate.ChoiceApplication, Question: "--application " + what, ToolText: "application " + what,
	}
}

// matchApplication narrows by the flow's application (spec 2026-10-16 §4.2,
// §4.3). Without a flow application or without application data, nothing
// changes: every rule that names an application keeps doubt.application, as
// before (§4.1).
//
// A rule is an explicit candidate when its application set holds the flow's
// application: by name, through a group at any depth (S8), through a filter
// that selects it (S1-S7, S11-S15), through a container that holds it (S9), or
// as any (I4). An allow rule is an implicit candidate when a content
// application in its set implies the flow's application (I1, I5); the reverse
// does not hold (I3), and a custom application never implies (I9). A rule
// whose set holds a name neither the data nor the configuration knows is kept
// in doubt, as an explicit candidate (§4.2, D8). firstMatch evaluates the
// explicit candidates before the implicit ones (D7). The facts are those
// measured on the lab VM, PAN-OS 12.1.9, and on fw02, PAN-OS 12.2.3 (I9).
func matchApplication(_ context.Context, s *state) (simulate.Outcome, error) {
	switch {
	case s.in.Flow.Application == "":
		return simulate.Outcome{Fidelity: simulate.Exact, Detail: "no application given"}, nil
	case s.apps == nil:
		return simulate.Outcome{Fidelity: simulate.Exact, Detail: "no application data"}, nil
	}
	s.evaluated = true
	app := s.in.Flow.Application // canonical: Run set it (P14)
	s.appDoubts = map[uint32][]reason.Reason{}
	s.implied = map[uint32][]string{}

	explicit, rep := s.view.Candidates(index.Application, app)
	var debug []string
	for _, h := range rep.Hits {
		debug = append(debug, fmt.Sprintf("%s (%s) via %s", h.Name, h.Kind, h.Via))
	}
	// Without the containers, the index reports each container as a gap; a
	// rule naming one is kept below, as for any unknown name, so the gaps
	// are no unresolved entry of the stage.
	kept := roaring.New()
	s.absentApplication(ruleDefault(s.target.Config, "application"), explicit, kept)

	// Names neither the data nor the configuration holds can hold the flow's
	// application, so their rules stay (§4.2). An explicit candidate needs no
	// doubt: an unknown name can only add applications to its set, and an
	// unknown exclude cannot remove a known application, whose container its
	// own entry names (F15).
	unknown := roaring.New()
	for _, u := range s.unknownNames() {
		why := reason.New("doubt.application-unknown", fmt.Sprintf(
			"application %s is in neither content %s nor the configuration", u.name, s.apps.Version()))
		if u.filter != "" {
			why = reason.New("doubt.application-unknown", fmt.Sprintf(
				"filter %s excludes %s, which is in neither content %s nor the configuration", u.filter, u.name, s.apps.Version()))
		}
		s.keep(unknown, roaring.AndNot(u.rules, explicit), why)
	}
	kept.Or(unknown)

	// A custom flow application whose risk or default cannot be read may or
	// may not be selected by a filter, so every rule that names a filter, at
	// any depth, stays in doubt.
	if s.flowErr != nil {
		filters := roaring.New()
		for _, f := range resolve.ApplicationFilters(s.target.Config, s.idx.Scope()) {
			filters.Or(s.idx.RulesReaching(index.Application, f.Name))
		}
		s.keep(kept, filters, reason.New("doubt.application", fmt.Sprintf(
			"filters not evaluated: %v", s.flowErr)))
	}

	// Implicit use: allow rules only (I5), and no rule in both passes (D8).
	allow := roaring.New()
	for i, r := range s.rules {
		if r.Action == "allow" {
			allow.Add(uint32(i)) //nolint:gosec // a rule position cannot reach 2^32
		}
	}
	implicit := roaring.New()
	for _, x := range s.apps.ImpliedBy(app) {
		b, _ := s.view.Candidates(index.Application, x)
		b.And(allow)
		b.AndNot(explicit)
		b.AndNot(kept)
		for it := b.Iterator(); it.HasNext(); {
			bit := it.Next()
			s.implied[bit] = append(s.implied[bit], x)
		}
		implicit.Or(b)
	}

	s.explicit, s.implicit, s.kept = explicit, implicit, kept
	s.cand.And(roaring.Or(roaring.Or(explicit, implicit), kept))
	out := simulate.Outcome{Fidelity: simulate.Exact, Candidates: s.cand}
	if still := roaring.And(unknown, s.cand); !still.IsEmpty() {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.OverMatchBecause(reason.New("doubt.application-unknown",
			"kept rules naming an application that neither the content data nor the configuration holds: "+names(s.rules, still))))
	}
	if still := roaring.And(roaring.AndNot(kept, unknown), s.cand); !still.IsEmpty() {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.OverMatchBecause(reason.New("doubt.application",
			"kept rules whose application this answer cannot evaluate: "+names(s.rules, still))))
	}
	out.Detail = fmt.Sprintf("%s: %d explicit, %d implicit, %d kept in doubt (content %s)", app,
		roaring.And(explicit, s.cand).GetCardinality(), roaring.And(implicit, s.cand).GetCardinality(),
		roaring.And(kept, s.cand).GetCardinality(), s.apps.Version())
	// The device identifies an application over the first packets of a
	// session and can match the session again once it knows the application
	// (spec 2026-10-16 §4.6). The answer, as the test command, evaluates one
	// application per flow.
	s.notes = append(s.notes, reason.New("note.app-shift", fmt.Sprintf(
		"the device can match the session again when App-ID identifies it later: an earlier application, such as ssl or web-browsing, can match another rule than %s", app)))
	debug = append(debug, "left: "+names(s.rules, s.cand))
	out.Debug = debug
	return out, nil
}

// absentApplication places the rules exported without an application. Such a
// rule takes the schema's default for the field (R1), as rulebase reads it for
// PBF: any in the 11.2.0 digest, so it is an explicit candidate. Without that
// default, it is kept in doubt.
func (s *state) absentApplication(def string, explicit, kept *roaring.Bitmap) {
	absent := s.withoutField("application")
	if def == "any" {
		explicit.Or(absent)
		return
	}
	s.keep(kept, absent, reason.New("doubt.application",
		"the rule has no application, and the schema gives the field no default"))
}

// keep adds rules to a kept set and gives each the reason.
func (s *state) keep(kept, rules *roaring.Bitmap, why reason.Reason) {
	for it := rules.Iterator(); it.HasNext(); {
		bit := it.Next()
		if !slices.Contains(s.appDoubts[bit], why) {
			s.appDoubts[bit] = append(s.appDoubts[bit], why)
		}
	}
	kept.Or(rules)
}

// unknownName is a name neither the data nor the configuration holds, and the
// rules it keeps: the rules that name it or a group holding it, or, for an
// exclude, the rules that reach the filter.
type unknownName struct {
	name, filter string
	rules        *roaring.Bitmap
}

// unknownNames finds the unknown names in the rules' application fields, the
// members of the application groups and the exclude lists of the filters, by
// name. The configuration names applications exactly (P14), so a name in
// another case than the content's is unknown. No predefined group or filter
// exists (F16). Without the containers, a container name is unknown (§2.2).
func (s *state) unknownNames() []unknownName {
	cfg, sc := s.target.Config, s.idx.Scope()
	known := map[string]bool{"any": true}
	for _, a := range resolve.Applications(cfg, sc) {
		known[a.Name] = true
	}
	for _, g := range resolve.ObjectsInScope(cfg, sc, "application-group") {
		known[g.Name] = true
	}
	filters := resolve.ApplicationFilters(cfg, sc)
	for _, f := range filters {
		known[f.Name] = true
	}
	isKnown := func(n string) bool {
		if known[n] {
			return true
		}
		if a, ok := s.apps.App(n); ok && a.Name == n {
			return true
		}
		c, ok := s.apps.Container(n)
		return ok && s.apps.HasContainers() && c.Name == n
	}
	names := map[string]bool{}
	for _, r := range s.rules {
		for _, n := range r.Fields["application"] {
			if !isKnown(n) {
				names[n] = true
			}
		}
	}
	for _, g := range resolve.ObjectsInScope(cfg, sc, "application-group") {
		for n := range strings.SplitSeq(g.Value, ", ") {
			if n != "" && !isKnown(n) {
				names[n] = true
			}
		}
	}
	var out []unknownName
	for _, n := range slices.Sorted(maps.Keys(names)) {
		out = append(out, unknownName{name: n, rules: s.idx.RulesReaching(index.Application, n)})
	}
	for _, f := range filters {
		for _, n := range f.Filter.Exclude {
			if !isKnown(n) {
				out = append(out, unknownName{name: n, filter: f.Name, rules: s.idx.RulesReaching(index.Application, f.Name)})
			}
		}
	}
	return out
}

// ruleDefault reads, from the schema digest, the member a security rule field
// holds when the configuration leaves it out (R1), as rulebase reads the PBF
// rule fields. The 11.2.0 digest gives any for application.
func ruleDefault(cfg *config.Config, field string) string {
	n := cfg.Digest()
	for _, seg := range []string{"devices", "entry", "vsys", "entry", "rulebase", "security", "rules", "entry", field, "member"} {
		n = n.Child(seg)
	}
	if n == nil {
		return ""
	}
	return n.Default
}

// implicitWinner sets Verdict.Implicit and the note when the deciding rule
// matches the flow's application only through implicit use (I1).
func (s *state) implicitWinner(r resolve.Rule) {
	bit := uint32(r.Position - 1) //nolint:gosec // a rule position cannot reach 2^32
	if !s.evaluated || !s.implicit.Contains(bit) {
		return
	}
	via := s.implied[bit]
	s.verdict.Implicit = &Implicit{App: s.in.Flow.Application, Via: via}
	s.notes = append(s.notes, reason.New("note.app-implicit", fmt.Sprintf(
		"rule %s matches %s only through the implicit use of %s", r.Name, s.in.Flow.Application, strings.Join(via, ", "))))
}

// protocolOf is the protocol a run takes for a flow application given
// without a protocol, and where it comes from (spec 2026-10-16 §4.1): the one
// protocol of the application's default. A default with several protocols,
// or without a default block, which allows every protocol (P6), leaves the
// protocol open: empty.
func protocolOf(a appid.App) (proto, from string) {
	ps := a.Default.Protocols()
	switch {
	case len(ps) == 1:
		return ps[0], fmt.Sprintf("protocol %s, from the default of %s (%s)", ps[0], a.Name, a.Default)
	case len(ps) == 0:
		return "", fmt.Sprintf("protocol open: %s has no default block, so it allows every protocol", a.Name)
	}
	return "", fmt.Sprintf("protocol open: the default of %s has %s (%s)", a.Name, strings.Join(ps, ", "), a.Default)
}

// portless reports whether a protocol is known and has no ports: neither
// tcp, udp nor sctp, given by name or by number.
func portless(proto string) bool {
	n, ok := appid.ProtocolNumber(proto)
	return ok && n != 6 && n != 17 && n != 132
}

// matchOrder ranks the answers of a default, the best last: no match, an
// open question, an ICMP type, a secure port, a plain port.
var matchOrder = []appid.PortMatch{appid.PortNo, appid.PortOpen, appid.PortICMP, appid.PortSecure, appid.PortYes}

// defaultMatch compares the flow's protocol and port with the default the
// rule's application-default uses, and names the applications of that
// default. An explicit candidate uses the default of the flow's application;
// a custom one takes it from the configuration (P7). An implicit candidate
// uses the union over its applications that imply the flow's, as observed on
// the lab VM, PAN-OS 12.1.9 (spec 2026-10-16 I7, I8). The error is that of a
// custom flow application whose default cannot be read.
func (s *state) defaultMatch(bit uint32) (appid.PortMatch, []string, error) {
	port := s.in.Flow.DestPort
	if !s.implicit.Contains(bit) {
		if s.flowErr != nil {
			return appid.PortNo, []string{s.flowApp.Name}, s.flowErr
		}
		return s.flowApp.Default.Match(s.proto, port), []string{s.flowApp.Name}, nil
	}
	best := appid.PortNo
	for _, x := range s.implied[bit] {
		// The data names x: it is a content application that implies the
		// flow's.
		a, _ := s.apps.App(x)
		if m := a.Default.Match(s.proto, port); slices.Index(matchOrder, m) > slices.Index(matchOrder, best) {
			best = m
		}
	}
	return best, s.implied[bit], nil
}

// applicationDefault judges the candidates in kept that name
// application-default, with an evaluated application (spec 2026-10-16 §4.4,
// §4.5). A match moves the rule from kept to hits, the rules whose service
// holds the flow; a secure port (P2) or an ICMP type (P5) gives the rule a
// port note. No match drops the rule, unless another of its values cannot be
// judged. An open protocol or port, or a default that cannot be read, keeps
// the rule with a service doubt. It returns the rules the question leaves
// open.
func (s *state) applicationDefault(kept, hits *roaring.Bitmap) *roaring.Bitmap {
	open := roaring.New()
	defined := rulebase.Defined(s.target.Config, s.idx.Scope(), resolve.Security, "service")
	for it := roaring.And(kept, s.cand).Iterator(); it.HasNext(); {
		bit := it.Next()
		r := s.rules[bit]
		vs := r.Fields["service"]
		if !slices.Contains(vs, "application-default") {
			continue
		}
		m, of, err := s.defaultMatch(bit)
		if err != nil {
			s.svcDoubts[bit] = reason.New("doubt.service-application-default", fmt.Sprintf(
				"service application-default: the default of %s cannot be read: %v", s.flowApp.Name, err))
			continue
		}
		port := s.portText()
		switch m {
		case appid.PortYes, appid.PortSecure, appid.PortICMP:
			kept.Remove(bit)
			hits.Add(bit)
			s.serviceHits.Add(bit)
		case appid.PortOpen:
			open.Add(bit)
			s.svcDoubts[bit] = reason.New("doubt.app-port-open", fmt.Sprintf(
				"service application-default: %s may match a default port of %s (%s)", port, strings.Join(of, ", "), s.defaults(of)))
		default:
			others := slices.DeleteFunc(slices.Clone(vs), func(v string) bool { return v == "application-default" })
			if len(others) == 0 || !rulebase.Undecidable(others, defined) {
				kept.Remove(bit)
			}
		}
		switch m {
		case appid.PortSecure:
			s.portNotes[bit] = append(s.portNotes[bit], reason.New("note.app-secure-port", fmt.Sprintf(
				"rule %s matches %s on %s, a secure extended port of %s", r.Name, s.in.Flow.Application, port, strings.Join(of, ", "))))
		case appid.PortICMP:
			s.portNotes[bit] = append(s.portNotes[bit], reason.New("note.app-icmp-type", fmt.Sprintf(
				"rule %s matches %s by ICMP type; the answer does not check the type", r.Name, s.in.Flow.Application)))
		}
	}
	return open
}

// nonDefaultPorts notes the candidates whose custom service holds the flow's
// port while the default of the application does not: such a rule matches
// the application only on its service's port, as observed on the lab VM,
// PAN-OS 12.1.9 (spec 2026-10-16 P8). A rule with service any is no such
// match.
func (s *state) nonDefaultPorts(hits *roaring.Bitmap) {
	byService := roaring.And(hits, s.cand)
	byService.AndNot(s.idx.RulesWithAny(index.Service))
	for it := byService.Iterator(); it.HasNext(); {
		bit := it.Next()
		m, of, err := s.defaultMatch(bit)
		if err != nil || m != appid.PortNo {
			continue
		}
		r := s.rules[bit]
		s.portNotes[bit] = append(s.portNotes[bit], reason.New("note.app-non-default-port", fmt.Sprintf(
			"rule %s matches %s only on %s of its service, not on a default port of %s (%s)",
			r.Name, s.in.Flow.Application, s.portText(), strings.Join(of, ", "), s.defaults(of))))
	}
}

// portText is the flow's protocol and port as a note names them.
func (s *state) portText() string {
	proto := s.proto
	if proto == "" {
		proto = "an open protocol"
	}
	if s.in.Flow.DestPort == 0 {
		return proto + " without a port"
	}
	return fmt.Sprintf("%s/%d", proto, s.in.Flow.DestPort)
}

// defaults gives the defaults of applications as text.
func (s *state) defaults(names []string) string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		d := s.flowApp.Default
		if n != s.flowApp.Name {
			a, _ := s.apps.App(n)
			d = a.Default
		}
		out = append(out, d.String())
	}
	return strings.Join(out, "; ")
}
