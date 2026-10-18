package fetch

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/task"
)

// The commands of the identity data, each a <show> command, in the order the
// step sends them (spec 2026-10-17 §3.2: U1, U3, U5–U9).
const (
	groupMappingStatsCmd = "<show><user><group-mapping><statistics/></group-mapping></user></show>"
	groupMappingStateCmd = "<show><user><group-mapping><state>all</state></group-mapping></user></show>"
	cieStatusCmd         = "<show><user><cloud-identity-engine><status><all/></status></cloud-identity-engine></user></show>"
	userIDsCmd           = "<show><user><user-ids><all/></user-ids></user></show>"
	userAttributesCmd    = "<show><user><user-attributes><user>all</user></user-attributes></user></show>"
	groupListCmd         = "<show><user><group><list/></group></user></show>"
	dugListCmd           = `<show><user><group><list><entry name="dynamic"/></list></group></user></show>`
	registeredUsersCmd   = "<show><object><registered-user><all/></registered-user></object></show>"
	mappingPageCmd       = "<show><user><ip-user-mapping-mp><all/><limit>%d</limit><start-point>%d</start-point></ip-user-mapping-mp></user></show>"
)

// mappingPage and mappingCap are the size of a page of the mapping table and
// the most entries a read keeps: the op schema takes a limit of 1–10,000 and
// a start-point of 1–512,000 (spec 2026-10-17 U1, §3.2).
const mappingPage, mappingCap = 10000, 512000

// identityCalls are the eight commands of the identity data before the pages
// of the mapping table, each with the part it serves (spec 2026-10-17 §3.2).
var identityCalls = []struct{ part, cmd string }{
	{identity.PartLDAP, groupMappingStatsCmd},
	{identity.PartLDAP, groupMappingStateCmd},
	{identity.PartCIE, cieStatusCmd},
	{identity.PartUserGroups, userIDsCmd},
	{identity.PartUserNames, userAttributesCmd},
	{identity.PartGroups, groupListCmd},
	{identity.PartGroups, dugListCmd},
	{identity.PartTags, registeredUsersCmd},
}

// The notes of a fetch without identity data (spec 2026-10-17 §3.4).
var (
	identityOff = reason.New("note.identity-off",
		"the inventory turns the identity data off for the device, so rules that name a user stay in doubt")
	identityMultiVsys = reason.New("note.identity-multi-vsys",
		"the device runs several vsys, so the identity data is not fetched and rules that name a user stay in doubt")
	identityVsysUnknown = reason.New("note.identity-multi-vsys",
		"the system info does not show that the device runs one vsys, so the identity data is not fetched and rules that name a user stay in doubt")
)

// identityStep fetches the User-ID data of the device and keeps it as one
// identity file (spec 2026-10-17 §3, D3, D4).
//
//   - The inventory turns it off, or the system info does not show that the
//     device runs one vsys: no call, no file, and a note (D4, D10). The
//     identity file has no vsys, and a device of several vsys keeps a table
//     per vsys, so a device of an unknown mode gets no file either (ruling
//     T7-I2).
//   - A command the device refuses, or an answer that does not read: its part
//     is empty and missing, and one note names every missing part (§3.4).
//   - A transport error: no file, an outcome named identity, and the step is
//     partial, so the fetch exits 3 (PD4). No step reads the identity data of
//     an older snapshot.
//
// It never returns an error, so the snapshot is stored in every case. The
// snapshot keeps no answer of the device, only the file of what the parsers
// read (D4).
func identityStep(ctx context.Context, s *State) (task.Result, error) {
	switch {
	case !s.Target.Identity:
		return s.noIdentity(identityOff, "turned off in the inventory")
	case strings.EqualFold(s.Result.System.MultiVsys, "on"):
		// show system info names the mode: off on fw01, which runs one vsys
		// (as observed on fw01, PAN-OS 11.2.5), and on for several (spec
		// 2026-10-17 §3.4).
		return s.noIdentity(identityMultiVsys, "the device runs several vsys")
	case !strings.EqualFold(s.Result.System.MultiVsys, "off"):
		// No system info, or one without the mode: the device can run
		// several vsys.
		return s.noIdentity(identityVsysUnknown, "the system info does not show the vsys mode")
	}
	r := &identityRead{s: s, why: map[string]string{}}
	file, err := r.file(ctx)
	if err != nil {
		s.Log.Warnf(runlog.TagAPI, "%s: identity failed: %v", s.Target.Name, err)
		s.Result.Outcomes = append(s.Result.Outcomes, Outcome{Name: "identity", Err: err})
		return task.Result{Status: task.Partial, Detail: "no identity data: " + err.Error()}, nil
	}
	s.Result.Identity = file
	s.Result.Notes = append(s.Result.Notes, r.notes...)
	s.Log.Infof(runlog.TagAPI, "%s: identity: %s, %d bytes", s.Target.Name, r.detail, len(file))
	return task.Result{Detail: r.detail, Notes: r.notes}, nil
}

// noIdentity skips the identity data, and its note says why.
func (s *State) noIdentity(note reason.Reason, detail string) (task.Result, error) {
	s.Log.Infof(runlog.TagAPI, "%s: identity: %s", s.Target.Name, detail)
	s.Result.Notes = append(s.Result.Notes, note)
	return task.Result{Status: task.Skipped, Detail: detail, Notes: []reason.Reason{note}}, nil
}

// identityRead is one read of the identity data: the parts so far, why each
// missing part is missing, the calls it made and the notes for the reader.
type identityRead struct {
	s      *State
	parts  identity.Parts
	why    map[string]string // a missing part -> its first cause
	calls  int
	pages  int
	notes  []reason.Reason
	detail string
}

// file reads every part and returns the identity file. It sends every
// command, so the calls are the same for each device but for the pages of the
// mapping table (SG1).
func (r *identityRead) file(ctx context.Context) ([]byte, error) {
	takenAt := time.Now()
	answers := make(map[string][]byte, len(identityCalls))
	for _, c := range identityCalls {
		b, err := r.ask(ctx, c.part, c.cmd)
		if err != nil {
			return nil, err
		}
		answers[c.cmd] = b
	}
	if err := r.mappings(ctx); err != nil {
		return nil, err
	}
	r.read(answers)
	f := identity.Assemble(r.parts, r.domains(), takenAt)
	r.notes = append(r.partsMissing(f.PartsMissing), r.notes...)
	r.detail = fmt.Sprintf("%s: %s, %s, %s in %s, %s", plural(r.calls, "call"), plural(len(f.Users), "user"),
		plural(len(f.Groups), "group"), plural(len(f.Mappings), "mapping"), plural(r.pages, "page"),
		plural(len(f.Sources.LDAP)+len(f.Sources.CIE), "source"))
	var buf bytes.Buffer
	err := identity.Encode(&buf, f)
	return buf.Bytes(), err
}

// ask sends one command of a part and returns the answer. A refusal makes the
// part missing and gives no answer; a transport error ends the read (spec
// 2026-10-17 §3.4).
func (r *identityRead) ask(ctx context.Context, part, cmd string) ([]byte, error) {
	r.calls++
	b, err := r.s.client.Op(ctx, cmd)
	if _, refused := errors.AsType[*APIError](err); refused {
		r.miss(part, err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", part, err)
	}
	return b, nil
}

// miss makes a part missing. The note gives the first cause of each part, and
// the run log each cause. A cause is a fixed text: a refusal gives no text of
// the device, and an error of the identity parsers names a line or an entry
// and a fixed reason, never a value of the answer (§3.5, ruling T7-M3).
func (r *identityRead) miss(part string, err error) {
	cause := "the device refused the command"
	if _, refused := errors.AsType[*APIError](err); !refused {
		cause = strings.TrimPrefix(err.Error(), part+": ")
	}
	if _, ok := r.why[part]; !ok {
		r.why[part] = cause
		r.parts.Missing = append(r.parts.Missing, part)
	}
	r.s.Log.Warnf(runlog.TagAPI, "%s: identity: %s is missing: %s", r.s.Target.Name, part, cause)
}

// missing reports whether a part is missing.
func (r *identityRead) missing(part string) bool {
	_, ok := r.why[part]
	return ok
}

// parsed reads the answer of a part. A part that is missing gives the zero
// value, and so does an answer that does not read, which makes the part
// missing.
func parsed[T any](r *identityRead, part string, b []byte, parse func([]byte) (T, error)) T {
	var zero T
	if r.missing(part) {
		return zero
	}
	v, err := parse(b)
	if err != nil {
		r.miss(part, err)
		return zero
	}
	return v
}

// errProfiles is a pair of group-mapping answers that do not name the same
// profiles: the base of a profile, or its group count, is not known.
var errProfiles = errors.New("the statistics and the state name different group-mapping profiles")

// read parses the answers of the eight commands into the parts. A part that
// one of its answers does not give whole stays empty.
func (r *identityRead) read(answers map[string][]byte) {
	r.ldap(answers[groupMappingStatsCmd], answers[groupMappingStateCmd])
	r.parts.CIE = parsed(r, identity.PartCIE, answers[cieStatusCmd], identity.ParseCIEStatus)
	r.parts.UserIDs = parsed(r, identity.PartUserGroups, answers[userIDsCmd], identity.ParseUserIDs)
	r.parts.Attrs = parsed(r, identity.PartUserNames, answers[userAttributesCmd], identity.ParseUserAttributes)
	r.parts.Groups = parsed(r, identity.PartGroups, answers[groupListCmd], identity.ParseGroupList)
	r.parts.DUGs = parsed(r, identity.PartGroups, answers[dugListCmd], identity.ParseGroupList)
	if r.missing(identity.PartGroups) {
		r.parts.Groups, r.parts.DUGs = nil, nil
	}
	r.parts.Tags = parsed(r, identity.PartTags, answers[registeredUsersCmd], identity.ParseRegisteredUsers)
}

// ldap joins U6 statistics, the name and group count of each profile, with U6
// state all, the base of each profile, by profile (spec 2026-10-17 U6). Two
// answers that name different profiles make sources.ldap missing: a profile
// without its base would give its groups the source xmlapi, which is wrong,
// while a missing part gives them ldap (§3.3, D9).
func (r *identityRead) ldap(stats, state []byte) {
	sources := parsed(r, identity.PartLDAP, stats, identity.ParseGroupMappingStatistics)
	bases := parsed(r, identity.PartLDAP, state, identity.ParseGroupMappingState)
	named := map[string]bool{}
	for i, src := range sources {
		st, ok := bases[src.Name]
		if !ok || named[src.Name] {
			r.miss(identity.PartLDAP, errProfiles)
			return
		}
		named[src.Name] = true
		sources[i].Base = st.Base
	}
	if len(named) != len(bases) {
		r.miss(identity.PartLDAP, errProfiles)
		return
	}
	r.parts.LDAP = sources
}

// partsMissing is the one note that names every missing part of the file,
// each with its cause (spec 2026-10-17 §3.4, Review focus 2).
func (r *identityRead) partsMissing(parts []string) []reason.Reason {
	if len(parts) == 0 {
		return nil
	}
	named := make([]string, len(parts))
	for i, p := range parts {
		why, ok := r.why[p]
		if !ok {
			// Assemble adds sources.cie for a CIE profile without a domain
			// (SG2).
			why = "a CIE profile has no domain in the configuration"
			r.s.Log.Warnf(runlog.TagAPI, "%s: identity: %s is missing: %s", r.s.Target.Name, p, why)
		}
		named[i] = p + " (" + why + ")"
	}
	return []reason.Reason{reason.New("note.identity-part-missing",
		"these parts of the identity data are missing, so answers that need them stay in doubt: "+strings.Join(named, ", "))}
}

// mappings reads the mapping table in pages, from start-point 1 on, each page
// limit entries further on (spec 2026-10-17 §3.2, U1). It stops when it holds
// total entries, at a page shorter than the limit, or at the cap: no page
// starts after it. When total changes between pages, it keeps every page, the
// later entry of an address wins, and the table moved. A read that ends with
// fewer entries than total, or than the cap, did not see the whole table, so
// the table moved too: an insert and a delete between two pages keep total
// but shift the later page (ruling T7-I1). A table larger than the cap keeps
// its first entries: it is cut. A moved or cut table is partial (SG13), with
// a note.
func (r *identityRead) mappings(ctx context.Context) error {
	limit, most := cmp.Or(r.s.mappingPage, mappingPage), cmp.Or(r.s.mappingCap, mappingCap)
	var held []identity.Mapping
	at := map[netip.Addr]int{} // address -> index in held
	total, moved := -1, false
	for start := 1; start <= most; start += limit {
		b, err := r.ask(ctx, identity.PartMappings, fmt.Sprintf(mappingPageCmd, limit, start))
		if err != nil {
			return err
		}
		page := parsed(r, identity.PartMappings, b, identity.ParseMappings)
		if r.missing(identity.PartMappings) {
			return nil
		}
		r.pages++
		moved = moved || (total >= 0 && page.Total != total)
		total = page.Total
		for _, m := range page.Entries {
			if i, ok := at[m.IP]; ok {
				held[i] = m
			} else if len(held) < most {
				at[m.IP] = len(held)
				held = append(held, m)
			}
		}
		if len(page.Entries) < limit || len(held) >= total {
			break
		}
	}
	moved = moved || len(held) < min(total, most)
	cut := total > most
	r.parts.Mappings, r.parts.MappingsPartial = held, moved || cut
	if moved {
		r.notes = append(r.notes, mappingsMoved)
	}
	if cut {
		r.notes = append(r.notes, reason.New("note.identity-mappings-cut",
			fmt.Sprintf("the mapping table holds %d entries; the snapshot keeps the first %d", total, most)))
	}
	return nil
}

// mappingsMoved is the note of a mapping table that changed while the step
// read it (spec 2026-10-17 §3.2).
var mappingsMoved = reason.New("note.identity-mappings-moved",
	"the mapping table changed while it was read in pages, so the snapshot can miss a mapping or hold an old one")

// singleVsys is the one vsys of a device that runs one: the answers of fw01
// name it vsys1 (as observed on fw01, PAN-OS 11.2.5, spec 2026-10-17 U1, U12).
const singleVsys = "vsys1"

// domains reads the domain of each source that the device listed from the
// configuration of the snapshot: the running configuration merged with the
// pushed template (spec 2026-10-17 §3.2, SG2, ruling Q1). U6 and U7 name no
// domain (X1). A configuration that did not arrive, or that does not read,
// gives no domain: a CIE profile then makes sources.cie missing (SG2), and an
// LDAP profile has an unknown domain.
func (r *identityRead) domains() identity.Domains {
	if len(r.parts.LDAP) == 0 && len(r.parts.CIE) == 0 {
		return identity.Domains{}
	}
	d, err := sourceDomains(r.s.Result.Docs[RunningConfig.Name])
	if err != nil {
		r.s.Log.Warnf(runlog.TagAPI, "%s: identity: the configuration gives no domain of a source: %v", r.s.Target.Name, err)
	}
	return d
}

// sourceDomains reads a configuration and gives the domain of each
// group-mapping profile and of each CIE profile of the one vsys, by profile.
// The schema says where they are (AGENTS.md R1): config reads the
// configuration, and resolve its profiles.
func sourceDomains(b []byte) (identity.Domains, error) {
	cfg, _, err := config.Parse(bytes.NewReader(b), RunningConfig.Name+".xml")
	if err != nil {
		return identity.Domains{}, err
	}
	sc := config.Scope{Sort: config.ScopeVsys, Name: singleVsys}
	d := identity.Domains{LDAP: map[string]string{}, CIE: map[string]string{}}
	for _, g := range resolve.GroupMappings(cfg, sc) {
		d.LDAP[g.Name] = g.Domain
	}
	for _, c := range resolve.CloudIdentityEngines(cfg, sc) {
		d.CIE[c.Name] = c.Domain
	}
	return d, nil
}
