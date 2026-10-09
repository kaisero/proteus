// Package query answers the questions proteus asks of a configuration or an
// estate: simulate policy, routing and NAT, search, lookup and snapshot diff.
// A query takes a typed input and an Env and returns a typed Envelope. It
// prints nothing and parses no flag: the command line and the MCP server
// both call it, each with its own way to read input and to render the
// answer (spec 2026-10-09 §3.7).
//
// R12: query imports the simulations, estate, store, inventory, search,
// drift, card, resolve, index, config, runlog and reason. It does not import
// fetch, cli, mcp, Cobra or a terminal package.
package query

import (
	"context"
	"net/netip"
	"time"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/store"
)

// FormatVersion is the envelope's format. A change that breaks a consumer
// increments it.
const FormatVersion = 2

// Env is what a query reads besides its input. The caller owns every value.
type Env struct {
	// Store holds the snapshots. A query that reads only a file needs none.
	Store *store.Store
	// Inventory names the devices. A query that reads only a file needs none.
	Inventory *inventory.Inventory
	// Now is the clock that ages snapshots; nil uses time.Now.
	Now func() time.Time
	// MaxAge is the age past which a snapshot is noted as stale.
	MaxAge time.Duration
	// Resolve looks up an FQDN's addresses, IPv4 and IPv6. Nil resolves no name.
	Resolve func(ctx context.Context, name string) ([]netip.Addr, error)
	// CanonicalName gives an FQDN's canonical name, trailing dot trimmed, as
	// this machine's resolver reports it. Nil gives none.
	CanonicalName func(ctx context.Context, name string) (string, error)
	// Users reads the user directory a configuration does not hold. It is read
	// only when a query needs it, so its error comes where it did on the
	// command line. Nil is no directory.
	Users func() (index.UserDirectory, error)
	// Log is the run log; nil logs nothing.
	Log *runlog.Logger
	// Fresh fetches devices before a query reads them and returns the notes
	// each device's fetch left, by device: TLS verification off, a failed
	// document, a failed fetch. Nil takes no fresh fetch.
	Fresh func(ctx context.Context, devices []string) (map[string][]reason.Reason, error)
}

// now is the env's clock.
func (e Env) now() time.Time {
	if e.Now == nil {
		return time.Now()
	}
	return e.Now()
}

// users is the user directory, or none.
func (e Env) users() (index.UserDirectory, error) {
	if e.Users == nil {
		return nil, nil
	}
	return e.Users()
}

// Envelope is the answer of one command. In and Res are the command's typed
// input and result element. Detail is "full" for a query's own answer and
// "summary" after Summarize.
//
// The fields carry no JSON tags: the command line writes the envelope from
// them, with its own input block. Targets holds what the renderers need and no
// envelope prints: every target read, with or without results (C16).
type Envelope[In, Res any] struct {
	Format     int
	Command    string
	Detail     string
	Input      In
	Results    []Res
	Summary    *Summary // search and lookup; nil elsewhere
	Holes      []estate.Hole
	Unresolved []Unresolved
	Notes      []Note
	Targets    []estate.Target
}

// Summary counts a search's or a lookup's results over the targets read.
type Summary struct {
	Found   int `json:"found"`   // results over every target
	With    int `json:"with"`    // targets with a result
	Without int `json:"without"` // targets read without one
}

// Summarize converts a full envelope into its summary form: each result through
// f, Detail "summary", every qualifier kept.
func Summarize[In, R, S any](e Envelope[In, R], f func(R) S) Envelope[In, S] {
	out := Envelope[In, S]{
		Format: e.Format, Command: e.Command, Detail: "summary", Input: e.Input, Summary: e.Summary,
		Holes: e.Holes, Unresolved: e.Unresolved, Notes: e.Notes, Targets: e.Targets,
	}
	if e.Results != nil {
		out.Results = make([]S, len(e.Results))
		for i, r := range e.Results {
			out.Results[i] = f(r)
		}
	}
	return out
}

// envelope starts a full envelope of a command.
func envelope[In, Res any](command string, in In) Envelope[In, Res] {
	return Envelope[In, Res]{Format: FormatVersion, Command: command, Detail: "full", Input: in}
}

// UsageError is an input that is not a valid question. Text is the command
// line's message; ToolText says the same with the input's field names where
// Text names a flag, and is empty where Text names none.
type UsageError struct {
	Code     reason.Code
	Text     string
	ToolText string
	err      error // the error Text came from, if any
}

func (e *UsageError) Error() string { return e.Text }

func (e *UsageError) Unwrap() error { return e.err }

// usage is a usage error. Every usage error has the one code call.usage: a
// caller acts on the code, and the text says what to change. A registry code
// per message would name the same action many times over.
func usage(text, toolText string) *UsageError {
	return &UsageError{Code: "call.usage", Text: text, ToolText: toolText}
}

// usageOf is a usage error that keeps err for errors.Is and errors.As.
func usageOf(err error, text, toolText string) *UsageError {
	u := usage(text, toolText)
	u.err = err
	return u
}

// Unresolved is something that makes an answer incomplete: it can be missing
// matches. JSON writes {device, vsys, value, code, text} (spec 2026-10-09 §3.2).
// A composite reason is one entry per part; Part marks each entry after the
// first, so a renderer can print the parts on one line.
type Unresolved struct {
	Device string      `json:"device"`
	Vsys   string      `json:"vsys,omitempty"`
	Value  string      `json:"value,omitempty"`
	Code   reason.Code `json:"code"`
	Reason string      `json:"text"`
	Part   bool        `json:"-"`
}

// Note qualifies an answer without making it incomplete, such as a snapshot
// past its age limit. JSON writes {device, vsys, code, text}.
type Note struct {
	Device string      `json:"device"`
	Vsys   string      `json:"vsys,omitempty"`
	Code   reason.Code `json:"code"`
	Note   string      `json:"text"`
}

// NoteOf is a note for a device and vsys with r's code and text.
func NoteOf(device, vsys string, r reason.Reason) Note {
	return Note{Device: device, Vsys: vsys, Note: r.Text, Code: r.Code}
}

// UnresolvedOf is an unresolved entry for a device and vsys with r's code and
// text.
func UnresolvedOf(device, vsys string, r reason.Reason) Unresolved {
	return Unresolved{Device: device, Vsys: vsys, Reason: r.Text, Code: r.Code}
}

// UnresolvedOfParts is a composite reason's unresolved entries: one per part,
// each with its code, the later ones marked as parts.
func UnresolvedOfParts(device, vsys string, rs simulate.Reasons) []Unresolved {
	out := make([]Unresolved, 0, len(rs))
	for i, r := range rs {
		u := UnresolvedOf(device, vsys, r)
		u.Part = i > 0
		out = append(out, u)
	}
	return out
}

// Target is how a result names where it came from.
type Target struct {
	Device   string `json:"device"`
	Vsys     string `json:"vsys"`
	Snapshot string `json:"snapshot,omitempty"`
	TakenAt  string `json:"taken_at,omitempty"`
}

// TargetOf is a target's name in a result.
func TargetOf(t estate.Target) Target {
	out := Target{Device: t.Device, Vsys: t.Vsys}
	if t.Snapshot != nil {
		out.Snapshot = t.Snapshot.ID
		out.TakenAt = t.Snapshot.Meta.TakenAt.Format(time.RFC3339)
	}
	return out
}

// Stage is one stage of any staged operation (spec 2026-09-27 §3.4).
// Simulations set Fidelity and Candidates; a fetch sets Status.
type Stage struct {
	Slug       string             `json:"slug"`
	Name       string             `json:"name"`
	Status     string             `json:"status,omitempty"`
	Fidelity   *simulate.Fidelity `json:"fidelity,omitempty"`
	Candidates *uint64            `json:"candidates,omitempty"`
	Detail     string             `json:"detail,omitempty"`
	Notes      []reason.Reason    `json:"notes,omitempty"`
	Unresolved []index.Unresolved `json:"unresolved,omitempty"`
	ElapsedMS  float64            `json:"elapsed_ms"`
}

// SimStages is a simulation's stages. Candidates keeps its meaning: the count
// after the stage, carried forward when a stage does not narrow it.
func SimStages(stages []simulate.Stage) []Stage {
	out := make([]Stage, len(stages))
	for i, st := range stages {
		fid, cand := st.Fidelity, st.State.Candidates
		out[i] = Stage{
			Slug: st.Slug, Name: st.Name, Fidelity: &fid, Candidates: &cand, Detail: st.Detail,
			Unresolved: st.Unresolved, ElapsedMS: float64(st.Elapsed.Microseconds()) / 1000,
		}
	}
	return out
}
