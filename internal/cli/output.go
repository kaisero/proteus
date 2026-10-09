package cli

import (
	"encoding/json"
	"io"
	"time"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
)

// formatVersion is the JSON envelope's format. A change that breaks a consumer
// increments it. Spec §15 C10.
const formatVersion = 1

// envelope is the one JSON object every command prints with --output json.
type envelope struct {
	Format     int           `json:"format"`
	Command    string        `json:"command"`
	Input      any           `json:"input"`
	Results    any           `json:"results"`
	Holes      []estate.Hole `json:"holes"`
	Unresolved []unresolved  `json:"unresolved"`
	Notes      []note        `json:"notes"`
}

// unresolved is something that makes an answer incomplete: it can be missing
// matches. It turns the exit code to 3.
type unresolved struct {
	Device string      `json:"device"`
	Vsys   string      `json:"vsys,omitempty"`
	Value  string      `json:"value,omitempty"`
	Reason string      `json:"reason"`
	Code   reason.Code `json:"-"` // the kind of Reason; out of the JSON until format 2
}

// note qualifies an answer without making it incomplete, such as a snapshot past
// its age limit.
type note struct {
	Device string      `json:"device"`
	Vsys   string      `json:"vsys,omitempty"`
	Note   string      `json:"note"`
	Code   reason.Code `json:"-"` // the kind of Note; out of the JSON until format 2
}

// noteOf is a note for a device and vsys with r's code and text.
func noteOf(device, vsys string, r reason.Reason) note {
	return note{Device: device, Vsys: vsys, Note: r.Text, Code: r.Code}
}

// unresolvedOf is an unresolved entry for a device and vsys with r's code and text.
func unresolvedOf(device, vsys string, r reason.Reason) unresolved {
	return unresolved{Device: device, Vsys: vsys, Reason: r.Text, Code: r.Code}
}

// target is how a result names where it came from.
type target struct {
	Device   string `json:"device"`
	Vsys     string `json:"vsys"`
	Snapshot string `json:"snapshot,omitempty"`
	TakenAt  string `json:"taken_at,omitempty"`
}

func targetOf(t estate.Target) target {
	out := target{Device: t.Device, Vsys: t.Vsys}
	if t.Snapshot != nil {
		out.Snapshot = t.Snapshot.ID
		out.TakenAt = t.Snapshot.Meta.TakenAt.Format(time.RFC3339)
	}
	return out
}

// targetQualifiers splits each target's notes: a version gap can make an answer
// miss rules, so it is unresolved; a stale snapshot or a failed fresh fetch is a
// note.
func targetQualifiers(ts []estate.Target) ([]unresolved, []note) {
	var un []unresolved
	var notes []note
	for _, t := range ts {
		for _, n := range t.Notes {
			if n.Code == "gap.version" {
				un = append(un, unresolvedOf(t.Device, t.Vsys, n))
				continue
			}
			notes = append(notes, noteOf(t.Device, t.Vsys, n))
		}
	}
	return un, notes
}

// stageJSON is one stage of any staged operation in the JSON envelope (spec §3.4).
// Simulations set Fidelity and Candidates; fetch sets Status.
type stageJSON struct {
	Slug       string             `json:"slug"`
	Name       string             `json:"name"`
	Status     string             `json:"status,omitempty"`
	Fidelity   *simulate.Fidelity `json:"fidelity,omitempty"`
	Candidates *uint64            `json:"candidates,omitempty"`
	Detail     string             `json:"detail,omitempty"`
	Notes      []string           `json:"notes,omitempty"`
	Unresolved []index.Unresolved `json:"unresolved,omitempty"`
	ElapsedMS  float64            `json:"elapsed_ms"`
}

// simStages is a simulation's stages. Candidates keeps its meaning: the count after
// the stage, carried forward when a stage does not narrow it.
func simStages(stages []simulate.Stage) []stageJSON {
	out := make([]stageJSON, len(stages))
	for i, st := range stages {
		fid, cand := st.Fidelity, st.State.Candidates
		out[i] = stageJSON{
			Slug: st.Slug, Name: st.Name, Fidelity: &fid, Candidates: &cand, Detail: st.Detail,
			Unresolved: st.Unresolved, ElapsedMS: float64(st.Elapsed.Microseconds()) / 1000,
		}
	}
	return out
}

// normalize turns nil slices into empty ones, so every key prints [] rather than
// null (spec U5). writeJSON and writeYAML both call it.
func normalize(e envelope) envelope {
	e.Format = formatVersion
	e.Results = emptySlice(e.Results)
	if e.Holes == nil {
		e.Holes = []estate.Hole{}
	}
	if e.Unresolved == nil {
		e.Unresolved = []unresolved{}
	}
	if e.Notes == nil {
		e.Notes = []note{}
	}
	return e
}

func writeJSON(w io.Writer, e envelope) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(normalize(e))
}
