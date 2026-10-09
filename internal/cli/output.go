package cli

import (
	"encoding/json"
	"io"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/query"
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

// The qualifiers, the target and the stage of a result are the query layer's.
type (
	unresolved = query.Unresolved
	note       = query.Note
	target     = query.Target
	stageJSON  = query.Stage
)

func noteOf(device, vsys string, r reason.Reason) note { return query.NoteOf(device, vsys, r) }

func unresolvedOf(device, vsys string, r reason.Reason) unresolved {
	return query.UnresolvedOf(device, vsys, r)
}

func targetOf(t estate.Target) target { return query.TargetOf(t) }

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

func simStages(stages []simulate.Stage) []stageJSON { return query.SimStages(stages) }

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
