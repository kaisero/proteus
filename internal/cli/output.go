package cli

import (
	"encoding/json"
	"io"
	"time"

	"github.com/okaiser/proteus/internal/estate"
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
	Device string `json:"device"`
	Vsys   string `json:"vsys,omitempty"`
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason"`
}

// note qualifies an answer without making it incomplete, such as a snapshot past
// its age limit.
type note struct {
	Device string `json:"device"`
	Vsys   string `json:"vsys,omitempty"`
	Note   string `json:"note"`
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
			if n == t.Report.VersionGap {
				un = append(un, unresolved{Device: t.Device, Vsys: t.Vsys, Reason: n})
				continue
			}
			notes = append(notes, note{Device: t.Device, Vsys: t.Vsys, Note: n})
		}
	}
	return un, notes
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

// finish returns the exit status an answer earns: incomplete when anything was a
// hole or unresolved.
func finish(holes []estate.Hole, un []unresolved) error {
	if len(holes) > 0 || len(un) > 0 {
		return errIncomplete
	}
	return nil
}
