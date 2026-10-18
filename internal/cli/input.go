package cli

import "github.com/kaisero/proteus/internal/query"

// The input block of each command's JSON envelope (spec §15 C10). The envelope is a
// contract, so each command has a struct rather than a map: a renamed key is then a
// compile error or a golden-file diff, never a silent change. Fields are declared in
// key order, which is the order a map was written in before.

// selectionInput records the selection flags. Only the flags given appear.
type selectionInput = query.Selection

func (sel selection) input() selectionInput {
	return selectionInput{
		At: sel.at, Device: sel.devices, File: sel.file, Fresh: sel.fresh, Label: sel.labels, Vsys: sel.vsys,
	}
}

type snapshotListInput struct {
	Device string `json:"device"`
}
