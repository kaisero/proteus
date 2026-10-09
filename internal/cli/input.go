package cli

import (
	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/simulate"
)

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

type searchInput struct {
	Direct    bool           `json:"direct"`
	Fields    []string       `json:"fields"`
	Kinds     []string       `json:"kinds"`
	Mode      string         `json:"mode"`
	Selection selectionInput `json:"selection"`
	Show      []string       `json:"show"`
	Term      string         `json:"term"`
}

type lookupInput struct {
	Expand    bool           `json:"expand"`
	Full      bool           `json:"full"`
	Kind      string         `json:"kind"`
	Name      string         `json:"name"`
	Selection selectionInput `json:"selection"`
}

type snapshotListInput struct {
	Device string `json:"device"`
}

type snapshotDiffInput struct {
	From      string         `json:"from"`
	Selection selectionInput `json:"selection"`
	To        string         `json:"to"`
}

type policyInput struct {
	Flow      simulate.Flow  `json:"flow"`
	Selection selectionInput `json:"selection"`
}

type natInput struct {
	At            string        `json:"at"`
	Device        string        `json:"device"`
	Flow          simulate.Flow `json:"flow"`
	FromInterface string        `json:"from_interface"`
	FromZone      string        `json:"from_zone"`
	Router        string        `json:"router"`
}

type routingInput struct {
	At     string        `json:"at"`
	Device string        `json:"device"`
	Flow   simulate.Flow `json:"flow"`
	RIB    bool          `json:"rib"`
	Router string        `json:"router"`
}
