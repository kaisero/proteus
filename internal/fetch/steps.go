package fetch

import (
	"context"
	"fmt"
	"strings"

	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/task"
)

// State is one device's fetch as it goes: the target, the client once logged in, and
// the result so far.
type State struct {
	Target inventory.Target
	Docs   []Document
	Opts   ActiveOptions
	Log    *runlog.Logger // the same logger as task.Options.Log; the client needs it
	Result Result
	client *Client // the device's, or the active peer's after the ha step
}

// NewState starts a device's fetch.
func NewState(t inventory.Target, docs []Document, opts ActiveOptions, log *runlog.Logger) State {
	return State{
		Target: t, Docs: docs, Opts: opts, Log: log,
		Result: Result{Device: t.Name, Host: t.Host, Docs: map[string][]byte{}},
	}
}

// Steps are the device-side steps of a fetch: log in, follow the active HA peer,
// fetch the documents. A failed login fails the device, because nothing can be read
// without a key; a failed document is recorded and the rest still arrive (spec S10).
func Steps() []task.Step[State] {
	return []task.Step[State]{
		{Name: "log in", Slug: "login", Do: loginStep},
		{Name: "follow the active HA peer", Slug: "ha", Do: haStep},
		{Name: "fetch the documents", Slug: "documents", Do: documentsStep},
	}
}

func loginStep(ctx context.Context, s *State) (task.Result, error) {
	c := NewClient(s.Target, s.Log)
	if err := c.Keygen(ctx, s.Target.Username, s.Target.Password); err != nil {
		return task.Result{}, err
	}
	s.client = c
	return task.Result{Detail: "logged in as " + s.Target.Username}, nil
}

// haStep reads the device's HA state and switches to the active peer when this
// device is the passive member of an active-passive pair (spec §17 R18).
//
// It follows only a complete, consistent pair: this device passive, the peer active,
// and the peer's own state naming this device's serial as its peer. It follows once.
// Anything else fetches the device asked and says why in a note: the HA pair shapes
// are not yet verified on a device, so doubt means "do not follow". A peer that cannot
// be logged in to fails the device, because the passive device's own tables may be
// stale.
func haStep(ctx context.Context, s *State) (task.Result, error) {
	local, ok := haState(ctx, s.client)
	if !ok {
		return task.Result{Status: task.Skipped, Detail: "HA state unreadable"}, nil
	}
	if !local.Enabled {
		return task.Result{Status: task.Skipped, Detail: "HA is not enabled"}, nil
	}
	if !strings.EqualFold(local.Mode, "active-passive") {
		return s.stay(fmt.Sprintf("HA mode %q: fetched this device as it is; only active-passive pairs are followed", local.Mode))
	}
	if local.LocalState != "passive" {
		if local.LocalState != "active" {
			return s.stay(fmt.Sprintf("HA state %q: fetched this device as it is", local.LocalState))
		}
		return task.Result{Detail: "active"}, nil
	}
	peerHost := s.Target.HAPeer
	if peerHost == "" && local.PeerMgmtIP.IsValid() {
		peerHost = local.PeerMgmtIP.String()
		if s.Opts.PeerHost != nil {
			peerHost = s.Opts.PeerHost(peerHost)
		}
	}
	if local.PeerState != "active" || peerHost == "" {
		return s.stay(fmt.Sprintf("passive, but the peer is %q or has no address: fetched this device as it is", local.PeerState))
	}
	s.Log.Infof(runlog.TagAPI, "%s: passive; following the active peer %s", s.Target.Name, peerHost)
	pt := s.Target
	pt.Host = peerHost
	pc := NewClient(pt, s.Log)
	if err := pc.Keygen(ctx, pt.Username, pt.Password); err != nil {
		return task.Result{}, fmt.Errorf("passive, and its active peer %s cannot be read (set ha_peer to its reachable host): %w", peerHost, err)
	}
	peer, ok := haState(ctx, pc)
	if !ok || peer.LocalState != "active" || peer.PeerSerial == "" || peer.PeerSerial != local.LocalSerial {
		return s.stay(fmt.Sprintf("passive, but %s does not confirm it is the active partner: fetched this device as it is", peerHost))
	}
	s.client = pc
	s.Result.FetchedFrom = peerHost
	return task.Result{Detail: "passive; fetched from the active peer " + peerHost}, nil
}

// stay records why the fetch stays on the device asked.
func (s *State) stay(note string) (task.Result, error) {
	s.Result.Notes = append(s.Result.Notes, note)
	return task.Result{Detail: "fetched this device as it is", Notes: []string{note}}, nil
}

func documentsStep(ctx context.Context, s *State) (task.Result, error) {
	failed := 0
	for _, d := range s.Docs {
		b, err := d.Fetch(ctx, s.client)
		s.Result.Outcomes = append(s.Result.Outcomes, Outcome{Name: d.Name, Bytes: len(b), Err: err})
		if err != nil {
			failed++
			s.Log.Warnf(runlog.TagAPI, "%s: %s failed: %v", s.Target.Name, d.Name, err)
			continue
		}
		s.Result.Docs[d.Name] = b
		s.Log.Infof(runlog.TagAPI, "%s: %s: %d bytes", s.Target.Name, d.Name, len(b))
	}
	if b, ok := s.Result.Docs[SystemInfo.Name]; ok {
		if sys, err := ParseSystemInfo(b); err == nil {
			s.Result.System = sys
		}
	}
	r := task.Result{Detail: fmt.Sprintf("%d of %d documents", len(s.Docs)-failed, len(s.Docs))}
	if failed > 0 {
		r.Status = task.Partial
	}
	return r, nil
}
