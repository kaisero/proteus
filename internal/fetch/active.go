package fetch

import (
	"context"
	"fmt"
	"strings"

	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/runlog"
)

// ActiveOptions tune RunActive.
type ActiveOptions struct {
	// PeerHost turns the peer's management address, as the HA state reports it,
	// into the host to connect to. Nil uses the address as it is. Tests map it to a
	// second fake device.
	PeerHost func(mgmtIP string) string
}

// RunActive fetches a device, or its active peer when the device is the passive
// member of an active-passive pair (spec §17 R18).
//
// It follows only a complete, consistent pair: this device passive, the peer
// active, and the peer's own state naming this device's serial as its peer. It
// follows once. Anything else fetches the device asked and says why in Notes: the
// HA pair shapes are not yet verified on a device, so doubt means "do not follow".
// A peer that cannot be logged in to fails the run, because the passive device's
// own tables may be stale.
func RunActive(ctx context.Context, t inventory.Target, docs []Document, opts ActiveOptions, log *runlog.Logger) (Result, error) {
	c, err := login(ctx, t, log)
	if err != nil {
		return Result{Device: t.Name, Host: t.Host, Docs: map[string][]byte{}}, err
	}
	local, ok := haState(ctx, c)
	if !ok || !local.Enabled {
		return fetchDocs(ctx, c, t, docs, log), nil
	}
	if !strings.EqualFold(local.Mode, "active-passive") {
		res := fetchDocs(ctx, c, t, docs, log)
		res.Notes = append(res.Notes, fmt.Sprintf("HA mode %q: fetched this device as it is; only active-passive pairs are followed", local.Mode))
		return res, nil
	}
	if local.LocalState != "passive" {
		res := fetchDocs(ctx, c, t, docs, log)
		if local.LocalState != "active" {
			res.Notes = append(res.Notes, fmt.Sprintf("HA state %q: fetched this device as it is", local.LocalState))
		}
		return res, nil
	}
	peerHost := t.HAPeer
	if peerHost == "" && local.PeerMgmtIP.IsValid() {
		peerHost = local.PeerMgmtIP.String()
		if opts.PeerHost != nil {
			peerHost = opts.PeerHost(peerHost)
		}
	}
	if local.PeerState != "active" || peerHost == "" {
		res := fetchDocs(ctx, c, t, docs, log)
		res.Notes = append(res.Notes, fmt.Sprintf("passive, but the peer is %q or has no address: fetched this device as it is", local.PeerState))
		return res, nil
	}
	log.Infof(runlog.TagAPI, "%s: passive; following the active peer %s", t.Name, peerHost)
	pt := t
	pt.Host = peerHost
	pc, err := login(ctx, pt, log)
	if err != nil {
		return Result{Device: t.Name, Host: t.Host, Docs: map[string][]byte{}},
			fmt.Errorf("%s is passive and its active peer %s cannot be read (set ha_peer to its reachable host): %w", t.Name, peerHost, err)
	}
	peer, ok := haState(ctx, pc)
	if !ok || peer.LocalState != "active" || peer.PeerSerial == "" || peer.PeerSerial != local.LocalSerial {
		res := fetchDocs(ctx, c, t, docs, log)
		res.Notes = append(res.Notes, fmt.Sprintf("passive, but %s does not confirm it is the active partner: fetched this device as it is", peerHost))
		return res, nil
	}
	res := fetchDocs(ctx, pc, pt, docs, log)
	res.Host = t.Host
	res.FetchedFrom = peerHost
	return res, nil
}

// haState reads a device's HA state; false when it cannot be read.
func haState(ctx context.Context, c *Client) (resolve.HAState, bool) {
	b, err := c.Op(ctx, haStateCmd)
	if err != nil {
		return resolve.HAState{}, false
	}
	st, err := resolve.ReadHAState(b)
	return st, err == nil
}
