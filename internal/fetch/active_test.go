package fetch

import (
	"context"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/fakepanos"
	"github.com/okaiser/proteus/internal/task"
)

// The HA pair shapes are synthetic: no lab device runs HA yet.
func ha(mode, local, localSerial, peer, peerSerial, peerIP string) string {
	return fakepanos.Success(`<enabled>yes</enabled><group><mode>` + mode + `</mode>` +
		`<local-info><state>` + local + `</state><serial-num>` + localSerial + `</serial-num></local-info>` +
		`<peer-info><state>` + peer + `</state><serial-num>` + peerSerial + `</serial-num><mgmt-ip>` + peerIP + `</mgmt-ip></peer-info></group>`)
}

func member(state string) *fakepanos.Device {
	d := device()
	d.Ops["<show><system><info/></system></show>"] = fakepanos.Success("<system><hostname>" + state +
		"</hostname><app-version>8000-1000</app-version><multi-vsys>off</multi-vsys></system>")
	return d
}

// pair starts a passive device whose peer reports 192.0.2.2, and an active device
// that PeerHost maps that address to.
func pair(t *testing.T, passiveHA, activeHA string) (string, ActiveOptions) {
	t.Helper()
	p, a := member("passive"), member("active")
	p.Ops[haStateCmd] = passiveHA
	a.Ops[haStateCmd] = activeHA
	ph, ah := p.Start(t), a.Start(t)
	return ph, ActiveOptions{PeerHost: func(ip string) string {
		if ip != "192.0.2.2" {
			t.Errorf("peer address %q", ip)
		}
		return ah
	}}
}

func hostname(r Result) string { return r.System.Hostname }

func TestHAStepFollowsAConfirmedPeer(t *testing.T) {
	t.Parallel()
	host, opts := pair(t,
		ha("Active-Passive", "passive", "A", "active", "B", "192.0.2.2/24"),
		ha("Active-Passive", "active", "B", "passive", "A", "192.0.2.1"))
	res, err := run(context.Background(), target(host), []Document{SystemInfo}, opts, nil)
	if err != nil || hostname(res) != "active" || res.FetchedFrom == "" || res.Host != host {
		t.Errorf("res = %+v, err %v", res, err)
	}
}

func TestHAStepStaysWhenInDoubt(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ passive, active, note, code string }{
		"peer not active": {ha("active-passive", "passive", "A", "suspended", "B", "192.0.2.2"), "", `peer is "suspended"`, "note.fetch-peer-unusable"},
		"peer disagrees": {
			ha("active-passive", "passive", "A", "active", "B", "192.0.2.2"),
			ha("active-passive", "active", "B", "passive", "SOMEONE-ELSE", "192.0.2.1"), "does not confirm", "note.fetch-peer-unconfirmed",
		},
		"active-active": {ha("Active-Active", "active-primary", "A", "active-secondary", "B", "192.0.2.2"), "", "only active-passive", "note.fetch-ha-mode"},
		"suspended":     {ha("active-passive", "suspended", "A", "active", "B", "192.0.2.2"), "", `HA state "suspended"`, "note.fetch-ha-state"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			host, opts := pair(t, tc.passive, tc.active)
			res, err := run(context.Background(), target(host), []Document{SystemInfo}, opts, nil)
			if err != nil || hostname(res) != "passive" || res.FetchedFrom != "" ||
				len(res.Notes) != 1 || !strings.Contains(res.Notes[0].Text, tc.note) || string(res.Notes[0].Code) != tc.code {
				t.Errorf("res = %+v, err %v", res, err)
			}
		})
	}
}

func TestHAStepWithoutHA(t *testing.T) {
	t.Parallel()
	d := member("alone")
	d.Ops[haStateCmd] = fakepanos.Success("<enabled>no</enabled>")
	res, err := run(context.Background(), target(d.Start(t)), []Document{SystemInfo}, ActiveOptions{}, nil)
	if err != nil || hostname(res) != "alone" || len(res.Notes) != 0 {
		t.Errorf("res = %+v, err %v", res, err)
	}
	// A device that refuses the HA command is fetched as it is.
	d = member("old")
	res, err = run(context.Background(), target(d.Start(t)), []Document{SystemInfo}, ActiveOptions{}, nil)
	if err != nil || hostname(res) != "old" {
		t.Errorf("res = %+v, err %v", res, err)
	}
	// An active member is fetched as it is, without a note.
	d = member("active")
	d.Ops[haStateCmd] = ha("active-passive", "active", "B", "passive", "A", "192.0.2.1")
	if res, _ := run(context.Background(), target(d.Start(t)), []Document{SystemInfo}, ActiveOptions{}, nil); len(res.Notes) != 0 {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestHAStepPeerUnreachable(t *testing.T) {
	t.Parallel()
	d := member("passive")
	d.Ops[haStateCmd] = ha("active-passive", "passive", "A", "active", "B", "192.0.2.2")
	_, err := run(context.Background(), target(d.Start(t)), []Document{SystemInfo},
		ActiveOptions{PeerHost: func(string) string { return "127.0.0.1:1" }}, nil)
	if err == nil || !strings.Contains(err.Error(), "ha_peer") {
		t.Errorf("err = %v", err)
	}
	if _, err := run(context.Background(), target("127.0.0.1:1"), nil, ActiveOptions{}, nil); err == nil {
		t.Error("a device that cannot be logged in to fails")
	}
}

// ha_peer in the inventory wins over the reported address.
func TestHAStepUsesTheInventoryPeer(t *testing.T) {
	t.Parallel()
	p, a := member("passive"), member("active")
	p.Ops[haStateCmd] = ha("active-passive", "passive", "A", "active", "B", "192.0.2.2")
	a.Ops[haStateCmd] = ha("active-passive", "active", "B", "passive", "A", "192.0.2.1")
	tg := target(p.Start(t))
	tg.HAPeer = a.Start(t)
	res, err := run(context.Background(), tg, []Document{SystemInfo},
		ActiveOptions{PeerHost: func(string) string { t.Error("PeerHost must not be asked"); return "" }}, nil)
	if err != nil || hostname(res) != "active" || res.FetchedFrom != tg.HAPeer {
		t.Errorf("res = %+v, err %v", res, err)
	}
}

// The ha stage says why it was skipped: HA off is not the same as a state that could
// not be read.
func TestHAStepSaysWhyItSkipped(t *testing.T) {
	t.Parallel()
	off := member("alone")
	off.Ops[haStateCmd] = fakepanos.Success("<enabled>no</enabled>")
	for name, tc := range map[string]struct {
		d      *fakepanos.Device
		detail string
	}{
		"not enabled": {off, "HA is not enabled"},
		"unreadable":  {member("old"), "HA state unreadable"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := NewState(target(tc.d.Start(t)), []Document{SystemInfo}, ActiveOptions{}, nil)
			recs, err := task.Run(context.Background(), s.Target.Name, &s, Steps(), task.Options{})
			if err != nil || len(recs) < 2 || recs[1].Slug != "ha" || recs[1].Status != task.Skipped || recs[1].Detail != tc.detail {
				t.Errorf("records = %+v, err %v", recs, err)
			}
		})
	}
}
