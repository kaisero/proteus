package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Each store failure matches its kind with errors.Is and keeps its message.
func TestErrorsMatchTheirKind(t *testing.T) {
	t.Parallel()
	s := open(t)
	sn, err := s.Write(Meta{Device: "fw01"}, docs(t, false), nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	noConfig, err := s.Write(Meta{Device: "fw01"}, map[string][]byte{RIBDoc: []byte("<rib/>")}, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	// A device whose directory is a file, a latest that is not a link, and a
	// meta.json that is a directory: each is there but cannot be read.
	if err := os.WriteFile(filepath.Join(s.root, "fw02"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.root, "fw03"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.root, "fw03", "latest"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.root, "fw03", "2026-09-28T09-00-00Z", "meta.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	corrupt, err := s.Write(Meta{Device: "fw04"}, docs(t, false), nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corrupt.Dir, "meta.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	early := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	// A device with snapshots, none of them with a configuration.
	if _, err := s.Write(Meta{Device: "fw05"}, map[string][]byte{RIBDoc: []byte("<rib/>")}, nil, 20); err != nil {
		t.Fatal(err)
	}
	// A configuration that is there but cannot be read: a link to itself.
	looped, err := s.Write(Meta{Device: "fw06"}, map[string][]byte{RIBDoc: []byte("<rib/>")}, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(looped.Path(ConfigDoc), looped.Path(ConfigDoc)); err != nil {
		t.Fatal(err)
	}
	both := errors.Join(ErrNoSnapshot, ErrNoConfig)

	cases := []struct {
		name string
		do   func() error
		kind error
		msg  string // "" when the message holds an OS detail
	}{
		{"List of an unknown device", func() error { _, err := s.List("fw09"); return err }, ErrNoSnapshot, ""},
		{"List of an unreadable device", func() error { _, err := s.List("fw02"); return err }, ErrUnreadable, ""},
		{
			"Latest of an unknown device", func() error { _, err := s.Latest("fw09"); return err }, ErrNoSnapshot,
			"store: fw09 has no snapshot with a configuration; run proteus fetch fw09",
		},
		{
			"Latest that is not a link", func() error { _, err := s.Latest("fw03"); return err }, ErrUnreadable,
			"store: fw03 has no snapshot with a configuration; run proteus fetch fw03",
		},
		{
			"Get of an unknown id", func() error { _, err := s.Get("fw01", "2026-09-27T00-00-00Z"); return err }, ErrNoSnapshot,
			"store: no snapshot fw01@2026-09-27T00-00-00Z",
		},
		{
			"Get of an unreadable meta.json", func() error { _, err := s.Get("fw03", "2026-09-28T09-00-00Z"); return err }, ErrUnreadable, "",
		},
		{"Get of a corrupt meta.json", func() error { _, err := s.Get("fw04", corrupt.ID); return err }, ErrUnreadable, ""},
		{
			"AtOrBefore with nothing that early", func() error { _, err := s.AtOrBefore("fw01", early); return err }, ErrNoSnapshot,
			"store: fw01 has no snapshot with a configuration at or before 2026-09-01T00:00:00Z",
		},
		{"AtOrBefore of an unknown device", func() error { _, err := s.AtOrBefore("fw09", early); return err }, ErrNoSnapshot, ""},
		{
			"Latest of snapshots without a configuration", func() error { _, err := s.Latest("fw05"); return err }, both,
			"store: fw05 has no snapshot with a configuration; run proteus fetch fw05",
		},
		{
			"AtOrBefore of snapshots without a configuration", func() error { _, err := s.AtOrBefore("fw05", time.Now()); return err }, both, "",
		},
		{"AtOrBefore of an unreadable configuration", func() error { _, err := s.AtOrBefore("fw06", time.Now()); return err }, ErrUnreadable, ""},
		{"ConfigPath of an unreadable configuration", func() error { _, err := looped.ConfigPath(); return err }, ErrUnreadable, ""},
		{
			"ConfigPath without a configuration", func() error { _, err := noConfig.ConfigPath(); return err }, ErrNoConfig,
			"store: fw01@" + noConfig.ID + " has no configuration",
		},
	}
	kinds := []error{ErrNoSnapshot, ErrNoConfig, ErrUnreadable}
	for _, c := range cases {
		err := c.do()
		if err == nil {
			t.Errorf("%s: no error", c.name)
			continue
		}
		for _, k := range kinds {
			if got := errors.Is(err, k); got != errors.Is(c.kind, k) {
				t.Errorf("%s: errors.Is(%v, %v) = %v", c.name, err, k, got)
			}
		}
		if c.msg != "" && err.Error() != c.msg {
			t.Errorf("%s: message %q, want %q", c.name, err, c.msg)
		}
	}
	if p, err := sn.ConfigPath(); err != nil || p != sn.Path(ConfigDoc) {
		t.Errorf("ConfigPath = %q, %v", p, err)
	}
}

// A wrapped OS error stays reachable beside the kind.
func TestErrorsKeepTheCause(t *testing.T) {
	t.Parallel()
	s := open(t)
	_, err := s.List("fw09")
	if !errors.Is(err, ErrNoSnapshot) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("List = %v; want ErrNoSnapshot and fs.ErrNotExist", err)
	}
}

// An absent zone document is not unreadable; one that cannot be opened or
// parsed is.
func TestZonesErrorsMatchTheirKind(t *testing.T) {
	t.Parallel()
	s := open(t)
	bare, err := s.Write(Meta{Device: "fw01"}, docs(t, false), nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bare.Zones()
	if !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrUnreadable) {
		t.Errorf("absent interface list: %v", err)
	}

	noFIB := docs(t, true)
	delete(noFIB, FIBDoc)
	half, err := s.Write(Meta{Device: "fw02"}, noFIB, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	_, err = half.Zones()
	if !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrUnreadable) {
		t.Errorf("absent forwarding table: %v", err)
	}

	// A snapshot directory that is a file: the interface list cannot be opened.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Snapshot{Device: "fw03", ID: "x", Dir: file}).Zones(); !errors.Is(err, ErrUnreadable) {
		t.Errorf("interface list in a file: %v", err)
	}

	// A forwarding table that links to itself cannot be opened.
	full, err := s.Write(Meta{Device: "fw04"}, docs(t, true), nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	loop := full.Path(FIBDoc)
	if err := os.Remove(loop); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if _, err := full.Zones(); !errors.Is(err, ErrUnreadable) {
		t.Errorf("forwarding table loop: %v", err)
	}

	// A forwarding table that does not parse.
	bad, err := s.Write(Meta{Device: "fw05"}, docs(t, true), nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad.Path(FIBDoc), []byte("<"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Zones(); !errors.Is(err, ErrUnreadable) {
		t.Errorf("forwarding table that does not parse: %v", err)
	}
}
