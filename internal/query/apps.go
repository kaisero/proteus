package query

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/okaiser/proteus/internal/appid"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
)

// appMemo loads each content file once per question, through the env's
// source: the hops of one path often share a content version (spec
// 2026-10-16 D11). A failed load is kept too, so the hops give one cause.
type appMemo struct {
	src estate.AppSource
	mu  sync.Mutex
	got map[string]appLoad
}

type appLoad struct {
	data *appid.Data
	err  error
}

// Apps implements estate.AppSource.
func (m *appMemo) Apps(path string) (*appid.Data, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.got[path]; ok {
		return l.data, l.err
	}
	d, err := m.src.Apps(path)
	m.got[path] = appLoad{d, err}
	return d, err
}

// appSource is a new memo for one question over the env's source of content
// files, or over the disk when it has none.
func (e Env) appSource() estate.AppSource {
	src := e.Apps
	if src == nil {
		src = estate.DiskApps{}
	}
	return &appMemo{src: src, got: map[string]appLoad{}}
}

// noAppData ends the text of note.app-data-missing.
const noAppData = "; rules that name an application stay in doubt"

// appsOf is a target's App-ID content data, or nil and note.app-data-missing
// with the cause: a snapshot that names no content version, a file that does
// not exist, or one that cannot be read or parsed. The answer is then as
// without data (spec 2026-10-16 §4.1). Data read from a file beside the
// configuration comes with note.app-data-file, which names the file: nothing
// checks that its content version is the device's (§6).
func appsOf(t estate.Target) (*appid.Data, simulate.Reasons) {
	if t.Apps == nil {
		what := "the snapshot names no content version"
		if t.Snapshot != nil {
			what = fmt.Sprintf("snapshot %s names no content version", t.Snapshot.ID)
		}
		return nil, simulate.Reasons{reason.New("note.app-data-missing", "no application data: "+what+noAppData)}
	}
	d, err := t.Apps()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, simulate.Reasons{reason.New("note.app-data-missing",
			fmt.Sprintf("no application data: %s does not exist%s", t.AppsPath, noAppData))}
	case err != nil:
		return nil, simulate.Reasons{reason.New("note.app-data-missing", "no application data: "+err.Error()+noAppData)}
	case t.Snapshot == nil:
		return d, simulate.Reasons{reason.New("note.app-data-file",
			fmt.Sprintf("application data of content %s from %s", d.Version(), t.AppsPath))}
	}
	return d, nil
}

// hasAppFile reports whether a file target has a content file beside it,
// without reading it. A question without an application loads no data (D11),
// but the needs ask for the application only when it could decide (C8).
func hasAppFile(t estate.Target) bool {
	if t.AppsPath == "" {
		return false
	}
	fi, err := os.Stat(t.AppsPath)
	return err == nil && fi.Mode().IsRegular()
}
