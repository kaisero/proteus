package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/okaiser/proteus/internal/appid"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/task"
)

// The show commands of the App-ID data. Each answers all predefined entries of
// one kind: response/result/application/entry and
// response/result/application-container/entry (spec 2026-10-16 F1).
const (
	applicationsCmd = "<show><predefined><xpath>/predefined/application</xpath></predefined></show>"
	containersCmd   = "<show><predefined><xpath>/predefined/application-container</xpath></predefined></show>"
)

// appsMissing is the note of a device that did not give its application data
// (spec 2026-10-16 §2.2).
var appsMissing = reason.New("note.fetch-applications-missing",
	"the device did not return its application data, so rules that name an application stay in doubt")

// applicationsStep gets the App-ID data of the device's content version (spec
// 2026-10-16 §2.2). It never returns an error, so the snapshot is stored in
// every case.
//
//   - Hit: the store holds the content file of the version. The device is not
//     asked.
//   - Miss: it asks the applications, then the containers, and trims each
//     answer as it reads it. Containers that do not arrive leave the
//     applications in the file, which records them as missing.
//   - Refusal, an answer without an entry, or a version that cannot name a
//     file: the note, and no data.
//   - Transport failure: an outcome named applications, and the step is
//     partial.
func applicationsStep(ctx context.Context, s *State) (task.Result, error) {
	v := s.Result.System.AppVersion
	if !appid.ValidVersion(v) {
		return s.noApps(fmt.Errorf("content version %q is not of the form <number>-<number>", v))
	}
	if s.HaveApps != nil && s.HaveApps(v) {
		s.Result.Apps = &AppData{Version: v}
		return task.Result{Detail: "content " + v + ", stored already"}, nil
	}
	apps, nApps, err := s.trimmed(ctx, applicationsCmd)
	var (
		file       bytes.Buffer
		containers []byte
		nConts     int
		contErr    error
	)
	if err == nil {
		containers, nConts, contErr = s.trimmed(ctx, containersCmd)
		if contErr != nil {
			containers = nil
		}
		err = appid.Encode(&file, v, apps, containers)
	}
	if refused(err) {
		return s.noApps(err)
	}
	if err != nil {
		s.Log.Warnf(runlog.TagAPI, "%s: applications failed: %v", s.Target.Name, err)
		s.Result.Outcomes = append(s.Result.Outcomes, Outcome{Name: "applications", Err: err})
		return task.Result{Status: task.Partial, Detail: "content " + v + ": " + err.Error()}, nil
	}
	s.Result.Apps = &AppData{Version: v, File: file.Bytes(), ContainersMissing: contErr != nil}
	s.Log.Infof(runlog.TagAPI, "%s: applications: content %s, %d bytes", s.Target.Name, v, file.Len())
	r := task.Result{Detail: fmt.Sprintf("content %s, %s, %s", v, plural(nApps, "application"), plural(nConts, "container"))}
	if contErr != nil {
		s.Log.Warnf(runlog.TagAPI, "%s: application containers missing: %v", s.Target.Name, contErr)
		r.Status = task.Partial
		r.Detail = fmt.Sprintf("content %s, %s, containers missing: %v", v, plural(nApps, "application"), contErr)
	}
	return r, nil
}

// plural is a count with its noun: "1 container", "4 applications".
func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %ss", n, one)
}

// trimmed runs one App-ID command and returns its trimmed entries and their
// count. It reads the answer as a stream (spec 2026-10-16 §2.2).
func (s *State) trimmed(ctx context.Context, cmd string) ([]byte, int, error) {
	var buf bytes.Buffer
	n := 0
	err := s.client.opStream(ctx, cmd, func(r io.Reader) error {
		buf.Reset()
		var err error
		n, err = appid.Trim(r, &buf)
		return err
	})
	return buf.Bytes(), n, err
}

// refused reports whether an error is the device's refusal of its App-ID data:
// an API refusal, an answer with status error, or an answer without an entry
// (spec 2026-10-16 §2.2).
func refused(err error) bool {
	_, api := errors.AsType[*APIError](err)
	_, app := errors.AsType[*appid.RefusedError](err)
	return api || app || errors.Is(err, appid.ErrNoEntries)
}

// noApps records that the device gave no application data, and why.
func (s *State) noApps(why error) (task.Result, error) {
	s.Log.Warnf(runlog.TagAPI, "%s: applications refused: %v", s.Target.Name, why)
	s.Result.Notes = append(s.Result.Notes, appsMissing)
	return task.Result{Detail: why.Error(), Notes: []reason.Reason{appsMissing}}, nil
}
