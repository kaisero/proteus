package fetch

import (
	"context"
	"fmt"

	"github.com/okaiser/panos-analyst/inventory"
	"github.com/okaiser/panos-analyst/runlog"
)

// Outcome is what happened to one document.
type Outcome struct {
	Name  string
	Bytes int
	Err   error
}

// Result is one device's fetch: the documents that arrived and what happened to
// every document asked for.
type Result struct {
	Device   string
	Host     string
	Docs     map[string][]byte
	Outcomes []Outcome
	System   System
}

// OK reports whether a document arrived.
func (r Result) OK(name string) bool {
	for _, o := range r.Outcomes {
		if o.Name == name {
			return o.Err == nil
		}
	}
	return false
}

// Run logs in to one firewall and fetches the documents in order.
//
// A document that fails is recorded and the rest are still fetched (spec S10). Only
// a failed login fails the whole run, because nothing can be read without a key.
func Run(ctx context.Context, t inventory.Target, docs []Document, log *runlog.Logger) (Result, error) {
	res := Result{Device: t.Name, Host: t.Host, Docs: map[string][]byte{}}
	c := NewClient(t, log)
	if err := c.Keygen(ctx, t.Username, t.Password); err != nil {
		return res, fmt.Errorf("%s: %w", t.Name, err)
	}
	for _, d := range docs {
		b, err := d.Fetch(ctx, c)
		res.Outcomes = append(res.Outcomes, Outcome{Name: d.Name, Bytes: len(b), Err: err})
		if err == nil {
			res.Docs[d.Name] = b
			log.Infof(runlog.TagAPI, "%s: %s: %d bytes", t.Name, d.Name, len(b))
		} else {
			log.Warnf(runlog.TagAPI, "%s: %s failed: %v", t.Name, d.Name, err)
		}
	}
	if b, ok := res.Docs[SystemInfo.Name]; ok {
		if s, err := ParseSystemInfo(b); err == nil {
			res.System = s
		}
	}
	return res, nil
}
