package simulate

import (
	"strings"

	"github.com/kaisero/proteus/internal/reason"
)

// Reasons is a list of reasons, such as a hop's notes. JSON writes each as
// {"code", "text"} (format 2); a composite reason is a list of its parts, each
// with its own code, the first carrying the prefix that names the subject.
type Reasons []reason.Reason

// Texts lists the texts; nil for a nil list, so JSON writes null for nil and []
// for an empty list, as for a []string.
func (rs Reasons) Texts() []string {
	if rs == nil {
		return nil
	}
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Text)
	}
	return out
}

// Text joins the texts with "; ", as a composite reason reads.
func (rs Reasons) Text() string { return strings.Join(rs.Texts(), "; ") }

// Joined is the list as one reason: the first reason's code and every text
// joined with "; "; the zero reason for none. Only a summary that names its
// own cause may join; JSON keeps the parts.
func (rs Reasons) Joined() reason.Reason {
	if len(rs) == 0 {
		return reason.Reason{}
	}
	return reason.Reason{Code: rs[0].Code, Text: rs.Text()}
}

// Prefixed returns a copy whose first text starts with p. A composite reason
// that names its subject once, "source: a; b", keeps each part's code.
func (rs Reasons) Prefixed(p string) Reasons {
	out := append(Reasons{}, rs...)
	if len(out) > 0 {
		out[0].Text = p + out[0].Text
	}
	return out
}
