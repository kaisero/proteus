package index

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// UserSnapshot is a point-in-time copy of user-to-group membership.
//
// A configuration does not hold this. In production it comes from User-ID, which
// learns it from a directory, and it changes as people log in and out. The library
// defines the format and reads it; fetching it is the caller's job, because the
// library performs no network access.
//
// TakenAt is not decoration. A mapping read yesterday can put a user in a group they
// have since left, and a lookup that trusted it silently would be wrong in the most
// convincing way. A snapshot older than MaxAge is reported through Stale.
type UserSnapshot struct {
	TakenAt time.Time `json:"taken_at"`
	Source  string    `json:"source"`
	// Groups maps a user to the groups holding it. Keys are compared case
	// insensitively, because a directory and a firewall rule rarely agree on case.
	Groups map[string][]string `json:"groups"`
	// MaxAge is how old the snapshot may be before a lookup says so. Zero means one
	// day.
	MaxAge time.Duration `json:"max_age,omitempty"`

	lower map[string][]string
	now   func() time.Time
}

const defaultSnapshotMaxAge = 24 * time.Hour

// LoadUserSnapshot reads a snapshot in the library's JSON format.
//
//	{
//	  "taken_at": "2026-09-27T13:00:00Z",
//	  "source": "user-id on fw01",
//	  "groups": {"acme\\alice": ["domain users", "engineering"]}
//	}
func LoadUserSnapshot(r io.Reader) (*UserSnapshot, error) {
	var s UserSnapshot
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return nil, fmt.Errorf("user snapshot: %w", err)
	}
	if s.TakenAt.IsZero() {
		return nil, fmt.Errorf("user snapshot: taken_at is required, so a stale snapshot can be reported")
	}
	s.index()
	return &s, nil
}

func (s *UserSnapshot) index() {
	s.lower = make(map[string][]string, len(s.Groups))
	for user, groups := range s.Groups {
		s.lower[strings.ToLower(user)] = groups
	}
}

// GroupsOf returns the groups holding a user, case insensitively.
func (s *UserSnapshot) GroupsOf(user string) []string {
	if s.lower == nil {
		s.index()
	}
	return s.lower[strings.ToLower(strings.TrimSpace(user))]
}

// Stale reports whether the snapshot is older than it should be trusted for.
func (s *UserSnapshot) Stale() (string, bool) {
	limit := s.MaxAge
	if limit == 0 {
		limit = defaultSnapshotMaxAge
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	age := now().Sub(s.TakenAt)
	if age <= limit {
		return "", false
	}
	return fmt.Sprintf(
		"the user snapshot was taken %s ago, more than the %s it is trusted for, so group "+
			"membership may have changed since",
		age.Round(time.Minute), limit), true
}
