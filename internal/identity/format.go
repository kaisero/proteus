package identity

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"
)

// Format is the format of the identity file (spec 2026-10-17 §4.1). It rises
// when a key changes its meaning or goes; an added key keeps it.
const Format = 1

// FileName is the name of the identity file in a snapshot (§4.1).
const FileName = "identity.json.gz"

// The parts of a fetch, as parts_missing and note.identity-part-missing name
// them (spec 2026-10-17 §3.2).
const (
	PartLDAP       = "sources.ldap" // U6 statistics and state all
	PartCIE        = "sources.cie"  // U7
	PartUserGroups = "users.groups" // U3
	PartUserNames  = "users.names"  // U8
	PartGroups     = "groups"       // U5, the full and the dynamic list
	PartTags       = "tags"         // U9
	PartMappings   = "mappings"     // U1, in pages
)

// The sources of a group (§3.3). An LDAP or a CIE group of a known profile has
// the source <kind>:<profile>, such as ldap:example.com.
const (
	SourceLDAP   = "ldap"   // alone: an LDAP group of an unknown profile (D9)
	SourceCIE    = "cie"    // alone: a CIE group of an unknown profile (SG2)
	SourceDUG    = "dug"    // a dynamic user group (U10)
	SourceXMLAPI = "xmlapi" // an XML API group, or any other name
)

// File is the identity file of one snapshot, with the keys of spec §4.1.
// Every name stays as the device prints it (§3.3).
type File struct {
	Format   int       `json:"format"`
	TakenAt  time.Time `json:"taken_at"`
	Sources  Sources   `json:"sources"`
	Users    []User    `json:"users"`
	Groups   []Group   `json:"groups"`
	DUGs     []string  `json:"dugs"`
	Tags     []Tags    `json:"tags"`
	Mappings []Mapping `json:"mappings"`
	// MappingsPartial: the fetch cut the table or read it while it moved
	// (SG13). The key is left out when false.
	MappingsPartial bool `json:"mappings_partial,omitempty"`
	// PartsMissing names each part of §3.2 that did not arrive whole, sorted.
	PartsMissing []string `json:"parts_missing"`
}

// Sources are the identity sources of the device.
type Sources struct {
	LDAP []LDAPSource `json:"ldap"`
	CIE  []CIESource  `json:"cie"`
}

// LDAPSource is one group-mapping profile (U6). Its domain comes from the
// configuration, and it is empty when the configuration names none (ruling
// Q1): the answers of U6 hold no domain (X1).
type LDAPSource struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Base   string `json:"base"`
	Groups int    `json:"groups"`
}

// CIESource is one Cloud Identity Engine profile (U7). Its domain comes from
// the configuration, and it is empty when the configuration names none (SG2).
type CIESource struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Groups int    `json:"groups"`
	Last   string `json:"last"` // the last action, as U7 prints it
}

// User is one user of U3 or U8: the primary name; the alternate names and the
// email of U8; the groups and DUGs of U3 (D13), in the order of U3.
type User struct {
	Name   string   `json:"name"`
	Alt    []string `json:"alt,omitempty"`
	Email  string   `json:"email,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// Group is one group of U5, with its source by form (§3.3) and the number of
// users whose groups hold it.
type Group struct {
	Name    string `json:"name"`
	Source  string `json:"source"` // ldap:<profile>, ldap, xmlapi, dug, cie:<profile> or cie
	Members int    `json:"members"`
}

// Tags are the registered tags of one user (U9).
type Tags struct {
	User string   `json:"user"`
	Tags []string `json:"tags"`
}

// Mapping is one user-to-IP mapping (U1).
type Mapping struct {
	IP      netip.Addr `json:"ip"`
	User    string     `json:"user"`
	Type    string     `json:"type"`
	Timeout int        `json:"timeout"` // in seconds (U1, U13)
}

// Encode writes f as an identity file: gzip JSON. It writes only a file that
// Read reads: one of this Format, with an address in each mapping. A list
// that f leaves nil is written as [].
func Encode(w io.Writer, f File) error {
	if f.Format != Format {
		return fmt.Errorf("the identity file has format %d; this build writes format %d", f.Format, Format)
	}
	if err := checkMappings(f.Mappings); err != nil {
		return err
	}
	zw := gzip.NewWriter(w)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(withLists(f)); err != nil {
		return fmt.Errorf("write the identity file: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("write the identity file: %w", err)
	}
	return nil
}

// Read reads an identity file. A damaged gzip, a file that is no JSON or
// holds a value of a wrong type, a mapping without an address and a file of
// another format are errors (§4.2). No error quotes a value of the file
// (§3.5). A list that the file holds as null reads as an empty list.
func Read(r io.Reader) (*Data, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("the identity file is no gzip file: %w", err)
	}
	stream := &streamReader{r: zr}
	dec := json.NewDecoder(stream)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, decodeError(err, stream.err)
	}
	// The rest of the stream holds white space only, and the gzip trailer
	// that checks the whole file.
	rest, err := io.ReadAll(io.MultiReader(dec.Buffered(), zr))
	if err != nil {
		return nil, fmt.Errorf("the identity file is damaged: %w", err)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("the identity file holds more than one JSON value")
	}
	if f.Format != Format {
		return nil, fmt.Errorf("the identity file has format %d; this build reads format %d", f.Format, Format)
	}
	if err := checkMappings(f.Mappings); err != nil {
		return nil, err
	}
	return New(withLists(f)), nil
}

// Load reads the identity file at path.
func Load(path string) (*Data, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	d, err := Read(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

// checkMappings refuses a mapping without a valid address: it would match no
// address, and its user would look unmapped.
func checkMappings(ms []Mapping) error {
	for i, m := range ms {
		if !m.IP.IsValid() {
			return fmt.Errorf("mapping %d of the identity file has no address", i+1)
		}
	}
	return nil
}

// streamReader keeps the error of the gzip stream, so Read can tell a damaged
// stream from a value of the file that does not read.
type streamReader struct {
	r   io.Reader
	err error
}

func (s *streamReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		s.err = err
	}
	return n, err
}

// decodeError names why the JSON of an identity file does not read. It never
// quotes the file: a value can be a user, a group or an address (§3.5).
func decodeError(err, streamErr error) error {
	if streamErr != nil {
		return fmt.Errorf("the identity file is damaged: %w", streamErr)
	}
	if se, ok := errors.AsType[*json.SyntaxError](err); ok {
		return fmt.Errorf("the identity file is no JSON at byte %d", se.Offset)
	}
	if te, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		return fmt.Errorf("the identity file holds a value of a wrong type at %s", te.Field)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errors.New("the JSON of the identity file ends early")
	}
	return errors.New("a value of the identity file does not read")
}

// withLists gives each nil list of f an empty one, so the file holds [] for
// it, as spec §4.1 shows for parts_missing.
func withLists(f File) File {
	f.Sources.LDAP = orEmpty(f.Sources.LDAP)
	f.Sources.CIE = orEmpty(f.Sources.CIE)
	f.Users = orEmpty(f.Users)
	f.Groups = orEmpty(f.Groups)
	f.DUGs = orEmpty(f.DUGs)
	f.Tags = orEmpty(f.Tags)
	f.Mappings = orEmpty(f.Mappings)
	f.PartsMissing = orEmpty(f.PartsMissing)
	return f
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
