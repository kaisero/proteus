package appid

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// TrimVersion names the set of kept fields. Increment it with every change to
// keptFields: the file name carries it, so an old file gives a miss.
const TrimVersion = 1

// versionRE is the shape of a content version, such as 9159-10287 (spec
// 2026-10-16 F2, §2.2). Only this shape becomes a file name.
var versionRE = regexp.MustCompile(`^[0-9]+-[0-9]+$`)

// ValidVersion reports whether v is a content version that can name a file.
func ValidVersion(v string) bool { return versionRE.MatchString(v) }

// FileName is the name of the content file of a version: "8000-1000.v1.xml.gz"
// (spec 2026-10-16 §3.1).
func FileName(version string) string {
	return version + ".v" + strconv.Itoa(TrimVersion) + ".xml.gz"
}

// keptFields are the children of an application or container entry that the
// trim keeps: the §3.2 table of spec 2026-10-16. Every other child goes, icon,
// references and the decoder fields too.
var keptFields = []string{
	// The filter fields (S1, S10).
	"category", "subcategory", "technology", "risk",
	"evasive-behavior", "consume-big-bandwidth", "used-by-malware", "able-to-transfer-file",
	"has-known-vulnerability", "tunnel-other-application", "prone-to-misuse", "pervasive-use",
	"is-saas", "new-appid",
	"tag",  // S3, S12
	"saas", // saas-risk, saas-certifications (S6, S11, F8)
	// application-default, every form with extended-port (F10, F11).
	"default",
	// Implicit use and the app card.
	"implicit-use-applications", "use-applications", "tunnel-applications",
	"application-container", "parent-app",
	// The app card. They do not change application-default (P12).
	"ident-by-dport", "ident-by-sport",
	"obsolete", "description",
	// The members of a container entry (S9).
	"functions",
}

var keptSet = func() map[string]bool {
	m := make(map[string]bool, len(keptFields))
	for _, f := range keptFields {
		m[f] = true
	}
	return m
}()

// kept reports whether the trim keeps a child of an entry.
func kept(field string) bool { return keptSet[field] }

// filterFields maps a field of an application filter to the application field
// it selects on. As measured on the lab VM, PAN-OS 12.1.9 (spec 2026-10-16
// S10); the fields absent here have the same name in both. A saas-risk member
// names a child of the app's saas block, and a saas-certifications member a
// child of saas/certifications (S6, F8). The schema names the filter fields,
// not the application fields they select, so this map is hand-modelled
// (AGENTS.md R8).
//
// The list is in schema field order, which Selection.Via follows (§5.1).
// TestEveryFilterFieldHasAKeptField holds the order to the digest.
var filterFields = []struct{ filter, app string }{
	{"category", "category"},
	{"subcategory", "subcategory"},
	{"technology", "technology"},
	{"evasive", "evasive-behavior"},
	{"excessive-bandwidth-use", "consume-big-bandwidth"},
	{"used-by-malware", "used-by-malware"},
	{"transfers-files", "able-to-transfer-file"},
	{"has-known-vulnerabilities", "has-known-vulnerability"},
	{"tunnels-other-apps", "tunnel-other-application"},
	{"prone-to-misuse", "prone-to-misuse"},
	{"pervasive", "pervasive-use"},
	{"is-saas", "is-saas"},
	{"new-appid", "new-appid"},
	{"risk", "risk"},
	{"saas-certifications", "saas"},
	{"saas-risk", "saas"},
	// no-tag reads the tags too, and adds no restriction (S14).
	{"no-tag", "tag"},
	// The configuration holds the tags under tagging/tag; S10 names the
	// field tagging, as the command line shows it.
	{"tag", "tag"},
	{"tagging", "tag"},
}

// filterIndex is the position of each filter field in filterFields.
var filterIndex = func() map[string]int {
	m := make(map[string]int, len(filterFields))
	for i, f := range filterFields {
		m[f.filter] = i
	}
	return m
}()

// FilterField returns the application field that a field of an application
// filter selects on. name and exclude select on no field.
func FilterField(name string) (string, bool) {
	i, ok := filterIndex[name]
	if !ok {
		return "", false
	}
	return filterFields[i].app, true
}

// ErrNoEntries is a success answer without an entry, such as "No data found"
// (spec 2026-10-16 §2.2, F16).
var ErrNoEntries = errors.New("the answer holds no entry")

// RefusedError is a device answer whose status is error (spec 2026-10-16 §2.2).
type RefusedError struct {
	Code    string
	Message string
}

func (e *RefusedError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = "no message"
	}
	if e.Code != "" {
		return fmt.Sprintf("the device refused the App-ID data (code %s): %s", e.Code, msg)
	}
	return "the device refused the App-ID data: " + msg
}

// entryDepth is the depth of an entry in an answer:
// response/result/application/entry or response/result/application-container/entry (F1).
const entryDepth = 4

// Trim reads a device answer to a show predefined call (spec 2026-10-16 F1)
// and writes its entries with the kept fields only. It writes each entry's
// @name and no other attribute: the device filters by release before it
// answers, so the trim drops @minver (F6, F7, §3.3). It reads the answer as a
// stream and never holds it whole. It returns the number of entries written.
//
// An answer with status error gives a *RefusedError, and a success answer
// without an entry gives ErrNoEntries.
func Trim(r io.Reader, w io.Writer) (int, error) {
	dec := xml.NewDecoder(r)
	enc := xml.NewEncoder(w)
	var werr error
	emit := func(tok xml.Token) {
		if werr == nil {
			werr = enc.EncodeToken(tok)
		}
	}
	var (
		path    []string
		status  string
		code    string
		msg     []string
		n       int
		inEntry bool
		skip    int // the depth of a dropped child, 0 outside one
	)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return n, fmt.Errorf("read the answer: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			d := len(path)
			switch {
			case d == 1:
				if t.Name.Local != "response" {
					return 0, fmt.Errorf("the answer is no PAN-OS response: its root is <%s>", t.Name.Local)
				}
				status, code = attr(t, "status"), attr(t, "code")
			case skip > 0:
			case inEntry && d == entryDepth+1 && !kept(t.Name.Local):
				skip = d
			case inEntry:
				emit(xml.StartElement{Name: xml.Name{Local: t.Name.Local}})
			case d == entryDepth && t.Name.Local == "entry" && status != "error" && path[1] == "result" &&
				(path[2] == "application" || path[2] == "application-container"):
				inEntry = true
				n++
				emit(xml.StartElement{
					Name: xml.Name{Local: "entry"},
					Attr: []xml.Attr{{Name: xml.Name{Local: "name"}, Value: attr(t, "name")}},
				})
			}
		case xml.EndElement:
			d := len(path)
			switch {
			case skip > 0:
				if d == skip {
					skip = 0
				}
			case inEntry:
				emit(xml.EndElement{Name: xml.Name{Local: t.Name.Local}})
				inEntry = d > entryDepth
			}
			path = path[:d-1]
		case xml.CharData:
			switch {
			case status == "error":
				msg = append(msg, string(t))
			case inEntry && skip == 0 && len(bytes.TrimSpace(t)) > 0:
				emit(t)
			}
		}
	}
	if werr == nil {
		werr = enc.Flush()
	}
	switch {
	case werr != nil:
		return n, fmt.Errorf("write the trimmed answer: %w", werr)
	case status == "":
		return 0, errors.New("the answer is no PAN-OS response: it has no status")
	case status == "error":
		return 0, &RefusedError{Code: code, Message: strings.Join(strings.Fields(strings.Join(msg, " ")), " ")}
	case n == 0:
		return 0, ErrNoEntries
	}
	return n, nil
}

// attr returns the value of an attribute, or "".
func attr(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// Encode writes one content file: the trimmed applications and containers of
// a content version, gzipped. A nil containers records that the containers are
// missing (spec 2026-10-16 §2.2); an empty one is an answer without a
// container. The file has this shape:
//
//	<content version="8000-1000" trim="1" containers="missing"?>
//	  <application>…</application><application-container>…</application-container>
//	</content>
func Encode(w io.Writer, version string, apps, containers []byte) error {
	if !ValidVersion(version) {
		return fmt.Errorf("content version %q is not of the form <number>-<number>", version)
	}
	missing := ""
	if containers == nil {
		missing = ` containers="missing"`
	}
	parts := []io.Reader{
		strings.NewReader(fmt.Sprintf(`<content version="%s" trim="%d"%s><application>`, version, TrimVersion, missing)),
		bytes.NewReader(apps),
		strings.NewReader(`</application>`),
	}
	if containers != nil {
		parts = append(parts, strings.NewReader(`<application-container>`), bytes.NewReader(containers),
			strings.NewReader(`</application-container>`))
	}
	parts = append(parts, strings.NewReader("</content>\n"))
	zw := gzip.NewWriter(w)
	if _, err := io.Copy(zw, io.MultiReader(parts...)); err != nil {
		return fmt.Errorf("write the content file: %w", err)
	}
	return zw.Close()
}
