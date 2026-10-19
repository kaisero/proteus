package fetch

import "github.com/kaisero/proteus/internal/reason"

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
	// FetchedFrom is the host that answered when it is not the device's own: the
	// active peer of a device found passive (the ha step).
	FetchedFrom string
	// Notes say what a reader of the snapshot should know, such as an HA state that
	// was not followed.
	Notes []reason.Reason
	// Apps is the device's App-ID data: nil when the device refused it or the
	// step failed.
	Apps *AppData
	// ConfigSource names where the configuration came from: "running+template",
	// "running", "export+template" or "export". The first word names the base,
	// the export after a fallback; +template says that the merge used the
	// pushed template. It is empty when the configuration did not arrive (spec
	// 2026-10-17 §2.1).
	ConfigSource string
	// Identity is the identity file of the device, gzip JSON to store as
	// identity.FileName; nil when the identity step was skipped or failed
	// (spec 2026-10-17 §3, §4.1).
	Identity []byte
}

// AppData is the App-ID data of one fetch (spec 2026-10-16 §2.2).
type AppData struct {
	// Version is the content version, such as 8000-1000.
	Version string
	// File is the gzip content file to store; nil on a hit, when the store
	// holds the file of Version already.
	File []byte
	// ContainersMissing says that the device answered the applications and
	// not the containers. The file records it too.
	ContainersMissing bool
}
