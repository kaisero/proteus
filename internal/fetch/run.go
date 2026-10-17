package fetch

import "github.com/okaiser/proteus/internal/reason"

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
