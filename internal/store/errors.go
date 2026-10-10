package store

import (
	"errors"
	"io/fs"
)

// The kinds of store failure a caller can tell apart with errors.Is, so an
// answer can say which data is missing without reading the message.
var (
	// ErrNoSnapshot: the store has no snapshot to pick, for the device or the id
	// or the time asked.
	ErrNoSnapshot = errors.New("store: no snapshot")
	// ErrNoConfig: the picked snapshot holds no configuration, or the device has
	// snapshots and none of them holds one (such an error matches ErrNoSnapshot
	// too).
	ErrNoConfig = errors.New("store: no configuration")
	// ErrUnreadable: a stored file is there but could not be read or parsed.
	ErrUnreadable = errors.New("store: unreadable")
)

// kindError adds a kind to an error and keeps its message as it is.
type kindError struct {
	kind error
	err  error
}

func (e *kindError) Error() string   { return e.err.Error() }
func (e *kindError) Unwrap() []error { return []error{e.kind, e.err} }

// mark returns err, which errors.Is also matches against kind.
func mark(kind, err error) error {
	return &kindError{kind: kind, err: err}
}

// unreadable marks err as ErrUnreadable unless the file is absent.
func unreadable(err, read error) error {
	if errors.Is(read, fs.ErrNotExist) {
		return err
	}
	return mark(ErrUnreadable, err)
}

// missingOr marks a read failure as missing when the file does not exist, and as
// unreadable otherwise.
func missingOr(missing, err, read error) error {
	if errors.Is(read, fs.ErrNotExist) {
		return mark(missing, err)
	}
	return mark(ErrUnreadable, err)
}
