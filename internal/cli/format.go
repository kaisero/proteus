package cli

import (
	"errors"
	"strings"
)

// format is the --output value.
type format string

const (
	formatText format = "text"
	formatJSON format = "json"
	formatYAML format = "yaml"
)

// formats are the values --output takes, in the order the help lists them.
var formats = []format{formatText, formatJSON}

func parseFormat(s string) (format, error) {
	for _, f := range formats {
		if s == string(f) {
			return f, nil
		}
	}
	names := make([]string, len(formats))
	for i, f := range formats {
		names[i] = string(f)
	}
	return "", errors.New("want " + orList(names))
}

// orList is "a", "a or b", "a, b or c".
func orList(xs []string) string {
	if len(xs) < 2 {
		return strings.Join(xs, "")
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " or " + xs[len(xs)-1]
}
