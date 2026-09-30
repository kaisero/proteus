package cli

import "errors"

// colorMode is the --color value (spec §9.1).
type colorMode string

const (
	colorAuto   colorMode = "auto"
	colorAlways colorMode = "always"
	colorNever  colorMode = "never"
)

func parseColor(s string) (colorMode, error) {
	switch m := colorMode(s); m {
	case colorAuto, colorAlways, colorNever:
		return m, nil
	}
	return "", errors.New("want auto, always or never")
}
