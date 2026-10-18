package cli

import (
	"errors"
	"regexp"
	"unicode/utf8"
)

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

// useColor decides for one stream (spec §9.1). Machine formats are never coloured.
// NO_COLOR, CLICOLOR_FORCE and TERM act on auto only; CLICOLOR is not read.
func useColor(mode colorMode, f format, getenv func(string) string, terminal bool) bool {
	if f != formatText {
		return false
	}
	switch mode {
	case colorNever:
		return false
	case colorAlways:
		return true
	}
	if getenv("NO_COLOR") != "" {
		return false
	}
	if v := getenv("CLICOLOR_FORCE"); v != "" && v != "0" {
		return true
	}
	if getenv("TERM") == "dumb" {
		return false
	}
	return terminal
}

// palette styles text by meaning, never by command (spec §9.2). The zero palette
// writes plain text.
type palette struct{ on bool }

func (p palette) bad(s string) string    { return p.sgr("31", s) } // holes, failures, deny
func (p palette) warn(s string) string   { return p.sgr("33", s) } // unresolved, partial, over-match
func (p palette) ok(s string) string     { return p.sgr("32", s) } // allow, exact, ok
func (p palette) head(s string) string   { return p.sgr("1", s) }  // target headers
func (p palette) dim(s string) string    { return p.sgr("2", s) }  // notes, log path, timings
func (p palette) accent(s string) string { return p.sgr("36", s) } // the first match

func (p palette) sgr(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// sgrSeq is one SGR escape sequence.
var sgrSeq = regexp.MustCompile("\x1b\\[[0-9;]*m")

// visibleWidth counts the runes a terminal shows: SGR sequences take no room.
func visibleWidth(s string) int {
	return utf8.RuneCountInString(sgrSeq.ReplaceAllString(s, ""))
}
