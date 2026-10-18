package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestTableAlignsColouredCells(t *testing.T) {
	t.Parallel()
	p := palette{on: true}
	var tb table
	tb.row(cell{"deny", p.bad}, plain("rule-a"), plain("x"))
	tb.row(plain("allow-long"), plain("b"), plain("y"))
	var buf bytes.Buffer
	if err := tb.write(&buf, "  ", 2); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if visibleWidth(lines[0]) != visibleWidth(lines[1]) {
		t.Errorf("rows differ in width:\n%q\n%q", lines[0], lines[1])
	}
	if !strings.Contains(lines[0], "\x1b[31mdeny\x1b[0m        rule-a") {
		t.Errorf("padding must follow the colour span: %q", lines[0])
	}
	for _, l := range lines {
		if strings.HasSuffix(l, " ") {
			t.Errorf("trailing space: %q", l)
		}
	}
}

// A row shorter or longer than its neighbours must not panic, and the columns
// every row shares still line up.
func TestTableRowsOfDifferentLengths(t *testing.T) {
	t.Parallel()
	var tb table
	tb.row(plain("a"), plain("bb"), plain("ccc"))
	tb.row(plain("dddd"))
	tb.row(plain("e"), plain("f"))
	var buf bytes.Buffer
	if err := tb.write(&buf, "", 1); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%q", len(lines), buf.String())
	}
	if !strings.HasPrefix(lines[0], "a bb ccc") {
		t.Errorf("row 0 not aligned: %q", lines[0])
	}
	if lines[1] != "dddd" {
		t.Errorf("single-cell row must not be padded: %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], "e f") {
		t.Errorf("row 2 not aligned with row 0's first column: %q", lines[2])
	}
}

// An empty table writes nothing at all, not even a blank line.
func TestTableEmptyWritesNothing(t *testing.T) {
	t.Parallel()
	var tb table
	var buf bytes.Buffer
	if err := tb.write(&buf, "  ", 1); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("empty table wrote %q, want nothing", buf.String())
	}
}
