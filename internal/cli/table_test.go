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
