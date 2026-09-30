package cli

import (
	"io"
	"strings"
)

// cell is one table cell: its text, and the palette method that styles it.
type cell struct {
	text  string
	style func(string) string // nil for plain
}

func plain(s string) cell { return cell{text: s} }

// table aligns cells by their visible width (spec §10). A cell prints as its styled
// text followed by plain padding, so colour never moves a column or covers padding.
// The last cell of a row is not padded.
type table struct {
	rows [][]cell
}

func (t *table) row(cells ...cell) { t.rows = append(t.rows, cells) }

func (t *table) write(w io.Writer, indent string, gap int) error {
	var widths []int
	for _, r := range t.rows {
		for i, c := range r[:max(len(r)-1, 0)] {
			if i == len(widths) {
				widths = append(widths, 0)
			}
			widths[i] = max(widths[i], visibleWidth(c.text))
		}
	}
	var b strings.Builder
	for _, r := range t.rows {
		b.WriteString(indent)
		for i, c := range r {
			s := c.text
			if c.style != nil {
				s = c.style(s)
			}
			b.WriteString(s)
			if i < len(r)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-visibleWidth(c.text)+gap))
			}
		}
		b.WriteString("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
