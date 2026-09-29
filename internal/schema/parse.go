package schema

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
)

var kindByElement = map[string]Kind{
	"sequence": KindSequence, "array": KindArray, "element": KindElement,
	"choice": KindChoice, "union": KindUnion, "attr-req": KindAttrReq,
	"enum": KindEnum, "memberof": KindMemberOf,
}

// transparentElement holds grammar elements that carry no structure of their own
// but do carry reference declarations. They are descended into rather than
// skipped, and anything they declare attaches to the enclosing real node.
//
// This is load-bearing. In the 11.2 firewall schema all 5,038 <memberof>
// elements sit inside a <validate>, and a further 1,020 targets are a memberof
// attribute on <validate> itself. Skipping validate parses without error and
// loses the entire reference graph.
var transparentElement = map[string]bool{"validate": true, "string": true}

// Parse reads a PAN-OS schema document and returns its root node.
//
// Elements the grammar carries but code generation does not need — compute,
// ipspec and UI hints — are skipped. Their absence is deliberate: the digest
// does not carry them either.
func Parse(r io.Reader) (*Node, error) {
	dec := xml.NewDecoder(r)
	var root *Node
	stack := []*Node{}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("schema: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			kind, known := kindByElement[t.Name.Local]
			if !known {
				if transparentElement[t.Name.Local] {
					// Descend. Attach any target it declares to the enclosing node.
					if len(stack) > 0 {
						if target := attrValue(t, "memberof"); target != "" {
							owner := stack[len(stack)-1]
							owner.MemberOf = append(owner.MemberOf, target)
						}
					}
					continue
				}
				if err := dec.Skip(); err != nil {
					return nil, fmt.Errorf("schema: skip %s: %w", t.Name.Local, err)
				}
				continue
			}
			n := newNode(kind, t)
			switch {
			case kind == KindEnum && len(stack) > 0:
				parent := stack[len(stack)-1]
				parent.EnumValues = append(parent.EnumValues, n.Name)
				if err := dec.Skip(); err != nil {
					return nil, fmt.Errorf("schema: skip enum: %w", err)
				}
				continue
			case kind == KindMemberOf && len(stack) > 0:
				target := n.memberOfTarget
				if target == "" {
					text, err := elementText(dec)
					if err != nil {
						return nil, err
					}
					target = text
				} else if err := dec.Skip(); err != nil {
					return nil, fmt.Errorf("schema: skip memberof: %w", err)
				}
				if target != "" {
					parent := stack[len(stack)-1]
					parent.MemberOf = append(parent.MemberOf, target)
				}
				continue
			}
			if len(stack) == 0 {
				root = n
			} else {
				parent := stack[len(stack)-1]
				n.Parent = parent
				parent.Children = append(parent.Children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if _, known := kindByElement[t.Name.Local]; known && len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	if root == nil {
		return nil, fmt.Errorf("schema: no recognised root element")
	}
	return root, nil
}

func newNode(kind Kind, t xml.StartElement) *Node {
	n := &Node{Kind: kind}
	for _, a := range t.Attr {
		switch a.Name.Local {
		case "name":
			n.Name = a.Value
		case "value": // enum carries its literal in value, not name
			if n.Name == "" {
				n.Name = a.Value
			}
		case "type":
			n.Type = a.Value
		case "optional":
			n.Optional = a.Value == "yes"
		case "default":
			n.Default = a.Value
		case "maxlen":
			if v, err := strconv.Atoi(a.Value); err == nil {
				n.MaxLen = v
			}
		case "min":
			n.Min = a.Value
		case "max":
			n.Max = a.Value
		case "help-string":
			n.Help = a.Value
		case "regex":
			n.Regex = a.Value
		case "subtype":
			n.SubType = a.Value
		case "memberof":
			n.memberOfTarget = a.Value
		}
	}
	return n
}

func elementText(dec *xml.Decoder) (string, error) {
	var sb []byte
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("schema: memberof text: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb = append(sb, t...)
		case xml.EndElement:
			return trimSpace(string(sb)), nil
		}
	}
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func attrValue(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}
