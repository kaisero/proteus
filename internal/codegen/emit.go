package codegen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/okaiser/go-panos-schema/internal/schema"
)

// Emit renders every generated type as one Go package.
func Emit(pkg string, root *schema.Node, names []TypeName, shapes Shapes) string {
	byFP := make(map[string]TypeName, len(names))
	for _, n := range names {
		byFP[n.Fingerprint] = n
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "// Code generated from the PAN-OS schema. DO NOT EDIT.\n\npackage %s\n\n", pkg)
	sb.WriteString("import \"encoding/xml\"\n\n")
	sb.WriteString("// MemberList is an <array><element name=\"member\"> list.\n")
	sb.WriteString("type MemberList struct {\n\tMember []string `xml:\"member\"`\n}\n\n")
	sb.WriteString("// RawNode preserves an element the model does not type. See AGENTS.md R3.\n")
	sb.WriteString("type RawNode struct {\n\tXMLName xml.Name\n\tAttrs   []xml.Attr `xml:\",any,attr\"`\n")
	sb.WriteString("\tText    []byte     `xml:\",chardata\"`\n\tNodes   []RawNode  `xml:\",any\"`\n}\n\n")

	writeRoot(&sb, root, byFP)

	sorted := append([]TypeName{}, names...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Canonical < sorted[j].Canonical })

	for _, tn := range sorted {
		var seq *schema.Node
		if tn.Kind == KindEntry {
			seq = shapes.Entry[tn.Fingerprint][0].EntrySequence()
		} else {
			seq = shapes.Inline[tn.Fingerprint][0]
		}
		fmt.Fprintf(&sb, "// %s is the %s shape reached by %d config path(s). Shallowest: %s\ntype %s struct {\n",
			tn.Canonical, tn.Kind, len(tn.Paths), tn.Shallowest, tn.Canonical)
		if tn.Kind == KindEntry {
			sb.WriteString("\tName string `xml:\"name,attr\"`\n")
		}
		writeFields(&sb, seq, byFP)
		fmt.Fprintf(&sb, "\t%s []RawNode `xml:\",any\"`\n}\n\n", ReservedUntyped)

		if tn.Kind == KindEntry {
			fmt.Fprintf(&sb, "// %sList is an entry-keyed list of %s.\ntype %sList struct {\n\tEntry []%s `xml:\"entry\"`\n}\n\n",
				tn.Canonical, tn.Canonical, tn.Canonical, tn.Canonical)
		}
		for _, a := range tn.Aliases {
			fmt.Fprintf(&sb, "// %s names the same shape as %s.\ntype %s = %s\n\n", a, tn.Canonical, a, tn.Canonical)
			if tn.Kind == KindEntry {
				fmt.Fprintf(&sb, "// %sList names the same shape as %sList.\ntype %sList = %sList\n\n",
					a, tn.Canonical, a, tn.Canonical)
			}
		}
	}
	return sb.String()
}

// writeRoot emits the Config type. /config is a sequence, and five of its six
// children are sequences too, so an entry-array walk alone emits none of them and
// the model cannot load a file.
func writeRoot(sb *strings.Builder, root *schema.Node, byFP map[string]TypeName) {
	sb.WriteString("// Config is the root of a PAN-OS or Panorama configuration.\n")
	sb.WriteString("type Config struct {\n")
	sb.WriteString("\tVersion string `xml:\"version,attr\"`\n")
	sb.WriteString("\tDetailVersion string `xml:\"detail-version,attr\"`\n")
	sb.WriteString("\tUrlDB string `xml:\"urldb,attr\"`\n")
	writeFields(sb, root, byFP)
	fmt.Fprintf(sb, "\t%s []RawNode `xml:\",any\"`\n}\n\n", ReservedUntyped)
}

// writeFields renders one struct's fields. Choice and union wrappers are already
// flattened by schema.Node.Fields.
func writeFields(sb *strings.Builder, seq *schema.Node, byFP map[string]TypeName) {
	used := map[string]bool{
		ReservedUntyped: true, "Name": true,
		"Version": true, "DetailVersion": true, "UrlDB": true,
	}
	for _, f := range seq.Fields() {
		if f.Name == "" || f.Name == "member" {
			continue
		}
		field := Pascal(f.Name)
		if used[field] {
			continue
		}
		used[field] = true
		tag := f.Name + ",omitempty"
		switch {
		case f.Kind == schema.KindArray && f.IsEntryList():
			child := byFP[schema.Fingerprint(f.EntrySequence())]
			if child.Canonical == "" {
				continue
			}
			fmt.Fprintf(sb, "\t%s *%sList `xml:%q`\n", field, child.Canonical, tag)
		case f.Kind == schema.KindArray && f.IsMemberList():
			fmt.Fprintf(sb, "\t%s *MemberList `xml:%q`\n", field, tag)
		case f.Kind == schema.KindSequence:
			child := byFP[schema.Fingerprint(f)]
			if child.Canonical == "" {
				continue // an empty sequence the schema describes no fields for
			}
			fmt.Fprintf(sb, "\t%s *%s `xml:%q`\n", field, child.Canonical, tag)
		case f.Kind == schema.KindElement:
			fmt.Fprintf(sb, "\t%s %s `xml:%q`\n", field, GoLeafType(f.Type), tag)
		}
	}
}
