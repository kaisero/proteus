package codegen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/okaiser/go-panos-schema/internal/schema"
)

const maxInlineDepth = 12

// Emit renders every generated type as one Go package.
func Emit(pkg string, names []TypeName, groups map[string][]*schema.Node) string {
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

	sorted := append([]TypeName{}, names...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Canonical < sorted[j].Canonical })

	for _, tn := range sorted {
		seq := groups[tn.Fingerprint][0].EntrySequence()
		fmt.Fprintf(&sb, "// %s is reached by %d config path(s). Shallowest: %s\ntype %s struct {\n",
			tn.Canonical, len(tn.Paths), tn.Shallowest, tn.Canonical)
		writeFields(&sb, seq, tn.Canonical, byFP)
		fmt.Fprintf(&sb, "\t%s []RawNode `xml:\",any\"`\n}\n\n", ReservedUntyped)
		fmt.Fprintf(&sb, "// %sList is an entry-keyed list of %s.\ntype %sList struct {\n\tEntry []%s `xml:\"entry\"`\n}\n\n",
			tn.Canonical, tn.Canonical, tn.Canonical, tn.Canonical)
		for _, a := range tn.Aliases {
			fmt.Fprintf(&sb, "// %s names the same shape as %s.\ntype %s = %s\n\n", a, tn.Canonical, a, tn.Canonical)
			fmt.Fprintf(&sb, "// %sList names the same shape as %sList.\ntype %sList = %sList\n\n",
				a, tn.Canonical, a, tn.Canonical)
		}
	}

	emittedInline := map[string]bool{}
	for _, tn := range sorted {
		seq := groups[tn.Fingerprint][0].EntrySequence()
		writeInline(&sb, tn.Canonical, seq, byFP, emittedInline, 0)
	}
	return sb.String()
}

// writeFields renders one struct's fields. Choice and union wrappers are already
// flattened by schema.Node.Fields.
func writeFields(sb *strings.Builder, seq *schema.Node, owner string, byFP map[string]TypeName) {
	used := map[string]bool{ReservedUntyped: true}
	for _, f := range seq.Fields() {
		if f.Kind == schema.KindAttrReq && f.Name == "name" {
			sb.WriteString("\tName string `xml:\"name,attr\"`\n")
			used["Name"] = true
		}
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
			if child := byFP[schema.Fingerprint(f)]; child.Canonical != "" {
				fmt.Fprintf(sb, "\t%s *%s `xml:%q`\n", field, child.Canonical, tag)
				continue
			}
			fmt.Fprintf(sb, "\t%s *%s `xml:%q`\n", field, inlineName(owner, field), tag)
		case f.Kind == schema.KindElement:
			fmt.Fprintf(sb, "\t%s %s `xml:%q`\n", field, GoLeafType(f.Type), tag)
		}
	}
}

// inlineName names a sequence that is not itself an entry type, so it has no
// shape group of its own.
func inlineName(owner, field string) string { return owner + field }

func writeInline(sb *strings.Builder, owner string, seq *schema.Node,
	byFP map[string]TypeName, done map[string]bool, depth int,
) {
	if depth > maxInlineDepth {
		return
	}
	for _, f := range seq.Fields() {
		if f.Kind != schema.KindSequence || f.Name == "" {
			continue
		}
		if byFP[schema.Fingerprint(f)].Canonical != "" {
			continue // an entry type already covers this shape
		}
		name := inlineName(owner, Pascal(f.Name))
		if done[name] {
			continue
		}
		done[name] = true
		fmt.Fprintf(sb, "// %s is an inline sequence under %s.\ntype %s struct {\n", name, owner, name)
		writeFields(sb, f, name, byFP)
		fmt.Fprintf(sb, "\t%s []RawNode `xml:\",any\"`\n}\n\n", ReservedUntyped)
		writeInline(sb, name, f, byFP, done, depth+1)
	}
}
