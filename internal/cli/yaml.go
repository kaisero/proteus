package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// writeYAML prints the envelope as YAML (spec §3.3). It walks the JSON encoding
// token by token, so the JSON tags stay the only schema and no key length limit
// applies.
func writeYAML(w io.Writer, e envelope) error {
	b, err := json.Marshal(normalize(e))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	n, err := yamlNode(dec)
	if err != nil {
		return err
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return err
	}
	return enc.Close()
}

func yamlNode(dec *json.Decoder) (*yaml.Node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case json.Delim:
		kind, tag := yaml.MappingNode, "!!map"
		if v == '[' {
			kind, tag = yaml.SequenceNode, "!!seq"
		}
		n := &yaml.Node{Kind: kind, Tag: tag}
		for dec.More() {
			if kind == yaml.MappingNode {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, _ := kt.(string)
				n.Content = append(n.Content, yamlString(key))
			}
			child, err := yamlNode(dec)
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, child)
		}
		_, err := dec.Token() // the closing delimiter
		return n, err
	case string:
		return yamlString(v), nil
	case json.Number:
		// No tag: the JSON number grammar resolves to int or float by itself, so 0
		// prints as 0, not "!!float 0".
		return &yaml.Node{Kind: yaml.ScalarNode, Value: v.String()}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(v)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	}
	return nil, fmt.Errorf("yaml: unexpected JSON token %T", tok)
}

// yaml11Words are the YAML 1.1 boolean and null words, which yaml.v3 (YAML 1.2)
// leaves plain in some spellings and PyYAML and other 1.1 readers then misread.
var yaml11Words = map[string]bool{
	"y": true, "n": true, "yes": true, "no": true, "on": true, "off": true,
	"true": true, "false": true, "null": true,
}

// sexagesimal is a YAML 1.1 base-60 number: 1:20 reads as 80.
var sexagesimal = regexp.MustCompile(`^[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?$`)

// yamlString is a string scalar. The !!str tag makes yaml.v3 quote every string its
// own resolver would read as something else; the cases it leaves plain but a YAML
// 1.1 reader misreads are forced into double quotes.
func yamlString(s string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
	if s == "" || s == "<<" || s == "=" || yaml11Words[strings.ToLower(s)] || sexagesimal.MatchString(s) {
		n.Style = yaml.DoubleQuotedStyle
	}
	return n
}
