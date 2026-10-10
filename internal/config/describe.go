package config

import "github.com/okaiser/proteus/internal/schema"

// pushedRulebases are the shared containers of rules pushed from Panorama. The
// firewall schema does not declare them; they hold the shape of a vsys rulebase
// (PAN-OS documentation, "Device Group Policies"), so they are read with its
// schema node, as resolve reads their rules. Both are registered in
// schema.HandModelled (AGENTS.md R8).
var pushedRulebases = map[string]bool{"pre-rulebase": true, "post-rulebase": true}

// SchemaNode returns the digest node that describes an element of this
// configuration, following its path from the root, or nil when the digest does
// not describe it.
func (c *Config) SchemaNode(el *Element) *schema.Node {
	var chain []*Element
	for cur := el; cur != nil; cur = cur.Parent {
		chain = append(chain, cur)
	}
	n := c.schema.root // the configuration's root element, config
	for i := len(chain) - 2; i >= 0 && n != nil; i-- {
		n = c.ChildNode(n, chain[i])
	}
	return n
}

// ChildNode returns the digest node that describes child, an element whose
// parent n describes, or nil when the digest does not describe it.
//
// It is schema.Node.Step with one hand-modelled addition: the shared pushed
// rulebases are described by a vsys rulebase's node.
func (c *Config) ChildNode(n *schema.Node, child *Element) *schema.Node {
	if cn := n.Step(child.Name); cn != nil {
		return cn
	}
	if n != nil && n == c.schema.shared && pushedRulebases[child.Name] {
		return c.schema.rulebase
	}
	return nil
}

// undescribed lists each element of the configuration the digest does not
// describe (AGENTS.md R3). The element stays in the tree with everything below
// it, so nothing is lost; it is listed once, at its top, so a field a newer
// release added counts as one however much it holds.
func (c *Config) undescribed() []Untyped {
	var out []Untyped
	var walk func(el *Element, n *schema.Node)
	walk = func(el *Element, n *schema.Node) {
		for _, ch := range el.Children {
			cn := c.ChildNode(n, ch)
			if cn == nil {
				out = append(out, Untyped{XPath: ch.InstancePath(), Digest: c.digestVersion})
				continue
			}
			if len(ch.Children) > 0 {
				walk(ch, cn)
			}
		}
	}
	walk(c.root, c.schema.root)
	return out
}
