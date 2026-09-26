# go-panos-schema

A read-only Go interface to a PAN-OS or Panorama configuration, with the object
model generated from PAN-OS's own configuration schema.

Other tools consume this library. It parses a config file and answers questions
about it. It never contacts a device and it never writes.

> **Status: skeleton.** The layout, build tooling and rules are in place. The
> implementation is not. See ARCHITECTURE.md for the design questions still open.

## Why generated, not hand-written

Every PAN-OS appliance ships its own configuration schema. Generating the model
from it gives **2,289** object types against pango's **117**, and removes a class
of defect that hand-maintained specs cannot avoid.

A concrete example: pango types a device group's `vsys` assignment as a member
list, but Panorama writes an entry list. pango returns an empty value and
preserves nothing, so a round trip deletes the assignment. The schema states the
shape unambiguously, so a generator cannot get it wrong.

The schema also carries the reference graph — 11,725 `memberof` declarations
saying which objects each field may point at — plus name length limits, defaults,
enum values and help strings.

## Getting the schema

The schema is not published and the device API does not serve it. Copy it off an
appliance:

```bash
make schema-pull HOST=labadmin@your-panos-vm
```

That fetches `schema.xml`, `cms-schema.xml` and `opschema.xml` from
`/opt/pancfg/mgmt/factory/` into `schemas/`. These are vendor files and are not
committed; see ARCHITECTURE.md.

## Development

```bash
make tools     # install pinned dev tools
make hooks     # enable the pre-commit gate
make gate      # tidy + lint + tests (what the hook runs)
make ci        # everything CI runs
make generate  # regenerate the model from schemas/
```

`make help` lists every target.

## Rules

AGENTS.md holds the rules that govern this repository. They are mandatory, and
each one names the check that enforces it.

## Licence

MIT. See LICENSE.
