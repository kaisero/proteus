# AGENTS.md

These rules are mandatory. They apply to every package, existing and new.
ARCHITECTURE.md holds the reasoning. This file holds the rules.

## R1 — The schema is the only source of field knowledge

Field names, types, defaults, name length limits, enum values and list shapes
come from the PAN-OS schema (`schema.xml`, `cms-schema.xml`). No package may
hand-write a field mapping that the schema already describes.

Where the schema genuinely does not describe a node, R8 applies.

Check: `go test ./internal/codegen -run TestNoHandWrittenFieldMaps`

## R2 — Read only, everywhere

No package may write to a device, mutate a loaded config, or expose a setter on
a model type. The library answers questions; it never changes anything.

A loaded index is immutable once built. A reload produces a new index and
replaces the pointer.

Check: `go test ./... -run TestPublicAPIIsReadOnly`

## R3 — Nothing is dropped silently

Every element present in the input either lands in a typed field or is preserved
verbatim in an escape-hatch field, and the loader reports a count of what it
could not type. An input element that is neither typed nor preserved is a bug,
not an omission.

This rule exists because pango types a device group's `vsys` as a member list
while Panorama writes an entry list. pango returns an empty value and preserves
nothing, so a round trip deletes the assignment.

Check: `go test ./config -run TestRoundTripLosesNothing`

## R4 — List shape is read from the grammar, never guessed

`<array><sequence name="entry">` is an entry-keyed list and generates a named
type with a `Name`. `<array><element name="member">` is a member list and
generates `[]string`. The generator reads which one the schema says. No
heuristic, no name-based special case.

Check: `go test ./internal/codegen -run TestListShape`

## R5 — Resolution is scope-correct

No lookup resolves a name globally. Every resolution takes an explicit scope —
shared, a vsys, or a device group with its ancestor chain — and sees only what
that scope sees.

A shared dynamic address group resolves to different members in different device
groups. A global resolution silently merges sibling device groups and returns
answers that are wrong rather than incomplete.

Check: `go test ./config -run TestScopedResolution`

## R6 — Generated code is committed, and drift is gated

The generated model is committed to the repository. A schema change that alters
the model must show up as a reviewable diff. CI regenerates and fails if the
result differs from what is committed.

Check: `make generate && git diff --exit-code config/`

## R7 — A performance claim has a benchmark

Any documented latency, throughput or memory figure is backed by a committed
benchmark in the repository. A figure without a benchmark is removed from the
documentation, not left standing.

Check: `go test -bench . ./...`

## R8 — Hand-modelled nodes are declared and justified

A node modelled by hand rather than generated is registered in
`internal/schema.HandModelled`, with the reason and the schema path.

There is one today: `/config/readonly`, which the schema declares as an empty
`skip-validation` sequence. It holds `parent-dg`, the device group hierarchy —
the single most important relationship in a Panorama config.

Check: `go test ./internal/schema -run TestHandModelledIsDeclared`

## R9 — Every claim about PAN-OS behaviour cites its source

Rule evaluation order, inheritance semantics and scoping rules carry a comment
naming the vendor document or the device observation they come from. "As
observed on <device>, <version>" is acceptable. An uncited assertion about
firewall behaviour is not.

Check: review.

## R10 — Indexes are keyed by scope

No index spans scopes, and no lookup resolves a name without one. A scope is
`shared`, `vsys:<name>`, or `dg:<name>` together with its ancestor chain.

A global index merges sibling device groups. Observed on the lab Panorama: one
shared dynamic address group resolves to `10.124.0.0/16` in `host_1_directory`
and `10.125.0.0/16` in its sibling `corp-graz`. A merged answer is wrong, not
merely incomplete.

Rule bitmaps key on the device group rather than on `(serial, vsys)`, because
merged Panorama policy is identical for every firewall in the same device group.

Check: `go test ./index -run TestNoGlobalIndex`

## R11 — Set-shaped state uses Roaring bitmaps

Membership, transitive closure and rule sets use `*roaring.Bitmap`, never
`[]uint32`.

Measured on 5,000 groups chained one inside the next, 137.5M logical edges:
the slice form cost 1,875 ms and 1,193 MB; bitmaps cost 6 ms and 69 MB. Build the
forward closure eagerly and memoise reverse lookups — building the reverse
closure eagerly on the same data cost 26 s and 294 MB.

Check: `go test ./index -run TestClosureRepresentation`
