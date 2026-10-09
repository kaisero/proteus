# AGENTS.md

Technical context for coding agents lives in
[`.agents/context/`](.agents/context/index.md). Start at the index, then open
only the subsystem deep-dive you need. That set explains mechanism and rationale.

This file holds the rules. They are mandatory and they apply to every package,
existing and new. `ARCHITECTURE.md` holds the reasoning behind the design as a
whole.

## R1 — The schema is the only source of field knowledge

Field names, types, defaults, name length limits, enum values and list shapes
come from the PAN-OS firewall schema (`schema.xml`). No package may
hand-write a field mapping that the schema already describes.

Where the schema genuinely does not describe a node, R8 applies.

Check: review.

## R2 — Read only, everywhere

No package may write to a device, mutate a loaded config, or expose a setter on
a model type. proteus answers questions; it never changes anything.

A loaded index is immutable once built. A reload produces a new index and
replaces the pointer.

The fetcher is the one package that talks to a device. It asks for an API key, runs
`<show>` commands and exports the configuration; `fetch.Client` refuses any other
op command before it reaches the device, and has no method for anything else.

Check: `go test ./... -run TestPublicAPIIsReadOnly`
Check: `go test ./internal/fetch -run TestOnlyReadCalls`

## R3 — Nothing is dropped silently

Every element present in the input either lands in a typed field or is preserved
verbatim in an escape-hatch field, and the loader reports a count of what it
could not type. An input element that is neither typed nor preserved is a bug,
not an omission.

This rule exists because a hand-written model can type an entry list as a member
list. pango did so for a vsys assignment: it returned an empty value and preserved
nothing, so a round trip deleted the assignment.

Check: `go test ./internal/config -run TestRoundTripLosesNothing`

## R4 — List shape is read from the grammar, never guessed

`<array><sequence name="entry">` is an entry-keyed list, and
`<array><element name="member">` is a member list. The schema parser records
which one the schema says, the digest carries it, and every reader of a
configuration takes it from there. No heuristic, no name-based special case.

Check: `go test ./internal/schema -run TestParseListShape`

## R5 — Resolution is scope-correct

No lookup resolves a name globally. Every resolution takes an explicit scope —
shared or a vsys — and sees only what that scope sees.

A shared dynamic address group resolves to different members in different vsys.
A global resolution silently merges sibling vsys and returns answers that are
wrong rather than incomplete.

Check: `go test ./internal/config -run TestScopedResolution`

## R6 — Retired

R6 gated drift in a Go model generated from the schema. Nothing read that model:
`resolve` and `index` read the configuration as an element tree guided by the
digest. The model and its generator were removed on 2026-09-29. The number stays
unused so the other rules keep theirs.

## R7 — A performance claim has a benchmark

Any documented latency, throughput or memory figure is backed by a committed
benchmark in the repository. A figure without a benchmark is removed from the
documentation, not left standing.

Check: `go test -bench . ./...`

## R8 — Hand-modelled nodes are declared and justified

A node modelled by hand rather than read from the schema is registered in
`internal/schema.HandModelled`, with the reason and the schema path.

Today two nodes are registered: the built-in action of the default security rules,
and the pushed default security rules under `shared/post-rulebase`.

Check: `go test ./internal/schema -run TestHandModelledIsDeclared`

## R9 — Every claim about PAN-OS behaviour cites its source

Rule evaluation order, inheritance semantics and scoping rules carry a comment
naming the vendor document or the device observation they come from. "As
observed on <device>, <version>" is acceptable. An uncited assertion about
firewall behaviour is not.

Check: review.

## R10 — Indexes are keyed by scope

No index spans scopes, and no lookup resolves a name without one. A scope is
`shared` or `vsys:<name>`, and a vsys inherits shared.

A global index merges sibling scopes. First observed on a lab device: one shared
dynamic address group resolved to `10.124.0.0/16` in one scope and
`10.125.0.0/16` in its sibling. Sibling vsys on one firewall stand in this
relation. A merged answer is wrong, not merely incomplete.

Rule bitmaps key on the vsys, because each vsys has its own rulebase.

Check: `go test ./internal/index -run TestNoGlobalIndex`

## R11 — Set-shaped state uses Roaring bitmaps

Membership, transitive closure and rule sets use `*roaring.Bitmap`, never
`[]uint32`.

Measured on 5,000 groups chained one inside the next, 137.5M logical edges:
the slice form cost 1,875 ms and 1,193 MB; bitmaps cost 6 ms and 69 MB. Build the
forward closure eagerly and memoise reverse lookups — building the reverse
closure eagerly on the same data cost 26 s and 294 MB.

Check: `go test ./internal/index -run TestClosureRepresentation`

## R12 — The read-only core imports no I/O, and dependencies point one way

`config`, `resolve` and `index` import no `net`, `net/http`, `net/url` or `os/exec`,
and no package of this module except each other, `internal/schema`,
`internal/digest` and `internal/reason`. `index` does not import `simulate`. `fetch`
imports neither `simulate` nor `estate`. `store` does not import `fetch`. `search`
and `drift` answer from one configuration and import none of `fetch`, `store` or
`estate`. `card` builds lookup's cards from one configuration and imports none of
`fetch`, `store`, `estate` or `simulate`. `simulate` is a leaf: it imports no
simulation implementation and none of `estate`, `store`, `fetch`, `search` or
`drift`. `internal/simulate/securitypolicy` imports none of `estate`, `store` or
`fetch`. `internal/simulate/routing` imports none of `estate`, `store`, `fetch`,
`search` or `drift`, and no I/O package: every device's data reaches it through
`simulate.Network`. `internal/task` runs staged operations for the command line; it
imports no I/O package and no package of this module except `internal/runlog` and
`internal/reason`. `fetch` may import `task`. What the simulations share lives in
the leaf packages `internal/simulate/topology` (interfaces, forwarding tables,
placement) and `internal/simulate/rulebase` (rulebase matching, PBF), which import
no simulation and no I/O package. `internal/simulate/nat` is also the NAT engine:
`routing` and `securitypolicy` may import it, and it imports neither of them, nor
I/O. `internal/simulate/pathpolicy` answers a flow along its path: it may import
`simulate`, `simulate/routing`, `simulate/securitypolicy`, `resolve`,
`simulate/topology`, `config`, `index` and `reason`, and imports none of `estate`,
`store`, `fetch`, `search`, `drift`, `card`, and no I/O package. `internal/query`
answers the questions for every front end: it may import the simulations, `estate`,
`store`, `inventory`, `search`, `drift`, `card`, `resolve`, `index`, `config`,
`runlog` and `reason`, and reaches none of `fetch`, `cli`, `mcp`, Cobra or a
terminal package; `cli` imports it. `internal/reason` names the reason codes answers
carry. It imports only the standard library, and every package may import it: each
rule above allows it. The test helpers `internal/fakepanos` and
`internal/simulate/pathlab` import `testing`; only tests import them.
`internal/reason` also imports `testing`, for `testing.Testing()` alone: its strict
hook, which makes `reason.New` panic on an unregistered code in a test binary. It is
not a test helper, and production code imports it. `internal/mcp` imports `testing`
for the same call: in a test binary its panic recover panics on, so a bug fails the
test instead of hiding as `call.internal`. `internal/mcp` is the only
package that imports the MCP Go SDK (`github.com/modelcontextprotocol/go-sdk`) or
`github.com/google/jsonschema-go`, in its code and in its tests. They and the
modules they bring (`segmentio/asm`, `segmentio/encoding`, `uritemplate`,
`x/oauth2`, `x/sync`, `x/time`) are the one dependency added for the MCP server;
any other new dependency needs its own decision.

The core's freedom from I/O is an absolute property today. A fetcher in the same
module makes it a conditional one, and conditional invariants decay unless a test
holds them. A rule for a package that does not exist yet passes; it binds when
the package lands.

Check: `go test ./internal/archtest -run 'TestImportDirection|TestTestHelpersStayInTests|TestOnlyMCPImportsTheSDK'`
