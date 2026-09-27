# decisions

Validated against 86fd84f on 2026-09-27 · Purpose: why the design is as it is, including the parts that were decided twice.

Each entry is a decision, the reason, and what would change it. Several were
reversed after measurement; those are kept, because the reasoning that failed is
more useful than the conclusion that survived.

## D1 — Generate the model from the schema, not from a hand-written SDK

**Decided: schema-first.** `pan-os-python` and `pango` are hand-maintained and
silently lose fields. `devicegroup.Devices.Vsys` is typed as a member list, but
Panorama writes `<entry name="vsys3"/>`, so the value is dropped and not even kept
in `Misc`. A tool built on that returns a wrong answer with no signal.

The appliance ships its own schema. Generating from it means a field the schema
describes cannot be missing. **R1** enforces it.

**Would change it:** Palo Alto publishing a complete, versioned machine-readable
model.

## D2 — The index is scope-keyed, never global

A name means different things in different scopes. The same shared dynamic address
group resolved to `10.124.0.0/16` in one Panorama device group and `10.125.0.0/16`
in its sibling; sibling vsys on one firewall stand in the same relation. (Panorama
support was removed in M1.) A global index merges siblings and returns answers that are **wrong**,
not merely incomplete. **R5** and **R10**.

## D3 — Reachability, not a verdict

The library says which rules a value can reach. Intersecting sides, dropping
disabled rules and deciding what a first match means belongs to the caller.

The line is drawn between the part a configuration determines and the part it does
not. Zones, applications and services narrow a match, and a profile decides what
happens afterwards; none of that is a property of the value.

## D4 — The four paths live in one place

They were duplicated across two commands, so the missing `any` path had to be
fixed twice. `index/candidates.go` composes them once.

## D5 — Value spaces, and the trie moves

**The prefix trie was never wrong; its position was.** While it sat on `Index`,
every reachability question was address-shaped, which blocked URLs, ports, users
and zones.

A resolver owns one value space and answers one question: which object names does
this value match. Everything after is identical for every space.

**Resolvers are internal and the set is closed.** A new space is implemented in the
library, so every one can be held to the same reporting obligation.

## D6 — Resolver wiring comes from the schema

The schema already declares which object kinds each field accepts. Deriving it from
the configuration cannot work: `any` is a keyword that yields no walk event, so an
all-`any` rulebase would look as though `source` names nothing.

This also revealed that `source` accepts `region`, `external-list` and
`ip-block-list-v2`, which were silently ignored before.

## D7 — Providers attach to a View, not to the Index

An index is cached per `(file, scope)` and immutable. User-ID data changes far
faster. Baking it in would poison the cache or force rebuilds.

## D8 — The library performs no I/O

Providers are interfaces; fetching is the caller's job. This keeps the library
offline, deterministic and testable, and it matches D3: the library answers from
what it was given.

## D9 — Incompleteness is reported, never hidden

The failures that matter here are plausible wrong answers. Asking for a URL once
returned nine of ten rules and omitted the only one naming it, because the nine
carried `category any`. Nothing said the URL had never been evaluated.

Later refined: **recognised and unmatched is a complete answer.** Reporting it as
incomplete trains a caller to ignore the warning.

## D10 — Searching and matching are separate calls

PAN-OS matches a URL by token. Substring matching would make
`wildcard-example.com` cover `wildcard-example.com.evil.net`, which the device does
not do. But substring is exactly right for a human question, because a value can be
longer than the name holding it: a custom URL category name is capped at 31
characters and a member at 255.

So `Candidates` is faithful and `SearchValues` is a search, and each says which it
is.

## D11 — URL syntax is device-verified; URL matching is not

The validator runs at `set` time with no commit, so each pattern form was offered
to a real firewall. That produced a fact the device's own error message contradicts:
`*.*.example.com` is rejected although its asterisks are not adjacent. The rule is
one asterisk per pattern; carets may repeat.

Matching could not be verified. `test url` reports PAN-DB categories only, checked
with the category referenced from a profile used by five rules, from a disabled rule
and from an enabled rule. The matching rules are documentation-derived and labelled
as such in `resolve/urlpattern.go`.

**Would change it:** traffic through a device and the URL filtering log.

## D12 — Profile paths carry no verdict

A rule reaches a category two ways. Its `category` field takes part in matching.
Its profile setting does not: the rule matches, and then the profile inspects the
request. What the profile then does depends on the response and the session,
neither of which is in a file.

So `ProfileUses` reports the path and the action list, and stops. Profile paths are
kept out of the rule bitmaps for the same reason.

## D13 — Zones are given for simulation, and inferred only on request

**This was decided wrongly first.** The measured gap between the library and a
device was blamed on missing zone resolution, and a whole zone value space was
planned to close it. The real cause was that `simulate` discarded the zones it was
already given, and the rule bitmaps had carried `from` and `to` since the index was
first built. Passing them through took agreement from 3 of 7 to 7 of 7.

A firewall's own `test security-policy-match` takes zones as input too.

The zone value space still exists, for the different question "which zone would this
address arrive on". It is config-derived and reports every limit.

## D14 — Report what cannot be known; never guess

A `Category Match` category, a URL external list, a dynamic group's runtime
members, an application filter, a zone with no interface, a route learned by BGP. In
every case the honest answer is the reason, and a guess would be indistinguishable
from a fact.

The precedent is the tag-filter parser, which refuses a filter it cannot read rather
than approximating it.

## D15 — Commit the embedded digests

`go:embed` cannot reach outside its own package, so `config/schemadigest/` must
exist for the package to compile. While it was gitignored, a pristine checkout did
not build and neither would `go get`. The copy is committed and `digest-check`
keeps it in step.

## See also

- `ARCHITECTURE.md` — the architecture and its open questions
- `AGENTS.md` — the rules these decisions produced
- `docs/plans/` and `docs/specs/` — the working documents, kept out of git by choice
