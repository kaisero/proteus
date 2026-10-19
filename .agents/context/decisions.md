# decisions

Validated against 86fd84f on 2026-09-27 · Purpose: why the design is as it is, including the parts that were decided twice.

Each entry is a decision, the reason, and what would change it. Several were
reversed after measurement; those are kept, because the reasoning that failed is
more useful than the conclusion that survived.

## D1 — Take field knowledge from the schema, not from a hand-written SDK

**Decided: schema-first.** `pan-os-python` and `pango` are hand-maintained and
silently lose fields. pango types a vsys assignment as a member list, but the
device writes `<entry name="vsys3"/>`, so the value is dropped and not even kept
in `Misc`. A tool built on that returns a wrong answer with no signal.

The appliance ships its own schema. Reading field shapes from its digest means a
field the schema describes cannot be missing. **R1** enforces it.

**Would change it:** Palo Alto publishing a complete, versioned machine-readable
model.

## D2 — The index is scope-keyed, never global

A name means different things in different scopes. The same shared dynamic address
group resolved to `10.124.0.0/16` in one scope and `10.125.0.0/16` in its
sibling; sibling vsys on one firewall stand in this relation. A global index merges siblings and returns answers that are **wrong**,
not merely incomplete. **R5** and **R10**.

## D3 — Reachability, not a verdict

The index says which rules a value can reach. Intersecting sides, dropping
disabled rules and deciding what a first match means belongs to the caller.

The line is drawn between the part a configuration determines and the part it does
not. Zones, applications and services narrow a match, and a profile decides what
happens afterwards; none of that is a property of the value.

## D4 — The four paths live in one place

They were duplicated across two commands, so the missing `any` path had to be
fixed twice. `internal/index/candidates.go` composes them once.

## D5 — Value spaces, and the trie moves

**The prefix trie was never wrong; its position was.** While it sat on `Index`,
every reachability question was address-shaped, which blocked URLs, ports, users
and zones.

A resolver owns one value space and answers one question: which object names does
this value match. Everything after is identical for every space.

**Resolvers are internal and the set is closed.** A new space is implemented in
`index`, so every one can be held to the same reporting obligation.

## D6 — Resolver wiring comes from the schema

The schema already declares which object kinds each field accepts. Deriving it from
the configuration cannot work: `any` is a keyword that yields no walk event, so an
all-`any` rulebase would look as though `source` names nothing.

This also revealed that `source` accepts `region`, `external-list` and
`ip-block-list-v2`, which were silently ignored before.

## D7 — Providers attach to a View, not to the Index

An index is cached per `(file, scope)` and immutable. User-ID data changes far
faster. Baking it in would poison the cache or force rebuilds.

## D8 — The read-only core performs no I/O

Providers are interfaces or immutable values (the App-ID and the User-ID data);
fetching and loading are the caller's job. This keeps the core
offline, deterministic and testable, and it matches D3: the core answers from
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
as such in `internal/resolve/urlpattern.go`.

**Would change it:** traffic through a device and the URL filtering log.

## D12 — Profile paths carry no verdict

A rule reaches a category two ways. Its `category` field takes part in matching.
Its profile setting does not: the rule matches, and then the profile inspects the
request. What the profile then does depends on the response and the session,
neither of which is in a file.

So `ProfileUses` reports the path and the action list, and stops. Profile paths are
kept out of the rule bitmaps for the same reason.

## D13 — Zones are given for simulation, and inferred only on request

**This was decided wrongly first.** The measured gap between proteus and a
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

`go:embed` cannot reach outside its own package, so `internal/config/schemadigest/` must
exist for the package to compile. While it was gitignored, a pristine checkout did
not build. It is committed, and it is the only copy: the schemadigest tool
writes the digests there.

## D16 — A snapshot holds `show config running`, merged with the pushed template

**This was decided three times** (spec 2026-10-17 D2, owner decisions of
2026-10-18). The export misses every value that a Panorama template pushes (C1):
zones, interfaces, identity sources. The first plan took `show config merged`,
which holds them. Lab round 3 showed that the merged view is the candidate: it held
every uncommitted change of the calling admin (X4). The second plan took the export
plus the pushed template. The C10 runs then showed that the export holds the
candidate too: uncommitted changes of the lab admin and of another admin (C12).
`show config running` held none, and the pushed template holds none, because a
template changes only by a Panorama push, which commits (C10).

So the base is `show config running`, and proteus merges the template itself
(`fetch.MergeTemplate`): an element whose schema node has `tlo="yes"`, a leaf and a
member list keep the local value whole; every other matched element merges by its
children (C6, C11). That rule gave the device's own merged view of a candidate
without content changes, element for element. `show config effective-running`
holds no uncommitted change either, but it adds Panorama device-group content
without marks (C8), so it is the check, not the source. The export stays as the
fallback for a device that refuses `show config running`, with
`note.config-not-running`.

**Would change it:** a device whose running answer lacks a node that it runs, or a
template form the merge does not know (a pushed interface, a variable;
`docs/todo.md` item 80).

## D17 — Dynamic user group membership comes from the device's user list

The device lists the dynamic user groups of each user, as it evaluates them, in
`show user user-ids all` (U3). proteus takes membership from there and evaluates
no tag filter (spec 2026-10-17 D13, owner decision 2026-10-18). A filter evaluator
would need the precedence and the parentheses of the filter grammar, which no lab
round tested (M14), and it could only disagree with the device. A user that U3 does
not list is in no DUG. The registered tags (U9) show in `lookup` only.

**Would change it:** a device whose U3 lags behind its tag registrations in a way
that matters for a snapshot.

## D18 — The User-ID data belongs to each snapshot

`PROTEUS_USERS` named one user-to-group file for every device and every time. It
had no tie to the snapshot an answer read, so a question about last week used
today's groups. Mappings and groups change all the time, so each snapshot keeps its
own `identity.json.gz` (spec 2026-10-17 D4, D8). `fetch` parses the answers at
fetch time and keeps no raw answer; a question loads the file only when it needs it
(PD10), and the MCP cache keeps it per snapshot. No fetch falls back to the data
of an older snapshot: an old mapping looks current and is wrong. Only single-vsys
firewalls get the data (D10), because the file has no vsys key.

**Would change it:** a need for mapping history (`docs/todo.md` item 74) or for
multi-vsys data (item 67).

## See also

- `ARCHITECTURE.md` — the architecture and its open questions
- `AGENTS.md` — the rules these decisions produced
- `docs/plans/` and `docs/specs/` — the working documents, kept out of git by choice
