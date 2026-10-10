# Simulate policy: does the estate allow a flow?

`proteus simulate policy <source> <destination>` answers whether the estate allows
a flow end to end. It traces the path as [simulate routing](simulate-routing.md)
does, checks the security policy of every firewall and vsys on that path, and gives
one verdict: `allowed`, `denied` or `undecided`. This is **path mode**, the default.

`--file <config.xml>` checks one configuration instead. See
[One configuration](#one-configuration---file).

## A path

```
$ proteus simulate policy 198.18.1.10 198.18.10.100 --port 443
denied at hop 2: fw01 / vsys1, rule block-servers (deny)

simulate policy 198.18.1.10 -> 198.18.10.100 tcp/443            fidelity: exact

  198.18.1.10
     │ 198.18.1.0/24
  ┌─ fw02 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
  │  zones   home -> labor                               │
  │  in      vlan.1        198.18.1.1/24                 │
  │  out     vlan.32       198.19.0.1/24                 │
  │  route   198.18.0.0/15 via 198.19.0.254   static     │
  │  policy  interzone-default (allow)                   │
  └──┬───────────────────────────────────────────────────┘
     │ 198.19.0.0/24   198.19.0.1 -> 198.19.0.254
  ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
  │  zones   transport -> server                         │
  │  in      ethernet1/1   198.19.0.254/24               │
  │  out     ethernet1/2   198.18.10.1/24                │
  │  route   198.18.10.0/24  connected                   │
  │  policy  block-servers (deny)                        │
  └──┬───────────────────────────────────────────────────┘
     │ 198.18.10.0/24
  198.18.10.100   delivered

firewalls on the path: fw02 (home -> labor), fw01 (transport -> server)
```

Each hop's check uses the hop's flow: the addresses after any NAT on an earlier
hop, and the zones that routing gives on that hop. You do not give zones in path
mode.

### The verdict line

The first line is the answer:

| Line | Meaning |
| --- | --- |
| `allowed` | every hop passes and routing delivers the flow |
| `denied at hop N: <device> / <vsys>, rule <name> (<action>)` | a rule or a default rule stops the flow |
| `denied at hop N: no route to <address> on <device>` | routing drops the flow on that hop |
| `undecided at hop N: <device> / <vsys>, <reason>` | proteus cannot decide that hop |

The first hop that stops the flow or that is undecided sets the verdict. Every
other hop is still checked. A hop after the deny shows `(after the deny)`. A deny
after an undecided hop does not decide the flow: the verdict stays `undecided`,
and a note names the later deny.

### The policy row

Each box has a `policy` row with that hop's answer:

| Row | Meaning |
| --- | --- |
| `<rule> (<action>)` | the rule that decides the hop |
| `interzone-default (deny)` | no rule matches; a default rule decides |
| `undecided: <reason>` | the hop is undecided |
| `not evaluated: <reason>` | the check did not run, for example after a routing drop |

A `doubt` row names a doubt that comes from the path or the zones, see
[Undecided](#undecided).

### The start

The path starts where the source is connected, or where the most specific route
to the source leaves. `--device` names the start firewall instead, and `--router`
picks its logical router. When the source is connected to two firewalls, or only
default routes cover it, the command exits 2 and asks you to name the start with
`--device <name>`.

An FQDN endpoint is resolved with this machine's DNS. A path needs one address, so
path mode traces the first IPv4 address. FQDN objects of that name still match.
With `--no-dns`, or when the name resolves to no IPv4 address, the command exits 2:
"path mode needs an address for <name>; remove --no-dns or give an address".

Each device answers from its latest snapshot, or from the latest one at or before
`--at`. For an HA pair, proteus reads the active member's snapshot.

### `--why`

`--why` adds routing's stages, then one block per hop: the security verdict, the
candidate rules with their doubts, the default rule, and the stage table:

```
$ proteus simulate policy 198.18.1.10 198.18.10.100 --port 443 --why
denied at hop 1: fw02 / vsys1, rule interzone-default (deny)
...
hop 1: fw02 / vsys1, security stop: default rule interzone-default (deny), built-in
  - interzone-default deny [default built-in]
  resolve-source      exact 0 198.18.1.10: 2 hits, 0 negated rules
  resolve-destination exact 0 198.18.10.100: 1 hits, 0 negated rules
  derive-zones        exact 0 from home, to labor, as given
  match-service       exact 0 tcp/443
  match-url           exact 0 no candidate names a URL category
  drop-disabled       exact 0 0 disabled
  order               exact 0 0 in order
  first-match         exact 0 no enabled rule matches; default rule interzone-default (deny), built-in
```

### Exit codes

| Exit | When |
| --- | --- |
| 0 | `allowed` or `denied`, with a complete answer |
| 3 | `undecided`, an unresolved entry, or a hole (a device without a snapshot, a configuration that cannot be read) |
| 2 | the command line must change: no start, a start tie, or a flag path mode refuses |

`--output json` gives one result with `mode`, `verdict`, `at` (the hop, the check,
the rule and the reason), `fidelity`, routing's fields, and per hop `doubts`,
`after_deny` and `checks.security`. The security block has the same keys as with
`--file`.

## Undecided

proteus decides a hop at the first candidate rule that it can evaluate in full.
An earlier candidate that it cannot evaluate is **in doubt**: the firewall can
match it first. When every such rule has the same action, the hop is still
decided, and the fidelity says `overmatch`. When one of them has another action,
the hop is undecided.

A hop is undecided for one of these causes:

- **Doubts on a rule.** A candidate above the match names:
  - an application, or service `application-default`;
  - a predefined service such as `service-https`, or no service;
  - a user, a HIP profile or a schedule;
  - a URL category, when no `--url` is given or the category is not in the
    configuration (a PAN-DB category);
  - an external dynamic list, a region or a dynamic address group as source or
    destination. These rules stay candidates, because their members are known only
    at runtime.
- **Doubts on the path.** ECMP (other next hops are not followed), a PBF rule that
  can redirect the flow, a NAT or PBF answer that can miss matches, or a start that
  only a default route places.
- **Zones.** The hop's vsys is unknown, a zone is missing, a zone is the
  placeholder `external` of a vsys crossing, or the zone is not defined in the
  vsys.
- **Default rules.** The local and the pushed override of a default rule have
  different actions. proteus does not know which one wins.
- **Routing ends.** The path leaves the estate, loops, or ends unresolved.

```
$ proteus simulate policy 198.18.1.10 198.18.10.100 --port 443
undecided at hop 1: fw02 / vsys1, 198.19.0.77 leaves the estate (not in the inventory)

simulate policy 198.18.1.10 -> 198.18.10.100 tcp/443            fidelity: undermatch

  198.18.1.10
     │ 198.18.1.0/24
  ┌─ fw02 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
  │  zones   home -> labor                               │
  │  in      vlan.1        198.18.1.1/24                 │
  │  out     vlan.32       198.19.0.1/24                 │
  │  route   198.18.0.0/15 via 198.19.0.77   static      │
  │  policy  interzone-default (allow)                   │
  └──┬───────────────────────────────────────────────────┘
     │ 198.19.0.0/24
  198.19.0.77   leaves the estate (not in the inventory)

firewalls on the path: fw02 (home -> labor)
may be incomplete: the path leaves the estate at 198.19.0.77
unresolved: fw02/vsys1: 198.19.0.77 leaves the estate (not in the inventory)
```

That run exits with code 3.

A destination that the firewall itself owns is checked like any other hop. A note
says that the firewall's own services (the interface management profile) are not
checked.

## Default rules and rule-type

A firewall evaluates its default rules after every other rule. proteus does the
same. `intrazone-default` decides a flow with equal zones and `interzone-default`
a flow with different zones. The built-in actions are allow and deny. An override
in the configuration changes the action:

| Source | Where it comes from |
| --- | --- |
| `built-in` | no override |
| `local` | the vsys's own default rule override |
| `pushed` | an override that Panorama pushed |

When a local and a pushed override have the same action, `local` is shown. When
they differ, the hop is undecided.

A rule's `rule-type` is applied too. A `universal` rule needs both zones in its
lists. An `intrazone` rule matches equal zones only, and an `interzone` rule
different zones only. Path mode always knows both zones. With `--file`, the
default rules apply only when both zones are given and defined in the vsys.
Rule-type applies then too, and when the zones are derived with one zone on each
side; the answer is then inferred. With several derived zones on a side, an
`intrazone` or `interzone` rule stays in doubt (`zone.derived`), and the answer is
undecided when that rule could change it.

## One configuration: `--file`

`--file` checks one configuration file, with no inventory and no path. `--vsys`
picks the vsys. Give the zones with `--from-zone` and `--to-zone`, both or neither:

```
$ proteus simulate policy 10.2.0.5 10.1.0.5 --port 443 \
    --from-zone dmz --to-zone inside --file testdata/config/firewall-zones.xml
10.2.0.5 -> 10.1.0.5 tcp/443
file / vsys1   testdata/config/firewall-zones.xml
  zones      from dmz, to inside (given)
  relevance  unknown: no stored forwarding table
  fidelity   exact
first match: interzone-default (deny), default rule (built-in)
```

Without zones, proteus derives them from the configuration's interfaces and
routes. A derived zone is always `inferred`, and no default rule can decide: a flow
that no rule matches is then undecided, "the default rule depends on the zones".

`--file` does not check NAT. The zones are the zones before NAT. Path mode applies
NAT on each hop.

`--why` shows every stage, each candidate with its doubts, and the default rule:

```
$ proteus simulate policy 198.19.0.254 10.2.0.5 --port 443 --why \
    --from-zone labor --to-zone dmz --file testdata/config/firewall-doubt.xml
198.19.0.254 -> 10.2.0.5 tcp/443
file / vsys1   testdata/config/firewall-doubt.xml
  zones      from labor, to dmz (given)
  relevance  unknown: no stored forwarding table
  fidelity   overmatch: earlier candidates in doubt share the action deny: labor-app; not evaluated: application
  resolve-source      exact     13 198.19.0.254: 1 hits, 0 negated rules
  resolve-destination exact     11 10.2.0.5: 0 hits, 0 negated rules
  derive-zones        exact     1  from labor, to dmz, as given
  match-service       exact     1  tcp/443
  match-url           exact     1  no candidate names a URL category
  drop-disabled       exact     1  0 disabled
  order               exact     1  1 in order
  first-match         overmatch 1  every candidate is in doubt; default rule interzone-default (deny), built-in
  14. labor-app         deny [local vsys:vsys1]
      doubt: application not evaluated (dropbox)
  -   interzone-default deny [default built-in]
first match: interzone-default (deny), default rule (built-in)
```

`labor-app` names an application, so it is in doubt. It denies, like the default
rule, so the answer is still decided.

An undecided answer ends with the first rule that surely matches, and the cause:

```
first certain match: dmz-plain (allow)
undecided: dmz-user (deny) at position 7 may match first: user not evaluated (corp\alice)
```

That run exits with code 3.

### The stages

A check runs named stages. Each stage removes candidate rules and declares its
[fidelity](../concepts.md#how-certain-an-answer-is).

| Stage | What it does |
| --- | --- |
| `resolve-source` | keeps rules whose source reaches the source address or FQDN |
| `resolve-destination` | the same for the destination |
| `derive-zones` | keeps rules whose zones and rule-type match, given or derived |
| `match-service` | keeps rules whose service holds `--port` |
| `match-url` | keeps rules whose URL category matches `--url` |
| `drop-disabled` | removes disabled rules |
| `order` | sorts the rest in evaluation order and lists each rule's doubts |
| `first-match` | decides at the first rule without doubt, else at a default rule |

`--url` matches custom URL categories. A rule that names a PAN-DB category stays a
candidate, in doubt. An FQDN resolves with this machine's DNS. The name matches
FQDN objects, and each address matches everything else.

## Flags that path mode refuses

These flags exit 2 in path mode. The message names the flag.

| Flag | Use instead |
| --- | --- |
| `--vsys`, `--label`, `--from-zone`, `--to-zone` | the path gives the firewalls, the vsys and the zones; use `--file <path> --vsys <name>` for one configuration |
| `--device a --device b` | path mode starts on one device |
| `--router` without `--device` | add `--device` |
| `--each` | arrives in a later release |
| `--fresh`, `--all-devices` | not available: path mode reads stored snapshots |

With `--file`, `--device`, `--label`, `--at` and `--router` exit 2: they select from
the store.

## Schema version gap

A configuration from a PAN-OS version without its own schema digest is read with
the nearest digest. For `simulate policy` this is a note, not an unresolved entry.
The check's fidelity is `inferred`, and the answer can still be `allowed` or
`denied`.

## What is not evaluated yet

- `--application` and `--user` are accepted but not evaluated. A rule that names
  an application or a user is in doubt.
- The return path is not checked.
- See [Limits](../limits.md#simulate-policy).
