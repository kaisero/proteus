# CLI reference

```
proteus <command> [arguments] [flags]
```

Questions are verbs (`search`, `lookup`, `simulate`). Housekeeping is grouped by
noun (`inventory`, `snapshot`). `fetch` stays at the top level because you use it
most.

## Global flags

Every command takes these flags. See [Configuration](configuration.md#settings)
for the matching variables and inventory keys.

| Flag | Meaning |
| --- | --- |
| `--config <path>` | inventory file |
| `--store <path>` | snapshot store |
| `--output text\|json\|yaml` | output format |
| `--color auto\|always\|never` | colour text output; `auto` colours only on a terminal |
| `--max-age <duration>` | add a note to answers from older snapshots, for example `24h` or `7d` |
| `--log-level error\|warn\|info\|debug` | run log level |
| `--log-dir <path>` | where run logs go |
| `--verbose` | echo the run log to stderr |
| `-v`, `--version` | print the version |

## Selection flags

Questions take the same selection flags.

| Flag | Meaning |
| --- | --- |
| `--device <name>` | only these devices; repeatable, any of them |
| `--label key=value` | only devices with this label; repeatable, all must hold |
| `--vsys <name>` | only these vsys; repeatable; default every vsys |
| `--at <time>` | each device's newest snapshot at or before this time: an id, RFC 3339 or a date |
| `--fresh` | fetch the selected devices first |
| `--file <path>` | read one configuration file instead of the store |

`--file` cannot be combined with `--device`, `--label`, `--at` or `--fresh`.

## fetch

```
proteus fetch [device...] [--label key=value] [--all]
```

Logs in to each device, reads its configuration and operational state, and stores
them as a snapshot. Name devices, select them with `--label`, or pass `--all`.
See [Snapshots](guides/snapshots.md#fetch).

| Flag | Meaning |
| --- | --- |
| `--why` | show every stage: what it decided and why |

Stages, in order: `resolve`, `login`, `ha`, `documents`, `store`.

## inventory init

```
proteus inventory init
```

Writes an inventory template with mode 0600. It never overwrites a file.

## snapshot list

```
proteus snapshot list <device>
```

Lists a device's snapshots, newest first. `*` marks `latest`.

## snapshot show

```
proteus snapshot show [selection flags]
```

Shows the snapshots a question would read: version, vsys, rule counts and
documents.

## snapshot diff

```
proteus snapshot diff [selection flags] [--from <time>] [--to <time>]
```

Compares objects and rules per vsys and shared. The default compares the snapshot
before `latest` with `latest`.

| Flag | Meaning |
| --- | --- |
| `--from <time>` | compare from the newest snapshot at or before this time |
| `--to <time>` | compare to the newest snapshot at or before this time; default `latest` |

## search

```
proteus search <term> [selection flags] [flags]
```

Finds every place a value or name appears. See [Search](guides/search.md).

| Flag | Meaning |
| --- | --- |
| `--exact` | the value equals the term |
| `--within` | the value lies inside the term (addresses, prefixes, ranges) |
| `--contains` | the value or name holds the term as text; not a match |
| `--kind <kinds>` | only objects and groups of these kinds |
| `--field <fields>` | only references and literals from these fields |
| `--show <stages>` | only these stages: `objects`, `groups`, `refs`, `literals` |
| `--direct` | groups one level up only |

`--exact`, `--within` and `--contains` exclude each other.

## lookup

```
proteus lookup <name> [selection flags] [flags]
```

Shows the whole rule or object behind a name. See [Lookup](guides/lookup.md).

| Flag | Meaning |
| --- | --- |
| `--kind <kind>` | `security-rule` or an object kind, when several kinds share the name |
| `--expand` | show each name's value and every group's members |
| `--full` | show every item of a list |

## simulate policy

```
proteus simulate policy <source> <destination> [selection flags] [flags]
```

Names the security rule a flow would hit. See
[Simulate policy](guides/simulate-policy.md).

| Flag | Meaning |
| --- | --- |
| `--port <port>` | destination port: `443` or `tcp/443` |
| `--protocol <proto>` | `tcp`, `udp`, `sctp`, `icmp` or a number; default `tcp` |
| `--source-port <n>` | source port |
| `--from-zone`, `--to-zone` | zones; derived when absent |
| `--url <url>` | URL, matched against URL categories |
| `--application`, `--user` | accepted, not evaluated yet |
| `--no-dns` | do not resolve an FQDN endpoint |
| `--why` | show every stage: its fidelity, what it kept and why |

## simulate nat

```
proteus simulate nat <source> <destination> --device <name> [flags]
```

Names the NAT rule a packet hits on one firewall and shows the packet after
translation. See [Simulate NAT](guides/simulate-nat.md).

| Flag | Meaning |
| --- | --- |
| `--device <name>` | the firewall; required |
| `--at <time>` | the newest snapshot at or before this time |
| `--from-zone`, `--from-interface` | where the packet arrives |
| `--router <name>` | the logical router, when the firewall has several |
| `--port`, `--protocol`, `--source-port` | complete the packet |
| `--no-dns` | resolve no FQDN |
| `--why` | list the rules above the match and every stage |

## simulate routing

```
proteus simulate routing <source> <destination>
proteus simulate routing <destination> --device <name>
```

Traces the path a packet takes across the inventory's firewalls. See
[Simulate routing](guides/simulate-routing.md).

| Flag | Meaning |
| --- | --- |
| `--device <name>` | start on this device |
| `--router <name>` | start in this logical router of `--device` |
| `--at <time>` | each device's newest snapshot at or before this time |
| `--port <port>` | decides NAT and PBF rules that name a service |
| `--rib` | list the routing table's other routes at each firewall |
| `--no-dns` | do not resolve an FQDN endpoint |
| `--why` | show every stage |

## completion

```
proteus completion bash|zsh|fish|powershell
```

Prints a shell completion script.

## Output

`--output text|json|yaml` picks the format. JSON and YAML share one envelope.

| Key | Holds |
| --- | --- |
| `format` | the envelope version, always `1` |
| `command` | the command name, for example `search` |
| `input` | the typed input: term, selection and flags |
| `results` | the answer; always an array, empty when there is nothing to show |
| `holes` | devices or parts the command could not read |
| `unresolved` | entries the command could not finish resolving |
| `notes` | extra facts a reader should know |

YAML encodes the same envelope as JSON: same keys, same values, the same array
shape for `results`. Pick whichever a script or a person reads more easily.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | a complete answer, which may be empty |
| 1 | no answer exists: the command could not say which part is missing |
| 2 | the user must change the command line |
| 3 | an answer with holes or unresolved entries |
| 130 | interrupted by SIGINT (Ctrl-C) |
| 143 | interrupted by SIGTERM |

`fetch` is an exception. Every device stored every document: exit 0. A device or
document failed, and at least one device stored: exit 3. No device stored: exit 1.
`fetch` prints its answer in all three cases.

## Errors in machine modes

In `json` and `yaml` mode, the last line of stderr on a non-zero exit is one JSON
object:

```json
{"format":1,"exit":3,"log":"/home/u/.local/state/proteus/log/search-….log"}
{"format":1,"exit":2,"error":"unknown flag: --bogus"}
```

- `error` is absent on exit 3. The answer on stdout already says what is missing.
- `log` is absent when no run log opened, such as an error before any command ran.
- Earlier stderr lines, such as the `--verbose` echo, can come before this line. The
  last line is always the JSON object.
