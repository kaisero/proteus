# Concepts

This page explains the model behind every answer. Read it once. The guides use
these terms without explaining them again.

## Inventory and devices

The **inventory** is a YAML file that lists your firewalls. Each entry is a
**device**: a name, a host, login settings and free-form labels such as
`site: vienna`. Commands select devices by name (`--device fw01`) or by label
(`--label site=vienna`). Without a selection, a question uses every device.

See [Configuration](configuration.md) for the file format.

## Snapshots and the store

`proteus fetch` writes one **snapshot** per device. A snapshot is a directory
with one XML file per document and a `meta.json`:

| Document | Source | Used for |
| --- | --- | --- |
| `config.xml` | configuration export | every question |
| `system-info.xml` | `show system info` | model, serial, PAN-OS version |
| `interfaces.xml` | `show interface all` | zones, interfaces, addresses |
| `fib.xml` | forwarding table | zones of an address, routing paths |
| `rib.xml` | routing table | `simulate routing --rib` |
| `ha.xml` | high-availability state | reading the active member of a pair |
| `predefined.xml` | the device's predefined services | the ports of `service-http` and `service-https` |

The **store** keeps the snapshots:

```
~/.local/share/proteus/
  fw01/
    2026-09-27T17-05-00Z/
      config.xml  system-info.xml  interfaces.xml  fib.xml  rib.xml  ha.xml
      predefined.xml
      meta.json
    latest -> 2026-09-27T17-05-00Z
  .content/
    8000-1000.v1.xml.gz
```

The **App-ID data** of a device is not a document of its snapshot. `.content/`
holds one file per App-ID content version: the predefined applications and
containers, with the fields that proteus needs. Every device and snapshot with
that content version shares the file. `meta.json` names the version as
`app_version`. The directory has mode 0700, and each file has mode 0600. See
[Snapshots](guides/snapshots.md#app-id-data).

Questions read `latest` by default. `--at <time>` reads the newest snapshot at or
before that time. The store keeps the newest 20 snapshots with a configuration
and the newest 20 without one, per device, by default (`snapshot_keep`).

A snapshot is written to a hidden directory first and then renamed. A reader
never sees half a snapshot.

## Scope

A **scope** is `shared` or one vsys. A vsys sees its own objects and the shared
objects. Two vsys do not see each other.

Every answer is keyed by device **and** vsys. The same shared group can hold
different members in two vsys, because each vsys adds its own tagged objects to a
dynamic group. proteus therefore never resolves a name across all vsys at once.
A merged answer would be wrong, not only incomplete.

## Rule layers

A firewall evaluates security rules in this order:

1. shared pre-rules, pushed by Panorama
2. the vsys's own rules
3. shared post-rules, pushed by Panorama
4. the default rules

proteus reads each firewall's own configuration. A managed firewall already
carries the rules that Panorama pushed to it, so proteus does not read Panorama.

## Value spaces

A rule field accepts values from several kinds of object. A security rule's
`source` accepts an address, an address group, a region, an external list and an
IP block list. Each kind is a **value space**. proteus takes the list of kinds per
field from the PAN-OS schema, not from hand-written code.

The type of a search term chooses how it matches:

| Term | Default match | Example |
| --- | --- | --- |
| address | covered by the value | `10.1.1.5` |
| prefix or range | overlaps the value | `10.1.0.0/16`, `10.1.1.1-10.1.1.9` |
| port | covered by the service | `tcp/8443`, `8443` |
| URL | PAN-OS URL tokens | `shop.example.com/cart` |
| anything else | exact name or value | `web-servers` |

## Four paths from a value to a rule

A rule field reaches a value in four ways:

1. The field names an object whose value matches.
2. The field names a group that holds such an object, at any depth.
3. The field holds the value directly, without an object.
4. The field is `any`.

`search` reports the first three, because it answers "where does this appear".
`simulate` uses all four, because it answers "which rule would this traffic hit".

## How certain an answer is

Every simulation stage declares a **fidelity**. The answer carries the weakest
one.

| Fidelity | Meaning |
| --- | --- |
| `exact` | The device would compute the same result. |
| `overmatch` | The answer can hold rules the device would not match. A candidate list stays safe. |
| `inferred` | The answer uses data the device may not use, for example a zone derived from a route. |
| `undermatch` | The answer can miss rules the device would match. |

An answer can also carry:

- **holes**: a device or vsys that proteus could not read. The answer covers the
  rest.
- **unresolved** entries: a value that proteus recognised but could not
  evaluate. The answer can miss matches.
- **notes**: a qualification that does not change the answer, for example an old
  snapshot.

A command that returns holes or unresolved entries exits with code 3. A script can
then refuse to act on the answer. See [Scripting](guides/scripting.md).

## Relevance

A firewall is **relevant** to a flow when it has a route to the source or the
destination that is more specific than the default route. `simulate policy
--file` prints a `relevance` line. It says `unknown`, because one configuration holds
no forwarding table. Path mode needs no relevance: it checks the firewalls on the
path.

## The schema digest

Every PAN-OS firewall carries its configuration schema. The schema says which
fields exist, which lists hold named entries, and which objects a field can
reference. proteus embeds one compact **digest** of that schema and reads every
PAN-OS version with it. The schema changes little between releases.

## Run log

Every command writes one log file. A command that fails or exits with code 3
prints the path of its log. `--log-level debug` records every API call and, for a
simulation, what each stage kept. Passwords and API keys never reach the log.
