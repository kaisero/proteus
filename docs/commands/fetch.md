# fetch

`fetch` reads the configuration and operational state of each selected firewall and stores them as one snapshot per device.

## Synopsis

```text
proteus fetch [device...] [--label key=value] [--all] [--why]
```

## Examples

### Fetch named devices

```bash
proteus fetch fw01 fw02
```

`fetch` logs in to fw01 and fw02 with the inventory's username and password and
asks each firewall for an API key. It then reads the documents that
[Snapshots](../concepts/snapshots.md) lists and stores them as one snapshot per
device.

### Fetch the devices of a site

```bash
proteus fetch --label site=vienna
```

`--label` selects the devices that carry the label in the inventory. Repeat it to
select the devices that hold every label.

### Fetch every device and show each stage

```bash
proteus fetch --all --why
```

`--all` fetches every device in the inventory. `--why` adds one line per stage
below each device: what the stage decided and why:

```text
$ proteus fetch fw01 --why
fw01: TLS certificate verification on
  config      2992 bytes
  system-info 252 bytes
  interfaces  7786 bytes
  fib         7295 bytes
  rib         15939 bytes
  ha          163 bytes
  predefined  245 bytes
  stored fw01@2026-09-28T10-00-00Z (PA-VM, PAN-OS 11.2.5, serial 000000000001)
  resolve      ok      fw01.example.net, TLS verification on
  login        ok      logged in as reader
  ha           skipped HA is not enabled
  documents    ok      8 of 8 documents
  template     ok      no template pushed to the device
  applications ok      content 8000-1000, 4 applications, 1 container
  identity     ok      9 calls: 4 users, 8 groups, 6 mappings in 1 page, 2 sources
  store        ok      fw01@2026-09-28T10-00-00Z
```

Panorama pushes no template to this firewall, so the `template` stage has nothing
to merge. The `identity` stage stored the User-ID data of the firewall.

## Reading the output

`fetch` prints one block per device, in the order you name them.

| Line | Meaning |
| --- | --- |
| `fw01: TLS certificate verification on` | the device's certificate is verified |
| `fw01: TLS certificate verification OFF (insecure_tls: true)` | the inventory turns verification off for the device |
| `fw01 is the passive HA peer; fetched from the active peer <host>` | the device is passive, and `fetch` read its active peer |
| `note: …` | a note about the device, such as missing App-ID data |
| `<document> <n> bytes` | a stored document and its size |
| `<document> FAILED <error>` | a document that the firewall did not return |
| `stored fw01@<id> (<model>, PAN-OS <version>, serial <serial>)` | the snapshot that `fetch` stored |
| `fw01/<stage>: <error>` | the device failed at that stage |

With `--why`, each stage prints a row `<stage> <status> <detail>`. The stages run
in this order:

| Stage | What it does |
| --- | --- |
| `resolve` | reads the device's entry in the inventory: host and TLS setting |
| `login` | logs in and gets an API key |
| `ha` | checks the HA state and follows the active peer of a passive device |
| `documents` | reads the documents, such as `8 of 8 documents` |
| `template` | merges the template that Panorama pushed into the configuration, such as `120 template elements added, 3 local elements kept`, see [The configuration](#the-configuration) |
| `applications` | reads the App-ID data of the content version, once per version |
| `identity` | reads the User-ID data, such as `9 calls: 4 users, 8 groups, 6 mappings in 1 page, 2 sources`, see [User-ID data](#user-id-data) |
| `store` | writes the snapshot, such as `fw01@2026-09-28T10-00-00Z` |

| Status | Meaning |
| --- | --- |
| `ok` | the stage did its work |
| `partial` | the stage did its work, and part of it failed |
| `skipped` | the stage had nothing to do, such as `HA is not enabled` |
| `failed` | the stage returned an error, and the device stops there |

`fetch` handles failures and special cases as follows:

| Case | Result |
| --- | --- |
| several devices | `fetch` reads up to eight firewalls at the same time |
| a failed login | the device fails, because nothing can be read without a key |
| a failed document | `meta.json` records the failure, and `fetch` keeps the rest of the snapshot |
| the firewall refuses its predefined services | a note; the fetch is still complete, and rules that name them stay in doubt |
| a failed device | the other devices continue, and `fetch` exits 3 |
| a passive member of an HA pair | `fetch` reads the active peer and says so |
| the active peer's reported address is not reachable from your machine | set `ha_peer` on the device in the [inventory](../reference/configuration.md#the-inventory) |

`fetch` also stores the device's App-ID data, the predefined applications and
containers, once per content version. See [App-ID data](snapshot.md#app-id-data).
With `export_inventory: true`, every run also writes the
[inventory export](../reference/configuration.md#the-inventory-export) for
[`mcp`](mcp.md).

### The configuration

`fetch` reads the running configuration with `show config running`. The running
configuration holds no change that an admin did not commit. The configuration
export holds such changes, so `fetch` does not use it while the firewall answers
`show config running`.

A firewall that Panorama manages runs the values of its template too, such as
zones, interfaces and identity sources. The running configuration does not hold
them. `fetch` reads them with `show config pushed-template` and merges them into
the running configuration. A value that the firewall holds itself wins over the
template value, as on the firewall. `config.xml` holds the result, and
`template.xml` holds the template as the firewall sent it.

| Case | Result |
| --- | --- |
| the firewall has a pushed template | `config.xml` holds the running configuration with the template values; `meta.json` holds `"config_source": "running+template"` |
| the firewall answers `No template pushed to device`, as a firewall that Panorama does not manage | `config.xml` holds the running configuration; `config_source` is `running`; no note |
| the firewall refuses the template, or its answer holds no template | `config.xml` holds the running configuration without the template values, with `note.config-no-template` |
| the template call fails on the way | the `documents` stage is `partial`, `config.xml` holds the running configuration, and `fetch` exits 3 |
| the firewall refuses `show config running`, or answers without a configuration | `fetch` exports the configuration, with `note.config-not-running`; the export can hold uncommitted changes; `config_source` is `export` or `export+template` |

The template values can name nodes that the schema digest does not describe, mainly
plugin settings. The load counts them as undescribed. `snapshot diff` against a
snapshot of an older release shows the template values as added once, with
`note.config-source-changed` (see [snapshot diff](snapshot.md#snapshot-diff)).

### User-ID data

After the App-ID data, `fetch` reads the User-ID data of the firewall and stores
it with the snapshot as `identity.json.gz`: the user-to-address mappings, the
users with their groups, alternate names and emails, the groups with their
source, the registered user tags, and the identity sources. It sends nine
`<show>` commands and one more for each further 10,000 mappings. See
[User-ID data](snapshot.md#user-id-data).

| Case | Result |
| --- | --- |
| a firewall with one vsys | `identity.json.gz` in the snapshot, and `"identity": true` in `meta.json` |
| a firewall with several vsys, or system info that does not show the vsys mode | no file, with `note.identity-multi-vsys`; rules that name a user stay in doubt |
| `identity: false` on the device in the [inventory](inventory.md) | no call and no file, with `note.identity-off` |
| the firewall refuses one command, or proteus cannot read one answer | that part of the file is empty, and `parts_missing` in the file and `note.identity-part-missing` name it; the stage is still `ok` |
| the mapping table changes while `fetch` reads its pages | `fetch` keeps the pages, with `note.identity-mappings-moved`, and the file marks the mappings as partial |
| the mapping table holds more than 512,000 entries | the file keeps the first 512,000, with `note.identity-mappings-cut`, and marks the mappings as partial |
| a call fails on the way | the stage is `partial`, the snapshot has no file, and `fetch` exits 3 |

`fetch` never takes the User-ID data of an older snapshot. The run log, the notes
and the errors name parts, counts and line numbers, and never a user, a group, a
mapped address or a tag.

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `device...` | none | fetch these devices by name |
| `--label key=value` | none | fetch the devices with this label; repeatable, and all labels must hold |
| `--all` | off | fetch every device in the inventory |
| `--why` | off | show every stage: what it decided and why |

Use exactly one of the three: device names, `--label` or `--all`.

## Exit codes

`fetch` uses the exit codes differently from the questions. See
[Output and exit codes](../reference/output.md#exit-codes).

## See also

- [snapshot](snapshot.md)
- [inventory](inventory.md)
- [Snapshots and the store](../concepts/snapshots.md)
- [How proteus works](../concepts/index.md)
- [Configuration](../reference/configuration.md)
