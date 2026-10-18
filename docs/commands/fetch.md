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
below each device: what the stage decided and why.

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
| `documents` | reads the documents, such as `7 of 7 documents` |
| `applications` | reads the App-ID data of the content version, once per version |
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
- [How Proteus works](../concepts/index.md)
- [Configuration](../reference/configuration.md)
