# Snapshots and the store

`proteus fetch` writes one **snapshot** per device. A snapshot is a directory with
one XML file per document and a `meta.json`.

| Document | Source | Used for |
| --- | --- | --- |
| `config.xml` | configuration export | every question |
| `system-info.xml` | `show system info` | model, serial, PAN-OS version |
| `interfaces.xml` | `show interface all` | zones, interfaces, addresses |
| `fib.xml` | forwarding table | zones of an address, routing paths |
| `rib.xml` | routing table | `simulate routing --rib` |
| `ha.xml` | high-availability state | the active member of a pair |
| `predefined.xml` | the device's predefined services | the ports of `service-http` and `service-https` |

## The store

The **store** is the directory that holds every snapshot:

```text
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

`fetch` writes each snapshot to a hidden directory and then renames it, so a
reader always sees a complete snapshot.

## App-ID data

The predefined applications and application containers of a device are its
**App-ID data**. They depend on the content version, so the store keeps them once
per version in `.content/`, and every snapshot with that version shares the file.
`meta.json` names the version as `app_version`.

`.content/` has mode 0700 and each file in it has mode 0600. See
[snapshot](../guides/snapshots.md#app-id-data) for how to inspect and import the
data.

## Which snapshot a question reads

| Flag | Snapshot |
| --- | --- |
| none | `latest` |
| `--at <time>` | the newest snapshot at or before that time |
| `--fresh` | a new snapshot, fetched first |

## Retention

The store keeps the newest 20 snapshots with a configuration and the newest 20
without one, per device. Set `snapshot_keep` in the
[configuration](../reference/configuration.md) to change the number.
