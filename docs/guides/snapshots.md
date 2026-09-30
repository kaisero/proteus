# Snapshots: fetch, list, show and compare

## Fetch

```bash
proteus fetch fw01 fw02          # these devices
proteus fetch --label site=vienna
proteus fetch --all              # every device in the inventory
```

`fetch` logs in with the inventory's username and password and asks the firewall
for an API key. It then reads the documents listed in
[Concepts](../concepts.md#snapshots-and-the-store) and stores them as one snapshot.

- It fetches up to eight firewalls at the same time.
- A failed document is recorded in `meta.json`. The rest of the snapshot is kept.
- A failed firewall does not stop the others. `fetch` then exits with code 3.
- When a device is the passive member of an HA pair, `fetch` reads the active peer
  instead and says so. Set `ha_peer` in the inventory when the peer's reported
  address is not reachable from your machine.

`fetch` is read-only. It runs `<show>` commands and a configuration export,
nothing else. The client refuses any other command before it reaches the device.

## List

```
$ proteus snapshot list fw01
* 2026-09-29T06-29-08Z  PAN-OS 11.2.5   4 documents, 0 failed
```

The list is newest first. `*` marks `latest`.

## Show

`snapshot show` shows what a question would read: the device, the snapshot and its
age, the PAN-OS version, the vsys and their rule counts, and each document.

```
$ proteus snapshot show --file testdata/config/firewall-multivsys.xml
file   testdata/config/firewall-multivsys.xml
  vsys1    PAN-OS 11.2.5, security rules: 1
  vsys2    PAN-OS 11.2.5, security rules: 0
  vsys3    PAN-OS 11.2.5, security rules: 0
```

## Compare

`snapshot diff` compares two snapshots of each selected device, per vsys and
shared. It compares objects and rules in the schema's terms, not as XML text.

```
$ proteus snapshot diff
fw01   2026-09-22T08-00-00Z -> 2026-09-28T08-00-00Z
  shared     no changes
  vsys:vsys1
    changed  address              net-home                 198.18.1.0/24 -> 198.18.2.0/24
    removed  address              net-labor                198.18.0.0/15
    changed  security rule        dc-to-home               allow application=ssl destination=net-home source=g-servers -> allow disabled application=ssl destination=net-home source=g-servers
    added    security rule        new-rule                 allow application=dns destination=any source=net-home
  vsys:vsys2 no changes
```

By default it compares the snapshot before `latest` with `latest`. `--from` and
`--to` take a snapshot id, an RFC 3339 time or a date. A rule that only moved is
not a change.

## Old snapshots

Every question takes `--at <time>`. It reads each device's newest snapshot at or
before that time. A date means the end of that day.

An answer from a snapshot older than `max_snapshot_age` (default 24h) carries a
note. Change the limit with `--max-age 7d`.
