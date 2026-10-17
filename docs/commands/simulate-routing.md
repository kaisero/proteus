# simulate routing

Which firewalls in your inventory does a packet cross, and through which zones?

## Synopsis

```text
proteus simulate routing <source> <destination> [flags]
proteus simulate routing <destination> --device <name> [flags]
```

The source and the destination are IPv4 addresses or FQDNs. proteus resolves an FQDN with the DNS of this machine.

## Examples

### A path across two firewalls

The lab has two firewalls, fw01 and fw02, joined by 198.19.0.0/24.

```text
$ proteus simulate routing 198.18.1.10 198.18.10.100
simulate routing 198.18.1.10 -> 198.18.10.100            fidelity: exact

  198.18.1.10
     │ 198.18.1.0/24
  ┌─ fw02 ─ vsys1 ─ router default ─ snapshot 2m ────────┐
  │  zones   home -> labor                               │
  │  in      vlan.1        198.18.1.1/24                 │
  │  out     vlan.32       198.19.0.1/24                 │
  │  route   198.18.0.0/15 via 198.19.0.254   static     │
  └──┬───────────────────────────────────────────────────┘
     │ 198.19.0.0/24   198.19.0.1 -> 198.19.0.254
  ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 2m ────────┐
  │  zones   transport -> server                         │
  │  in      ethernet1/1   198.19.0.254/24               │
  │  out     ethernet1/2   198.18.10.1/24                │
  │  route   198.18.10.0/24  connected                   │
  └──┬───────────────────────────────────────────────────┘
     │ 198.18.10.0/24
  198.18.10.100   delivered

firewalls on the path: fw02 (home -> labor), fw01 (transport -> server)
```

The path starts at fw02, where the source is connected. Each box starts with the zone pair that a security rule on that firewall must allow.

### A path that leaves the inventory

Add `--why` to see every stage of every hop. Add `--output json --detail summary` to get the same answer as a compact JSON document.

=== "text"

    ```text
    $ proteus simulate routing 198.18.10.5 8.8.8.8 --why
    simulate routing 198.18.10.5 -> 8.8.8.8            fidelity: undermatch

      198.18.10.5
         │ 198.18.10.0/24
      ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
      │  zones   server -> transport                         │
      │  in      ethernet1/2   198.18.10.1/24                │
      │  out     ethernet1/1   198.19.0.254/24               │
      │  route   0.0.0.0/0 via 198.19.0.1   static           │
      └──┬───────────────────────────────────────────────────┘
         │ 198.19.0.0/24   198.19.0.254 -> 198.19.0.1
      ┌─ fw02 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
      │  zones   labor -> wan                                │
      │  in      vlan.32       198.19.0.1/24                 │
      │  out     ethernet1/1   192.168.0.138/24              │
      │  route   0.0.0.0/0 via 192.168.0.1   static          │
      └──┬───────────────────────────────────────────────────┘
         │ 192.168.0.0/24
      192.168.0.1   leaves the estate (not in the inventory)

    firewalls on the path: fw01 (server -> transport), fw02 (labor -> wan)
    may be incomplete: the path leaves the estate at 192.168.0.1

      place       exact      connected: 198.18.10.5 on fw01 ethernet1/2
      hop1/pbf    exact      no PBF rule could match
      hop1/lookup exact      8.8.8.8 in router default: 0.0.0.0/0 via 198.19.0.1 on ethernet1/1
      hop1/zones  exact      server -> transport
      hop1/nat    exact      no NAT rule matches
      hop1/next   exact      next: fw02 vlan.32
      hop2/pbf    exact      no PBF rule could match
      hop2/lookup exact      8.8.8.8 in router default: 0.0.0.0/0 via 192.168.0.1 on ethernet1/1
      hop2/zones  exact      labor -> wan
      hop2/nat    exact      no NAT rule matches
      hop2/next   undermatch the path leaves the estate at 192.168.0.1
    ```

=== "json"

    The same question with `--output json --detail summary`. `--why` changes only
    the text output; `--detail full` adds the stages to the JSON.

    ```json
    {
      "format": 2,
      "command": "simulate routing",
      "detail": "summary",
      "input": {
        "at": "",
        "device": "",
        "flow": {
          "source": {
            "addrs": [
              "198.18.10.5"
            ],
            "resolved": false
          },
          "destination": {
            "addrs": [
              "8.8.8.8"
            ],
            "resolved": false
          },
          "protocol": "tcp"
        },
        "rib": false,
        "router": ""
      },
      "results": [
        {
          "answer": "192.168.0.1 leaves the estate (not in the inventory)",
          "needs": [],
          "fidelity": {
            "level": "undermatch",
            "reasons": [
              {
                "code": "path.left-estate",
                "text": "the path leaves the estate at 192.168.0.1"
              }
            ]
          },
          "source": {
            "addrs": [
              "198.18.10.5"
            ],
            "resolved": false
          },
          "destination": {
            "addrs": [
              "8.8.8.8"
            ],
            "resolved": false
          },
          "outcome": "left-estate",
          "end": "192.168.0.1   leaves the estate (not in the inventory)",
          "end_code": "path.left-estate",
          "hops": [
            {
              "device": "fw01",
              "vsys": "vsys1",
              "snapshot": "2026-09-28T10-00-00Z",
              "from_zone": "server",
              "to_zone": "transport",
              "route": "0.0.0.0/0 via 198.19.0.1"
            },
            {
              "device": "fw02",
              "vsys": "vsys1",
              "snapshot": "2026-09-28T10-00-00Z",
              "from_zone": "labor",
              "to_zone": "wan",
              "route": "0.0.0.0/0 via 192.168.0.1"
            }
          ]
        }
      ],
      "holes": [],
      "unresolved": [],
      "notes": []
    }
    ```

`may be incomplete` names what proteus cannot see. Here it is the network behind 192.168.0.1, which no firewall in the inventory owns.

## Reading the output

The path starts where the source is connected, or where the most specific route to the source leaves. With `--device`, the path starts on that firewall. proteus then follows the stored forwarding table of each firewall to the next firewall.

| Line | Meaning |
| --- | --- |
| `simulate routing … fidelity: …` | the packet and the [fidelity](../concepts/fidelity.md) of the answer |
| `│ <prefix>` | the link between two boxes, with the addresses at each end |
| last line of the path | where the path ends, such as `delivered` or `leaves the estate` |
| `firewalls on the path` | each firewall with the zone pair that its security rule must allow |
| `may be on the path, not detected` | a firewall that can be on the path but that proteus cannot see, such as one in virtual wire or Layer 2 mode |
| `may be incomplete` | the reasons the answer can be incomplete, and the stages that proteus did not evaluate |

Each box shows one firewall, its vsys, its logical router and the age of its snapshot. Each row has a label:

| Row | Meaning |
| --- | --- |
| `zones` | the zone the packet enters by and the zone it leaves by |
| `in` | the ingress interface and its address |
| `out` | the egress interface and its address |
| `route` | the route the lookup uses, with its protocol, or `connected` |
| `ecmp` | the other equal-cost next hops that proteus does not follow |
| `pbf` | a policy-based forwarding rule that could take the packet |
| `nat` | a NAT rule that changes the packet, or may change it |
| `alt` | with `--rib`, another route to the destination; the active route is marked `(active)` |
| `schema` | the schema that proteus uses to check PBF and NAT |
| `note` | another fact about the hop |

proteus handles these cases as follows:

| Case | What proteus does |
| --- | --- |
| ECMP | follows the lowest next hop and names the others (`ecmp`) |
| policy-based forwarding | names a PBF rule that could take the packet (`pbf`) and still follows the forwarding table |
| NAT | applies NAT on every firewall; later firewalls see the translated packet |
| a source connected to two firewalls | stops and asks you to pick one with `--device` |

With `--why`, a stage table follows. `hopN/` is the number of the hop.

| Stage | What it does |
| --- | --- |
| `place` | finds the firewall and interface where the path starts |
| `hopN/pbf` | names a policy-based forwarding rule that could take the packet |
| `hopN/lookup` | finds the route to the destination in the logical router |
| `hopN/zones` | finds the ingress and egress zones |
| `hopN/nat` | applies the NAT rule that matches, if any |
| `hopN/next` | finds the next firewall, or where the path ends |

With `--output json`, each hop carries its flow: device, vsys, zones, source and destination. [simulate policy](simulate-policy.md) takes that flow as its input.

## Flags

`simulate routing` takes `--device` and `--at`. See [selection flags](../reference/global-flags.md#selection-flags). With `--at`, proteus reads the newest snapshot of each device at or before that time. It also takes [`--detail`](../reference/output.md#detail).

| Flag | Default | Description |
| --- | --- | --- |
| `--device <name>` | | start the path on this firewall; required when you give a destination only |
| `--router <name>` | | start in this logical router of `--device` |
| `--port <port>` | | the destination port, `443` or `tcp/443`; decides NAT and PBF rules that name a service |
| `--rib` | off | list the other routes to the destination at each firewall and mark the active one |
| `--no-dns` | off | do not resolve an FQDN endpoint |
| `--why` | off | show every stage with its fidelity |

The command needs fetched snapshots. It does not take `--file`, because a path can cross several firewalls.

## Limits

- proteus traces IPv4 only.
- proteus names policy-based forwarding, and the path does not follow it.
- A path ends where it leaves the inventory, also into a tunnel.
- proteus does not see a firewall in virtual wire or Layer 2 mode on a path. The answer names it.

See [Limits: simulate routing](../reference/limits.md#simulate-routing) and [Limits: host names](../reference/limits.md#host-names).

## See also

- [simulate nat](simulate-nat.md)
- [simulate policy](simulate-policy.md)
- [fetch](fetch.md)
- [Snapshots](../concepts/snapshots.md)
- [Fidelity](../concepts/fidelity.md)
