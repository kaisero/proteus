# simulate nat

Which NAT rule does a packet hit on one firewall, and what does the packet look like after translation?

## Synopsis

```text
proteus simulate nat <source> <destination> --device <name> [flags]
```

The source and the destination are IPv4 addresses or FQDNs. Give `-` as the source to match any source.

## Examples

### A port forward

```text
$ proteus simulate nat 198.19.0.1 198.18.250.10 --device fw01 --port 8443
simulate nat 198.19.0.1 -> 198.18.250.10 tcp/8443 on fw01            fidelity: exact

t-dnat-port: destination 198.18.250.10:8443 -> 198.18.10.100:443

  ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
  │  zones   transport -> server                         │
  │  in      ethernet1/1   198.19.0.254/24               │
  │  out     ethernet1/2   198.18.10.1/24                │
  │  route   0.0.0.0/0 via 198.19.0.1   (pre-NAT)        │
  │  route   198.18.10.0/24  connected   (post-NAT)      │
  │  rule    t-dnat-port, matched transport -> transport │
  │  dest    198.18.250.10:8443 -> 198.18.10.100:443     │
  └──────────────────────────────────────────────────────┘

  before   198.19.0.1 -> 198.18.250.10:8443  tcp
  after    198.19.0.1 -> 198.18.10.100:443  tcp

security policy matches: 198.19.0.1 -> 198.18.250.10, port 8443, zones transport -> server
```

The NAT rule matches on the zone of the pre-NAT route, `transport`. The translated destination routes into `server`. Your security rule must allow `transport -> server` for the original addresses and port.

### A source address pool

```text
$ proteus simulate nat 198.18.11.5 198.18.250.200 --device fw01 --port 443
simulate nat 198.18.11.5 -> 198.18.250.200 tcp/443 on fw01            fidelity: exact

t-dip-pool: source 198.18.11.5 -> 198.18.250.64/29, port unchanged; fallback 198.19.0.254

  ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 2m ───────────────────────────────────┐
  │  zones   client -> transport                                                    │
  │  in      ethernet1/3   198.18.11.1/24                                           │
  │  out     ethernet1/1   198.19.0.254/24                                          │
  │  route   0.0.0.0/0 via 198.19.0.1                                               │
  │  rule    t-dip-pool, matched client -> transport                                │
  │  source  198.18.11.5 -> 198.18.250.64/29, port unchanged; fallback 198.19.0.254 │
  └─────────────────────────────────────────────────────────────────────────────────┘

  before   198.18.11.5 -> 198.18.250.200:443  tcp
  after    198.18.250.64 -> 198.18.250.200:443  tcp

security policy matches: 198.18.11.5 -> 198.18.250.200, port 443, zones client -> transport
```

The firewall picks a pool address at runtime. Proteus shows the whole pool on the `source` row and the first candidate address on the `after` line.

### The rules above the match

Add `--why` to see each rule above the match with the field that excluded it, then every stage. Add `--output json --detail summary` to get the same answer as a compact JSON document.

=== "text"

    ```text
    $ proteus simulate nat 198.18.1.10 198.18.250.10 --device fw01 --router default --from-zone transport --port 8443 --why
    simulate nat 198.18.1.10 -> 198.18.250.10 tcp/8443 on fw01            fidelity: exact

    t-dnat-port: destination 198.18.250.10:8443 -> 198.18.10.100:443

      ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
      │  zones   transport -> server                         │
      │  out     ethernet1/2   198.18.10.1/24                │
      │  route   0.0.0.0/0 via 198.19.0.1   (pre-NAT)        │
      │  route   198.18.10.0/24  connected   (post-NAT)      │
      │  rule    t-dnat-port, matched transport -> transport │
      │  dest    198.18.250.10:8443 -> 198.18.10.100:443     │
      └──────────────────────────────────────────────────────┘

      before   198.18.1.10 -> 198.18.250.10:8443  tcp
      after    198.18.1.10 -> 198.18.10.100:443  tcp

    security policy matches: 198.18.1.10 -> 198.18.250.10, port 8443, zones transport -> server

      not t-no-nat   from zone client ≠ transport
      not t-disabled disabled
      place       exact given: zone transport
      pbf         exact no PBF rule could take the packet
      lookup      exact 198.18.250.10 leaves by ethernet1/1 (zone transport)
      match       exact rule t-dnat-port
      translate   exact destination -> 198.18.10.100
      post-lookup exact 198.18.10.100 leaves by ethernet1/2 (zone server)
    ```

=== "json"

    The same question with `--output json --detail summary`. `--why` changes only
    the text output; `--detail full` adds the stages to the JSON.

    ```json
    {
      "format": 2,
      "command": "simulate nat",
      "detail": "summary",
      "input": {
        "at": "",
        "device": "fw01",
        "flow": {
          "source": {
            "addrs": [
              "198.18.1.10"
            ],
            "resolved": false
          },
          "destination": {
            "addrs": [
              "198.18.250.10"
            ],
            "resolved": false
          },
          "protocol": "tcp",
          "port": 8443
        },
        "from_interface": "",
        "from_zone": "transport",
        "router": "default"
      },
      "results": [
        {
          "answer": "t-dnat-port: destination 198.18.250.10:8443 -\u003e 198.18.10.100:443",
          "rule": "t-dnat-port",
          "fidelity": {
            "level": "exact"
          },
          "doubts": [],
          "destination": {
            "kind": "static",
            "candidates": [
              "198.18.10.100"
            ],
            "address": "198.18.10.100",
            "port": "443"
          },
          "flow": {
            "source": {
              "addrs": [
                "198.18.1.10"
              ],
              "resolved": false
            },
            "destination": {
              "addrs": [
                "198.18.10.100"
              ],
              "resolved": false
            },
            "protocol": "tcp",
            "port": 443
          }
        }
      ],
      "holes": [],
      "unresolved": [],
      "notes": []
    }
    ```

`--from-zone transport` sets the ingress, so the box has no `in` row. `t-no-nat` misses on its from zone, and `t-disabled` is disabled.

## Reading the output

| Line | Meaning |
| --- | --- |
| `simulate nat … fidelity: …` | the packet, the firewall and the [fidelity](../concepts/fidelity.md) of the answer |
| answer line | the rule the packet hits and its translation |
| `before` | the packet as it arrives |
| `after` | the packet after translation; a source port that the firewall picks reads `(runtime)` |
| `security policy matches` | the addresses and port before NAT, and the zones after NAT; absent when the packet drops |
| `may be incomplete` | the fidelity level, then each stage that is not exact, with its detail |

The box shows the firewall, the vsys, the logical router and the age of the snapshot. Each row has a label:

| Row | Meaning |
| --- | --- |
| `zones` | the ingress zone and the egress zone after NAT |
| `in` | the interface and address where the packet arrives |
| `out` | the interface and address where the packet leaves |
| `route` | a route that the lookup uses, marked `(pre-NAT)` or `(post-NAT)` when the rule translates |
| `rule` | the matched rule and the zone pair it matched on; `none: …` with the reason when no rule matches or the packet drops before NAT |
| `source` | the source translation |
| `dest` | the destination translation |
| `doubt` | a rule that Proteus cannot decide, with the reason |
| `note` | a fact that limits the answer, such as an ignored active/active binding |

A rule that names a service is a `doubt` when you give no `--port`. A rule that a bi-directional rule implies carries `(implicit rule of the bi-directional <rule>)`.

With `--why`, a `not` row names each rule above the match and the field that excluded it. The stage table follows:

| Stage | What it does |
| --- | --- |
| `place` | finds where the packet arrives: the interface and zone of the source |
| `pbf` | names a policy-based forwarding rule that could take the packet |
| `lookup` | routes the original destination (the pre-NAT route) |
| `match` | finds the first NAT rule that matches |
| `translate` | applies the rule's source and destination translation |
| `post-lookup` | routes the translated destination (the post-NAT route) |

The `place` stage uses the interface where the source is connected, or where its return route leaves. The egress zone and interface come from the stored forwarding table.

## Flags

`simulate nat` takes `--device`, which is required, and `--at`. See [selection flags](../reference/global-flags.md#selection-flags). It also takes [`--detail`](../reference/output.md#detail).

| Flag | Default | Description |
| --- | --- | --- |
| `--from-zone <zone>` | derived | the zone where the packet arrives; a zone that the vsys does not define exits 2 and lists its zones |
| `--from-interface <name>` | derived | the interface where the packet arrives |
| `--router <name>` | | the logical router, when the firewall has several |
| `--port <port>` | | the destination port: `443` or `tcp/443` |
| `--protocol <name>` | `tcp` | `tcp`, `udp`, `sctp`, `icmp` or a protocol number |
| `--source-port <port>` | | the source port |
| `--no-dns` | off | resolve no FQDN, neither an endpoint nor a translated destination |
| `--why` | off | list every rule above the match and the field that excluded it, then every stage |

## Limits

- A DIPP port, a dynamic-IP pool address and the distribution of a dynamic destination are chosen at runtime. Proteus shows them as candidates.
- Proteus does not simulate NAT64 and NPTv6.
- Proteus ignores the active/active binding of a rule and adds a note.

See [Limits: simulate nat](../reference/limits.md#simulate-nat) and [Limits: host names](../reference/limits.md#host-names).

## See also

- [simulate routing](simulate-routing.md)
- [simulate policy](simulate-policy.md)
- [Fidelity](../concepts/fidelity.md)
- [Output and exit codes](../reference/output.md)
