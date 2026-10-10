# Simulate NAT: which NAT rule would a packet hit?

`proteus simulate nat <source> <destination> --device <name>` answers three
questions on one firewall:

1. Which NAT rule does the packet hit?
2. What does the packet look like after translation?
3. What must the security policy match: the addresses and port before NAT, and the
   zones after NAT?

## The stages

| Stage | What it does |
| --- | --- |
| `place` | finds where the packet arrives: the interface and zone of the source |
| `pbf` | names a policy-based forwarding rule that could take the packet |
| `lookup` | routes the original destination (the pre-NAT route) |
| `match` | finds the first NAT rule that matches |
| `translate` | applies the rule's source and destination translation |
| `post-lookup` | routes the translated destination (the post-NAT route) |

## A port forward

```
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

The NAT rule matches on the zone of the **pre-NAT** route (`transport`). The
translated destination routes into `server`. The security rule must therefore
allow `transport -> server` for the original addresses and port.

## A source address pool

```
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

The firewall picks a pool address at runtime. proteus shows the pool and the first
candidate address.

## Options

| Flag | Effect |
| --- | --- |
| `--why` | lists every rule above the match and the field that excluded it, then every stage |
| `--from-zone`, `--from-interface` | set where the packet arrives, instead of deriving it |
| `--router` | picks the logical router when the firewall has several |
| `--port`, `--protocol`, `--source-port` | complete the packet |
| `--no-dns` | resolves no FQDN, neither an endpoint nor a translated destination |

A rule that proteus cannot decide is shown as a `doubt` row with the reason. For
example, a rule that names a service cannot be decided when you give no `--port`.

## Limits

- A dynamic-IP-and-port (DIPP) port, a dynamic-IP pool address and the distribution
  of a dynamic destination are chosen at runtime. proteus shows them as candidates.
- NAT64 and NPTv6 are not simulated.
- The active/active binding of a rule is ignored, with a note.
