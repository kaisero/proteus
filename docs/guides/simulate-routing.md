# Simulate routing: which firewalls does a packet cross?

`proteus simulate routing <source> <destination>` follows a packet through the
firewalls in your inventory. It starts at the firewall where the source is
connected. It then follows each firewall's stored forwarding table to the next
firewall, until the packet is delivered or leaves the inventory.

This command needs fetched snapshots. It does not work with `--file`, because a
path can cross several firewalls.

## A path across two firewalls

The lab below has two firewalls, fw01 and fw02, joined by 198.19.0.0/24:

```
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

Each box starts with the zone pair. That is the pair a security rule on that
firewall must allow.

## A path that leaves the inventory

```
$ proteus simulate routing 198.18.10.5 8.8.8.8
simulate routing 198.18.10.5 -> 8.8.8.8            fidelity: undermatch
...
  192.168.0.1   leaves the estate (not in the inventory)

firewalls on the path: fw01 (server -> transport), fw02 (labor -> wan)
may be incomplete: the path leaves the estate at 192.168.0.1
```

`may be incomplete` names what proteus cannot see. Here it is the network behind
192.168.0.1, which no firewall in the inventory owns.

## What the answer names

| Case | What proteus does |
| --- | --- |
| ECMP | follows the lowest next hop and names the others (`ecmp`) |
| policy-based forwarding | names a PBF rule that could take the packet (`pbf`) and still follows the forwarding table |
| NAT | applies NAT on every firewall; later firewalls see the translated packet |
| a source connected to two firewalls | stops and asks you to pick one with `--device` |

## Options

| Flag | Effect |
| --- | --- |
| `--device fw01` | starts on this firewall; needed when you give a destination only |
| `--router` | picks the logical router of `--device` |
| `--rib` | lists the other routes to the destination at each firewall and marks the active one |
| `--port` | decides NAT and PBF rules that name a service |
| `--why` | shows every stage with its fidelity |

`--output json` gives each hop's flow: device, vsys, zones, source and destination.
That is the input `simulate policy` takes.

## Limits

- IPv4 only.
- A firewall in virtual wire or Layer 2 mode is not seen on a path. The answer
  names it.
