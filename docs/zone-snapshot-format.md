# Zone snapshot format

A zone snapshot tells the library which zone an address would arrive on, using the
firewall's own forwarding table instead of an inference from its configuration.

The library reads this format. **It never fetches it.** Capturing belongs to the
caller, and this page is the contract to write a capture tool against.
`scripts/capture-zones.sh` is a working reference implementation.

## The file

One JSON object.

```json
{
  "taken_at": "2026-09-27T17:05:00Z",
  "source": "fw01.example.net",
  "serial": "007900000000002",
  "interfaces_xml": "<response status=\"success\"><result>…</result></response>",
  "fib_xml": "<response status=\"success\"><result>…</result></response>"
}
```

| Field | Required | Meaning |
|---|---|---|
| `interfaces_xml` | **yes** | the output of `show interface all`, verbatim |
| `fib_xml` | **yes** | the output of `show advanced-routing fib`, verbatim |
| `taken_at` | no | RFC 3339. Provenance only, **not enforced** |
| `source` | no | whatever names the device to a human |
| `serial` | no | the device serial, for the same reason |

The two XML documents go in **unmodified**. Do not distil them, reformat them or strip
sections. All parsing lives in the library, so a capture that went wrong stays
distinguishable from a device that answered oddly.

`taken_at` is not enforced, which is a deliberate difference from a user snapshot.
A user-to-group mapping read days ago is a realistic and silent error; a forwarding
table is expected to be supplied fresh by whatever captured it, so the library does not
second-guess its age.

## Capturing the two documents

Over the XML API:

```
type=op&cmd=<show><interface>all</interface></show>
type=op&cmd=<show><advanced-routing><fib><afi>both</afi></fib></advanced-routing></show>
```

From the CLI, with `set cli op-command-xml-output on`:

```
show interface all
show advanced-routing fib
```

Both envelopes load. The API returns `<response status="success"><result>…`, the CLI
prints a bare `<result>`, and the library accepts either.

### Which FIB command

A firewall not in Advanced Routing Mode rejects `show advanced-routing fib`; one in it
rejects the legacy `show routing fib`. Try one and fall back to the other.

The shape is the same either way. Both command paths declare the same handler,
`handler="routing"`, in the appliance's own `opschema.xml`, so both produce the same
document and one parser reads both.

### afi

The `afi` argument takes `ipv4`, `ipv6` or `both`, and is declared by the operational
schema. Pass `both` so a device with IPv6 routes reports them. Omitting it is safe.

## What the library reads

**From `interfaces_xml`, the `ifnet` section only.** The `hw` section describes
physical links — speed, duplex, MAC — and none of that places an address in a zone.

```xml
<ifnet><entry>
  <name>ethernet1/7</name>   <!-- the interface a route leaves by  -->
  <vsys>1</vsys>             <!-- a zone is visible only in its vsys -->
  <zone>int-link-b</zone>    <!-- the answer                       -->
  <fwd>lr:lte</fwd>          <!-- the logical router; "N/A" if unrouted -->
  <ip>198.19.11.1/24</ip>    <!-- "N/A" when the interface has none -->
</entry></ifnet>
```

`fwd` is also read as `vr:<name>` for releases that name a virtual router.

**From `fib_xml`, one table per router per address family.**

```xml
<fibs><entry>
  <vr>lte</vr>               <!-- the router -->
  <type>0</type>             <!-- 0 is IPv4, 1 is IPv6 -->
  <entries><entry>
    <dst>198.19.11.0/24</dst>
    <interface>ethernet1/7</interface>
    <nexthop>0.0.0.0</nexthop>
    <flags>u</flags>
  </entry></entries>
</entry></fibs>
```

Everything else in both documents is ignored, so extra fields in a future release do
no harm.

## How the answer is produced

**address → longest matching route in each router → interface → zone**

Longest prefix wins inside a router, the way a router decides. Across routers there is
no winner to pick: a firewall can have several whose address space overlaps, and which
applies depends on the interface the packet arrived on, which is the thing being worked
out. Every match is returned, each naming its interface, router and route.

On a lab firewall, `198.19.11.5` is covered by the `lte` router's `198.19.11.0/24`,
reaching zone `int-link-b`, and by the `default` router's `0.0.0.0/0`, reaching zone
`transport`. Both are reported and the answer says why neither was chosen.

## What the library refuses

- **A failed command.** `status="error"` is an error, not an empty device.
- **The wrong document in either field.** An interface list in `fib_xml` is reported.
- **A snapshot where no forwarding entry leaves by an interface that is in a zone.**
  Usually this means the two documents came from different devices. An empty table
  would otherwise answer "no zone" for every address and read like a finding.

Individual malformed entries are skipped rather than failing the document: one
unreadable route must not lose the other twenty-four.

## Using it

```go
f, _ := os.Open("zone-snapshot.json")
snap, err := index.LoadZoneSnapshot(f)

placements, report := idx.With(index.Providers{Zones: snap}).
	Candidates(index.FromZone, "198.18.0.5")
```

Or from two HTTP bodies, with no JSON to assemble:

```go
snap, err := index.NewZoneSnapshot(time.Now(), "fw01", interfacesBody, fibBody)
```

With `panos-explore`, point `PANOS_ZONES` at the file.

## Without a snapshot

The library falls back to reading the configuration: interface addresses and static
routes, treated as a small routing table. That answer works offline and it is always
reported as configuration-derived, because it is an inference from what the firewall
was *told*.

The two differ routinely. On the lab firewall the configuration held one static route
and the forwarding table held 25, and they disagreed about the default route — so the
configuration-derived answer was reasoning from a route the device had already
replaced.

**A snapshot is authoritative.** When one is supplied and it places nothing, the
configuration is not consulted instead; falling back would hide exactly that
disagreement.
