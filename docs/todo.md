# To do

Every item names its **component** (the package or area it changes) and one **tag**:

| Tag | Meaning |
|---|---|
| `feature` | New behaviour for a user. |
| `test` | A check against a real device or a missing test; no behaviour change expected. |
| `qa` | Behaviour that works but is weaker than it should be; a quality gap. |
| `bug` | Behaviour that is wrong today. |
| `research` | A question to answer before any code is written. |
| `perf` | Memory or time. |

"Source" points to where the item was deferred: a spec section, a decision, or a plan.

## Index

| # | Tag | Component | Title |
|---|---|---|---|
| 1 | test | resolve, simulate/routing | Verify a route into another logical router (next-lr) |
| 2 | test | resolve, simulate/routing | Verify a discard route |
| 3 | test | resolve | Verify a secondary and a DHCP address |
| 4 | test | fetch, estate | Verify an HA pair |
| 5 | test | simulate/routing | Verify a path across several vsys |
| 6 | test | resolve, fetch | Verify the legacy (non-Advanced-Routing) RIB shape |
| 7 | feature | simulate/routing | Follow a route into another logical router |
| 8 | feature | simulate/routing | Drop at a discard route |
| 9 | done | simulate/routing | ~~Gap check: security policy on every hop of a path~~ (path mode of `simulate policy`, item 21) |
| 10 | feature | simulate/routing, simulate | Simulate policy-based forwarding |
| 11 | done | simulate/nat, simulate/routing, simulate/securitypolicy | ~~Simulate NAT~~ (branch nat-simulation, spec §18) |
| 12 | feature | inventory, simulate/routing, simulate | Bridge a known hop outside the inventory (`links:`) |
| 13 | feature | simulate/routing | Chain a path through a tunnel |
| 14 | feature | simulate/routing | IPv6 paths |
| 15 | feature | simulate/routing | Failover simulation from the RIB alternates |
| 16 | qa | simulate/routing | Check PBF when the start vsys is unknown |
| 17 | qa | simulate/routing | Hidden firewalls: read zone modes from the configuration |
| 18 | done | simulate/nat | ~~NAT detection: service, nat64 and nptv6~~ (the NAT engine decides them) |
| 19 | feature | fetch, estate, simulate/routing | Active/active HA pairs |
| 20 | feature | inventory, fetch | Skip the RIB for a device with a full BGP table |
| 21 | feature | simulate, estate, cmd | Estate simulation for policy (M5): path mode done, fan-out open |
| 22 | feature | simulate/securitypolicy, index | Evaluate application and user |
| 23 | qa | simulate/securitypolicy, index | Derived zones on overlay networks |
| 24 | done | resolve, card, simulate/securitypolicy | ~~Table of predefined services~~ (fetched from the device, no table) |
| 25 | feature | card, cmd | NAT and PBF rules in `lookup` |
| 26 | feature | search, drift, cmd | `--compare` across devices and time |
| 27 | done | mcp, cmd | ~~MCP server~~ (`proteus mcp`, spec `docs/specs/2026-10-09-mcp-server.md`) |
| 28 | research | resolve | Panorama pushed rules on a managed firewall |
| 29 | research | config, fetch, internal/digest | A digest for PAN-OS 12.2, possibly from the device |
| 30 | research | index | URL matching beyond the documentation |
| 31 | research | schema | Design of the public `schema` package |
| 32 | perf | config | Memory of large configurations |
| 33 | test | simulate/nat | Verify the dataplane with a dynamic destination whose FQDN resolves to nothing |
| 34 | feature | simulate/nat, fetch | Use the device's FQDN cache for dynamic destination NAT |
| 35 | test | simulate/nat | Verify persistent DIPP needs no global setting, and a service object's source port |
| 36 | feature | simulate/pathpolicy, simulate/routing | Return-path asymmetry check |
| 37 | test | simulate/routing, simulate/pathpolicy | Verify a shared-gateway path on a device |
| 38 | test | resolve, simulate/securitypolicy | Verify pushed default rules and their precedence on a managed firewall |
| 39 | test | simulate/pathpolicy | Probe fw01 with the path probe |
| 40 | feature | mcp | Verify a signed identity (`X-User-JWT`) |
| 41 | feature | mcp, inventory | Reload the inventory without a restart |
| 42 | research | mcp | Authorisation specifics |
| 43 | feature | query, simulate | Check every address of a host name |
| 44 | qa | mcp | Generate the `proteus://limits` resource from `docs/limits.md` |
| 45 | qa | mcp | The caller's address behind a trusted proxy |
| 46 | test | mcp | Run the model check through Portkey |
| 47 | done | mcp | ~~Keep the stack of a panic after a timeout~~ (the call's run log keeps the late work) |
| 48 | perf | mcp, query, search, drift | Let the timeout stop a load, a search and a diff |
| 49 | perf | mcp, search | Cache the zone document for `search` |
| 50 | feature | mcp | Ask the user for needs and choices with elicitation |
| 51 | feature | mcp | Publish OAuth resource metadata if Portkey is dropped |
| 52 | bug | simulate/routing, simulate/nat | NAT in the first vsys of an inter-vsys path sees the wrong egress zone |
| 53 | qa | simulate/securitypolicy | A doubted NAT rule's own post-NAT zone is not a derived destination zone |
| 54 | bug | simulate/routing | A hairpin through another firewall is reported as a loop |
| 55 | qa | config, query | Undescribed elements of a configuration read with its own digest reach no answer |
| 56 | qa | config, archtest | The read-only check sees setter names only, not writable exported fields |
| 57 | done | resolve, index, simulate/nat | ~~Verify an address and an address group of one name in two scopes~~ (lab fact L10: as services) |

---

## Device checks

The routing simulation reads these shapes without having seen them on a device, so
its parsers take the cautious result: an unknown route type stops the path as
unresolved, and an HA state that is not a confirmed pair is not followed. Each check
needs configuration that fw01 and fw02 do not have. The tool is read-only
(AGENTS.md R2), so an administrator adds it on the device first.

After each check: run `scripts/device-probe.sh --routing <device> <router>
<destination>...` for the new routes, update spec §17.2 ("Still unverified") and §14
item 7, and delete the fetched data and API keys from the scratch directory.

### 1. Verify a route into another logical router (next-lr)

- **Tag:** test · **Component:** resolve, simulate/routing · **Source:** spec §17.2, §14 item 7, R16
- **On fw01:** in logical router `lte`, add a static route 10.77.0.0/16 with next hop
  "next LR" `default`. Commit.
- **Check:** `panos-analyst fetch fw01`, then read the stored `fib.xml` and `rib.xml`
  for 10.77.0.0/16: its `nh_type`, `interface` and `nexthop` in the FIB, and its
  next-hop fields in the RIB. Save both as fixtures. Then item 7.

### 2. Verify a discard route

- **Tag:** test · **Component:** resolve, simulate/routing · **Source:** spec §17.2, §14 item 7, R7
- **On fw01:** in logical router `default`, add a static route 10.66.0.0/16 with next
  hop "discard". Commit.
- **Check:** fetch, then read the FIB entry for 10.66.0.0/16 (`nh_type`, `interface`,
  `flags`) and its RIB entry. Save as a fixture. Then item 8.

### 3. Verify a secondary and a DHCP address

- **Tag:** test · **Component:** resolve · **Source:** spec §17.2
- **On fw01:** add a second IPv4 address to ethernet1/4 (198.18.19.1/24 today), for
  example 198.18.29.1/24. Commit. A DHCP client interface, where one exists, gives
  the `<dyn-addr>` shape.
- **Check:** fetch, then read that interface's `<addr>` and `<dyn-addr>` in
  `interfaces.xml`. The parser reads `<member>` children; confirm or correct it.
- **Then:** `simulate routing 198.18.10.5 198.18.29.20` must reach ethernet1/4 and be
  delivered. Replace the synthetic test in `resolve/routing_test.go` with a fixture.

### 4. Verify an HA pair

- **Tag:** test · **Component:** fetch, estate · **Source:** spec R18, §17.2
- **Needs:** an active-passive pair.
- **Check:** fetch the passive member; read `ha.xml` for the mode, local and peer
  state, serials and the peer's management address. `resolve.ReadHAState` uses
  element names that are not verified (`group/mode`, `local-info/state`,
  `local-info/serial-num`, `peer-info/state`, `peer-info/serial-num`,
  `peer-info/mgmt-ip`).
- **Then:** `fetch` must say "fetched from the active peer". With both members in
  the inventory, `simulate routing` must treat them as one firewall. Replace the
  synthetic tests in `fetch/active_test.go` and `estate/network_test.go`.

### 5. Verify a path across several vsys

- **Tag:** test · **Component:** simulate/routing · **Source:** spec R16
- **Needs:** a firewall with multi-vsys enabled and external zones.
- **Check:** the vsys numbers in `interfaces.xml`, and a path from vsys1 into vsys2
  through the external zones. Replace the synthetic
  `testdata/config/firewall-intervsys.xml` test with real data. Also check a shared
  gateway.

### 6. Verify the legacy (non-Advanced-Routing) RIB shape

- **Tag:** test · **Component:** resolve, fetch · **Source:** spec §17.2
- **Needs:** a firewall with Advanced Routing off.
- **Check:** `<show><routing><route/></routing></show>`. `resolve.ReadRIBRoutes`
  refuses anything but the Advanced Routing JSON today. Write the second parser from
  a fixture. Also confirm the legacy FIB shape still matches `ReadFIBRoutes`.

## Routing simulation

### 7. Follow a route into another logical router

- **Tag:** feature · **Component:** simulate/routing · **Source:** spec R16; needs item 1
- The lookup stage knows `nh_type` 0 and 3 only. Add the next-lr type: a second
  `route` row in the same box, then the lookup continues in the other router. Loop
  detection keys on device, vsys and router already.

### 8. Drop at a discard route

- **Tag:** feature · **Component:** simulate/routing · **Source:** spec R7; needs item 2
- End the path "dropped on fw01: route 10.66.0.0/16 discards" (Exact) instead of
  stopping it as unresolved.

### 9. Gap check: security policy on every hop of a path

- **Tag:** done · **Component:** simulate/routing · **Source:** spec R14
- Done as path mode of `simulate policy` (item 21): it checks every hop of the path
  with that hop's flow and zones and gives one verdict.

### 10. Simulate policy-based forwarding

- **Tag:** feature · **Component:** simulate/routing, simulate · **Source:** spec §17.6, R10
- Replace the `pbf` detection stage: when a rule matches, follow its egress
  interface or next hop. Covers path monitoring, symmetric return, and that a rule
  naming an application does not apply to a session's first packet. Also closes part
  of item 23.

### 11. Simulate NAT

- **Tag:** feature · **Component:** simulate, simulate/routing, card · **Source:** spec §13, §17.6, R10, K10
- Translate the flow at the `nat` stage and fill `Hop.PostNAT`; later hops then see
  the translated addresses, and the route lookup uses the post-NAT destination.
  Model translated addresses (README known limit). Brings NAT rules to `lookup`
  (item 25) and to the policy simulation's destination zone.

### 12. Bridge a known hop outside the inventory (`links:`)

- **Tag:** feature · **Component:** inventory, simulate/routing, simulate · **Source:** spec §17.6, R6
- An inventory section such as `198.19.0.1 -> fw02 ethernet1/1` lets a path cross a
  router that the tool cannot fetch. Needs its own seam (`Network.Links()`), not
  per-device data.

### 13. Chain a path through a tunnel

- **Tag:** feature · **Component:** simulate/routing · **Source:** spec §17.6
- Match the IKE gateway's peer address to an inventory interface and continue on the
  peer with the inner flow. Today the path ends "leaves by tunnel.1".

### 14. IPv6 paths

- **Tag:** feature · **Component:** simulate/routing · **Source:** spec R9
- The FIB and interface state already carry IPv6 (`afi both`); the topology skips it
  and the command refuses IPv6 addresses. Fetch the RIB with `afi both` too.

### 15. Failover simulation from the RIB alternates

- **Tag:** feature · **Component:** simulate/routing · **Source:** spec R3
- `--rib` lists the alternates as information. Trace the path that the next-best
  route would give when the active one fails.

### 16. Check PBF when the start vsys is unknown

- **Tag:** qa · **Component:** simulate/routing · **Source:** implementation of Task 9
- With `--device` and no source, the hop's vsys is known only after the lookup, so the
  `pbf` stage reports "not evaluated". Take the vsys of the egress interface, or check
  every vsys of the device, so PBF is not skipped.

### 17. Hidden firewalls: read zone modes from the configuration

- **Tag:** qa · **Component:** simulate/routing · **Source:** plan Task 8, R19
- `Path.Hidden` names off-path devices with interfaces that have a zone and no router,
  from interface state. The plan also asked to read virtual-wire and layer2 zone modes
  from the configuration (schema-backed), and to cover devices on the path.

### 18. NAT detection: service, nat64 and nptv6

- **Tag:** qa · **Component:** simulate/routing · **Source:** implementation of Task 9
- A NAT rule's `service` is always taken as "could match", and nat64 and nptv6 rules
  are skipped. Match the service when the flow has a port; flag nat64 and nptv6 once
  IPv6 paths exist (item 14).

### 19. Active/active HA pairs

- **Tag:** feature · **Component:** fetch, estate, simulate/routing · **Source:** spec R18, §17.6
- Today `fetch` notes the mode and fetches the device asked. Model floating addresses
  and the session owner and setup device.

### 20. Skip the RIB for a device with a full BGP table

- **Tag:** feature · **Component:** inventory, fetch · **Source:** spec §17.6, R3
- An internet edge firewall returns megabytes on every fetch. An inventory switch per
  device leaves the `rib` document out.

## Security policy simulation

### 21. Estate simulation for policy (M5)

- **Tag:** feature · **Component:** simulate, estate, cmd · **Source:** spec
  `docs/specs/2026-10-07-estate-policy-simulation.md` §12
- **M5a, path mode: done.** `simulate policy` checks every firewall and vsys on the
  flow's routed path and gives one verdict.
- **M5b, fan-out: open.** `--each` checks each selected firewall on its own:
  `--device`, `--label` and `--vsys` filters, relevance order, hidden rows that are
  not relevant, `--all-devices`, `--fresh`, and the zone flags. `--file` moves to the
  fan-out result shape.

### 22. Evaluate application and user

- **Tag:** feature · **Component:** simulate/securitypolicy, index · **Source:** spec §11.6, README known limits
- The `first-match` stage reports application (and user) as not evaluated.
  `--application` and `--user` are accepted and not used.

### 23. Derived zones on overlay networks

- **Tag:** qa · **Component:** simulate/securitypolicy, index · **Source:** spec §14 item 5
- Zones derived from the forwarding table agreed with fw01 on 3 of 7 probe flows
  (given zones: 7 of 7). The misses are traffic arriving on a tunnel zone and
  destinations sent by PBF. Needs the arrival interface and PBF (item 10).

## Lookup, search and comparison

### 24. Table of predefined services

- **Tag:** done · **Component:** resolve, card, simulate/securitypolicy · **Source:** spec §14 item 6, K6
- Done without a table: `fetch` reads the predefined services from the device into
  each snapshot (`predefined.xml`), and every service reader sees them in scope
  `predefined`, below shared. A snapshot without them keeps the doubt.
  `application-default` still puts a rule in doubt.

### 25. NAT and PBF rules in `lookup`

- **Tag:** feature · **Component:** card, cmd · **Source:** spec K10
- `lookup` shows security rules and the objects they name. NAT rules were deferred
  to NAT simulation (item 11); PBF rules can follow with it.

### 26. `--compare` across devices and time

- **Tag:** feature · **Component:** search, drift, cmd · **Source:** spec §10, C9
- A `Comparison` that groups findings by name across a selector, and `--compare` on
  questions, so a diff shows how answers changed, not only the configuration.

### 27. MCP server

- **Tag:** done · **Component:** mcp, cmd · **Source:** spec S11, §12 "Later"
- Done as `proteus mcp` (spec `docs/specs/2026-10-09-mcp-server.md`). See the
  [MCP guide](guides/mcp.md). Follow-ups are items 40 to 51.

## Core and schema

### 28. Panorama pushed rules on a managed firewall

- **Tag:** research · **Component:** resolve · **Source:** spec §5.3, §14 item 1
- Confirm where a Panorama-managed firewall's running configuration keeps pushed
  pre- and post-rules. Needs one managed firewall's export. Decides how much of
  `resolve/rules.go` survives.

### 29. A digest for PAN-OS 12.2, possibly from the device

- **Tag:** research · **Component:** config, fetch, internal/digest · **Source:** spec §14 item 3, S13
- fw02 (12.2.2) loads with the 11.2 digest and a version-gap warning. Ship a 12.2
  digest, and decide whether `fetch` should pull a device's own `schema.xml` to
  generate one.
- Since E25 (spec `docs/specs/2026-10-07-estate-policy-simulation.md`), the gap
  makes `simulate policy` `inferred` with a note, not undecided. Other commands
  still report it as unresolved.

### 30. URL matching beyond the documentation

- **Tag:** research · **Component:** index · **Source:** spec §14 item 2
- Custom URL category matching follows the documentation. `test url` reports PAN-DB
  categories only, so no device check exists yet. Find one.

### 31. Design of the public `schema` package

- **Tag:** research · **Component:** schema · **Source:** README project structure ("design not settled")
- Decide what the public package that queries the schema itself offers.

### 32. Memory of large configurations

- **Tag:** perf · **Component:** config · **Source:** spec §14 item 4
- The parsed element tree peaks near ten times the file size. An estate of large
  exports makes this a real limit.

## NAT follow-ups

### 33. Verify the dataplane with a dynamic destination whose FQDN resolves to nothing

- **Tag:** test · **Component:** simulate/nat · **Source:** spec §18 F17, D8
- `test nat-policy-match` answers no rule for such a flow on fw01, not the next
  matching rule. Send real traffic to a `t-dnat-fqdn`-like rule and read the traffic
  log: is the session dropped, or does a later rule apply?

### 34. Use the device's FQDN cache for dynamic destination NAT

- **Tag:** feature · **Component:** simulate/nat, fetch · **Source:** spec §18 N2, §18.6
- `<show><dns-proxy><fqdn><all/></fqdn></dns-proxy></show>` lists what the firewall
  resolved. Fetch it as a document and prefer it to this machine's DNS, so the
  translation is the device's own.

### 35. Verify persistent DIPP needs no global setting, and a service object's source port

- **Tag:** test · **Component:** simulate/nat · **Source:** spec §18 F7; plan Task 4
- F7 notes that per-rule persistent DIPP may need the global persistent-DIPP
  setting. The engine also ignores a service object's source port. Check both on a
  device.

## Estate policy follow-ups

Source for each: spec `docs/specs/2026-10-07-estate-policy-simulation.md` §13.

### 36. Return-path asymmetry check

- **Tag:** feature · **Component:** simulate/pathpolicy, simulate/routing · **Source:** spec §11, §13, D11
- Path mode checks the forward path only. Trace the return path too, and say when it
  crosses other firewalls than the forward path.

### 37. Verify a shared-gateway path on a device

- **Tag:** test · **Component:** simulate/routing, simulate/pathpolicy · **Source:** spec §11, §13
- A shared gateway's vsys name comes from routing's `vsysName`. Needs a firewall with
  a shared gateway; compare a path through it with `scripts/device-probe.sh --path`.

### 38. Verify pushed default rules and their precedence on a managed firewall

- **Tag:** test · **Component:** resolve, simulate/securitypolicy · **Source:** spec §4.6, §10.2, §13, E24
- proteus reads pushed default-rule overrides from
  `shared/post-rulebase/default-security-rules`, which the firewall schema does not
  declare. Confirm the path and whether a local override wins over a pushed one.
  Until then a disagreement leaves the hop undecided. Related to item 28.

### 39. Probe fw01 with the path probe

- **Tag:** test · **Component:** simulate/pathpolicy · **Source:** spec §10.2
- The first `--path` run (2026-10-08) probed fw02 only. Run it with fw01's
  credentials, also for a flow that a default rule denies on fw01.

## MCP server follow-ups

Source for each, unless it says otherwise: spec `docs/specs/2026-10-09-mcp-server.md`
§8 and §10.

### 40. Verify a signed identity (`X-User-JWT`)

- **Tag:** feature · **Component:** mcp · **Source:** spec §4.4, §10
- proteus audits the claims of `X-User-Claims` without a check, so a token holder can
  forge them. A gateway can also send the user's identity as a signed JWT. Verify its
  signature against the gateway's keys, and audit only verified claims.

### 41. Reload the inventory without a restart

- **Tag:** feature · **Component:** mcp, inventory · **Source:** spec §8, §10
- The device enum of the tools comes from the export when the server starts. A
  device added by `fetch` needs a server restart. Watch the export, and update the
  tools' input schemas with a `tools/list_changed` notification.

### 42. Authorisation specifics

- **Tag:** research · **Component:** mcp · **Source:** spec §8, §10
- proteus does no authorisation; the gateway decides who can call the server.
  Decide whether proteus should limit tools, devices or labels per identity, and
  which claim carries the decision.

### 43. Check every address of a host name

- **Tag:** feature · **Component:** query, simulate · **Source:** spec §8, §10
- A host name is resolved, and only its first IPv4 address is checked. A name with
  several addresses (DNS round robin, a CDN) can get a different answer for each. Run
  the question for each address, or say when the answers differ.

### 44. Generate the `proteus://limits` resource from `docs/limits.md`

- **Tag:** qa · **Component:** mcp · **Source:** implementation of the MCP server
- The resource is a hand summary in Go and can drift from `docs/limits.md`. Generate
  it, or add a test that checks it against the headings of the document.

### 45. The caller's address behind a trusted proxy

- **Tag:** qa · **Component:** mcp · **Source:** implementation of the MCP server
- Behind the proxy, the audit's `remote` is the proxy's address, so the rate limit
  of refused requests (10 per minute per address) is in effect global. Read
  `X-Forwarded-For` from a proxy named in the settings.

### 46. Run the model check through Portkey

- **Tag:** test · **Component:** mcp · **Source:** spec §7.1; lab acceptance 2026-10-10
- Run the [model check](guides/mcp.md#model-check) through the Portkey SaaS gateway
  with the chatbot's model, and record the result in
  [Limits](limits.md#model-check). This also tests the path through Portkey, which
  needs a public URL.

### 47. Keep the stack of a panic after a timeout

- **Tag:** done · **Component:** mcp · **Source:** implementation of the MCP server
- Done: a call that times out leaves its run log to its work. When the work
  returns, the log gets what the work logged late, the time it returned and the
  stack of a panic, and then closes.

### 48. Let the timeout stop a load, a search and a diff

- **Tag:** perf · **Component:** mcp, query, search, drift · **Source:** spec §4.7, §8
- A configuration load, an index build, `search` and `drift` take no context. A call
  past `call_timeout` answers `call.timeout`, but its work keeps a slot until it
  ends. Pass the context into them.

### 49. Cache the zone document for `search`

- **Tag:** perf · **Component:** mcp, search · **Source:** implementation of the MCP server
- `search` reads each target's zone document from disk on every call. The server
  cache holds configurations and operational data, not zones.

### 50. Ask the user for needs and choices with elicitation

- **Tag:** feature · **Component:** mcp · **Source:** spec `docs/specs/2026-10-10-mcp-followup.md` §1
- A result's `needs` and the error `call.choice` ask the model to ask the user. MCP
  elicitation lets the server ask the user directly. Add it when Portkey and the
  clients support it.

### 51. Publish OAuth resource metadata if Portkey is dropped

- **Tag:** feature · **Component:** mcp · **Source:** spec `docs/specs/2026-10-10-mcp-followup.md` §1
- Portkey owns authentication, so proteus checks a static bearer token. Without the
  gateway, clients expect the MCP authorisation flow: publish OAuth protected
  resource metadata and verify the access tokens.

## Audit follow-ups

Source for each: the code audit of 2026-10-10 and the cleanup plan
(`docs/plans/2026-10-10-cleanup.md`).

### 52. NAT in the first vsys of an inter-vsys path sees the wrong egress zone

- **Tag:** bug · **Component:** simulate/routing, simulate/nat · **Source:** audit finding 12
- Each hop runs zones, then NAT, then next. `next()` puts the external zone in place
  of the egress zone at the vsys boundary, after NAT has run. So a vsys1 NAT rule
  from trust to the external zone `to-vsys2` is not found, and the answer says "no
  NAT rule matches" with fidelity exact.
- The fix moves the external-zone change into `zones()`, before NAT. It follows the
  admin guide only. Do it only after a check on a firewall with multi-vsys and
  external zones (item 5): the lab firewalls have one vsys.

### 53. A doubted NAT rule's own post-NAT zone is not a derived destination zone

- **Tag:** qa · **Component:** simulate/securitypolicy · **Source:** review of plan
  `docs/plans/2026-10-10-cleanup.md` T5
- With derived zones, the security check keeps the pre-NAT destination zone and the
  zone after the NAT rule that applies. A NAT rule in doubt above it may translate
  the destination to a third zone; that zone is not added, so a security rule whose
  to zone is only that zone drops out. The stage says `doubt.nat-rule` (overmatch),
  but the candidate set can be too narrow.
- Only the fan-out kind reaches this: path mode gives the zones, and a NAT doubt
  leaves its hop undecided. Fix: translate each doubted rule too, and add its
  post-NAT zone.

### 54. A hairpin through another firewall is reported as a loop

- **Tag:** bug · **Component:** simulate/routing · **Source:** audit finding 13
- The loop check keys on device, vsys and router. A path fw02 → fw01 → fw02, where
  fw01 translates the destination to a host behind fw02, repeats that key and ends as
  "loop", undecided, although the device delivers the packet.
- The fix adds the current destination to the key; a real loop still repeats it. Do
  it only after a check on fw01 and fw02 together (fw01 did not answer on 2026-10-10
  and 2026-10-11): build the path with a DNAT on fw01 and confirm with the device
  probes that the packet arrives.

### 55. Undescribed elements of a configuration read with its own digest reach no answer

- **Tag:** qa · **Component:** config, query · **Source:** cleanup plan T31 (R3)
- `config.Load` counts the elements the digest does not describe, and the
  `gap.version` note names the count. Without a version gap (a patch release read
  with the digest of its own version) the count reaches no answer. A separate
  `gap.undescribed` note would show it, but it marks the answer unresolved (exit 3).
  Decide whether that is wanted.

### 56. The read-only check sees setter names only, not writable exported fields

- **Tag:** qa · **Component:** config, archtest · **Source:** cleanup plan T31 (R2)
- `TestPublicAPIIsReadOnly` fails on an exported setter name. `config.Element` has
  exported fields that a caller can still write. Make them read through methods, or
  extend the check to exported, writable fields of model types.

### 57. Verify an address and an address group of one name in two scopes

- **Tag:** done · **Component:** resolve, index, simulate/nat · **Source:** cleanup
  plan, lab fact L9
- A service name resolves by scope first and kind second (L9), and the index and NAT
  read services that way. Addresses are still read one kind at a time: the index
  reads `address` and `address-group` each on its own, so a rule naming `x` reaches
  both a vsys address `x` and a shared address group `x`. NAT's translation takes the
  address of that name first, in any scope.
- Check on fw02 which object a rule's `x` means. If the device resolves it as it does
  a service, read both kinds through `resolve.ObjectsOfKindsInScope` in the index and
  in NAT, and test the lab fact.
- Done: on fw02, PAN-OS 12.2.3, an address name resolves as a service name does, by
  scope first and kind second (lab fact L10). The index, NAT and lookup cards read
  addresses and address groups through `resolve.ObjectsOfKindsInScope`.
