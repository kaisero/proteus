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
| 22 | done | simulate/securitypolicy, index | ~~Evaluate user~~ (User-ID support; items 66 to 91 hold what stays open) |
| 23 | qa | simulate/securitypolicy, index | Derived zones on overlay networks |
| 24 | done | resolve, card, simulate/securitypolicy | ~~Table of predefined services~~ (fetched from the device, no table) |
| 25 | feature | card, cmd | NAT and PBF rules in `lookup` |
| 26 | feature | search, drift, cmd | `--compare` across devices and time |
| 27 | done | mcp, cmd | ~~MCP server~~ (`proteus mcp`, spec `docs/specs/2026-10-09-mcp-server.md`) |
| 28 | research | resolve | Panorama pushed rules on a managed firewall |
| 29 | research | config, internal/digest | Replace the one digest with the newest release's schema |
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
| 58 | test | index | A hidden address's tags and a dynamic group in the vsys |
| 59 | qa | appid | One unknown form in the content data hides all application data |
| 60 | feature | search, store, cmd | Audit missing application dependencies, and export a snapshot with its content file |
| 61 | qa | simulate/securitypolicy | The App-ID shift: a session can match another rule once App-ID knows it |
| 62 | research | fetch, store, appid | One content version on two PAN-OS releases |
| 63 | test | simulate/securitypolicy | A default rule after an implicit allow, with traffic |
| 64 | qa | simulate/pathpolicy, simulate/routing, simulate/nat | The open protocol of routing and NAT in path mode |
| 65 | qa | store, fetch | A content file without containers serves until the trim version changes |
| 66 | perf | fetch, store, estate | Parse every document at fetch time and load snapshot data lazily |
| 67 | feature | fetch, identity, simulate/securitypolicy | Identity data of a multi-vsys firewall and the User-ID hub |
| 68 | test | identity, simulate/securitypolicy | A Cloud Identity Engine lab |
| 69 | test | simulate/securitypolicy | Traffic tests of `unknown` and of `known-user` against `pre-logon` |
| 70 | test | simulate/pathpolicy | A path with NAT and a mapping on the later hop |
| 71 | test | fetch, identity | The user tables of 10,000 users |
| 72 | research | identity, tools/uidlab | How an XML API group goes away |
| 73 | research | identity | Why `email-lookup` and `user-attributes` differ |
| 74 | feature | identity, query, drift | Mapping history and mapping changes in `snapshot diff` |
| 75 | research | identity, simulate/securitypolicy | The cause of the NetBIOS form of a mapping (N6) |
| 76 | test | identity, simulate/securitypolicy | An email that is no alternate name (N7) |
| 77 | test | fetch | The pushed template of a managed firewall without a template (C7) |
| 78 | test | fetch, identity | User-ID answers with data on PAN-OS 12.2 |
| 79 | research | fetch | Uncommitted changes of another admin in `show config running` (C12) |
| 80 | test | fetch | A template that pushes an interface, and a template with variables (C11) |
| 81 | test | identity, simulate/securitypolicy | A nested test group in the lab directory (X3) |
| 82 | research | identity | Two directory groups with one cn |
| 83 | research | identity | A short name with an escaped cn |
| 84 | research | identity | One domain for LDAP and CIE |
| 85 | research | identity | A registered user in two cases |
| 86 | research | identity | One alternate name or email on two users |
| 87 | test | tools/applab | The App-ID lab on PAN-OS 11.2 |
| 88 | research | index, simulate/securitypolicy | A local user group given as `--user` |
| 89 | qa | card | The source of an empty directory group |
| 90 | research | tools/uidlab, tools/applab | A partial commit clears another admin's journal entries on a shared list |
| 91 | research | identity, simulate/securitypolicy | Other User-ID facts the lab rounds could not show |

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
- Policy-based forwarding does not evaluate the user either: a PBF rule that names
  a user keeps its doubt, as one that names an application does (spec
  `docs/specs/2026-10-17-user-id-design.md` §5.3).

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

### 22. Evaluate user

- **Tag:** done · **Component:** simulate/securitypolicy, index · **Source:** spec §11.6, README known limits
- Done as User-ID support (spec `docs/specs/2026-10-17-user-id-design.md`): the
  `match-user` stage evaluates `--user` and the mapping of the source address from
  the User-ID data of each snapshot. Items 66 to 91 hold what stays open.
- The application is done: `match-application` evaluates it from the App-ID data
  (spec `docs/specs/2026-10-16-app-id-design.md`). Items 59 to 65 hold what stays
  open.

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

### 29. Replace the one digest with the newest release's schema

- **Tag:** research · **Component:** config, internal/digest · **Source:** plan `docs/plans/2026-10-15-single-schema.md` task 6
- proteus reads every version with one digest, from 11.2. Replace it with the
  schema of the newest lab release (12.2): `make schema-pull`, then
  `make schema-digest PANOS_VERSION=12.2.0`.
- Before the swap is committed, check it against other versions:
  - every 11.2 fixture gives the same answers with the 12.2 digest, and no
    reference is lost (`make ci`, golden diff);
  - the untyped counts of the fixtures do not grow;
  - `rulebase.pbfDefaults` reads the same defaults from the 12.2 digest.

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

### 55. Undescribed elements of a configuration reach no answer

- **Tag:** qa · **Component:** config, query · **Source:** cleanup plan T31 (R3)
- `config.Load` counts the elements the digest does not describe. The count
  reaches no answer: one digest reads every version, and no version note exists.
  A separate `gap.undescribed` note would show it, but it marks the answer
  unresolved (exit 3). Decide whether that is wanted.

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

### 58. A hidden address's tags and a dynamic group in the vsys

- **Tag:** test · **Component:** index · **Source:** cleanup plan, fix review
- A vsys address group `x` hides a shared address `x` (lab fact L10). The index keys an
  object by its name, so it reads only the group: the shared address's tags no longer
  place its address in a dynamic group of the vsys. Before L10 the index read both,
  and a dynamic group whose filter matched the address's tags took the group `x`
  instead, which was wrong too.
- Check on fw02 whether a vsys dynamic group holds a shared address whose name a vsys
  group hides. If it does, the closure must hold the address by its value, not by its
  name.

## App-ID follow-ups

Source for each: spec `docs/specs/2026-10-16-app-id-design.md`, unless the item
names another.

### 59. One unknown form in the content data hides all application data

- **Tag:** qa · **Component:** appid · **Source:** App-ID lab run on fw02
  (`docs/lab/app-id-lab.md`)
- `appid.Parse` refuses the whole content file when one application holds a form it
  does not know. The first lab run on fw02 met this: `exp` writes
  `ident-by-ip-protocol` as the range `253-254`. Every answer then carried
  `note.app-data-missing`, and rules that name an application stayed in doubt. The
  answer was safe, not wrong, but no application was evaluated.
- `appid` reads the range now. A later content version can bring another new form.
  Keep the application with its unread default instead, so only rules with
  `application-default` for that application stay in doubt, and name it in a note.

### 60. Audit missing application dependencies, and export a snapshot with its content file

- **Tag:** feature · **Component:** search, store, cmd · **Source:** spec §6, §10
- An allowed application can need others: its `use-applications`. A rule that
  allows the application and not what it uses can break the application. This is
  a configuration audit, not a simulation. List the allow rules whose applications
  use an application that no rule allows on the same path.
- `snapshot export` is deferred. `--file` reads `apps.xml.gz` beside the
  configuration, and a user copies it from `<store>/.content/` by hand. An export
  writes the configuration, `predefined.xml` and the content file of the snapshot
  into one directory.

### 61. The App-ID shift: a session can match another rule once App-ID knows it

- **Tag:** qa · **Component:** simulate/securitypolicy · **Source:** spec §4.6, §10
- The firewall identifies an application over the first packets of a session. Before
  that, an earlier application such as `ssl` or `web-browsing` can match another
  rule first. Then the firewall evaluates the session again. proteus evaluates one
  application per flow, as `test security-policy-match` does, and adds
  `note.app-shift` to every answer with an application.
- Decide whether an answer should also name the rule that the earlier application
  matches. Measure it with traffic on a lab device first.

### 62. One content version on two PAN-OS releases

- **Tag:** research · **Component:** fetch, store, appid · **Source:** spec §3.3, O1, F6
- The content file is keyed by the content version and the trim version. The device
  filters its content by release before it answers, so two releases with one content
  version can answer differently. They then share a file that is right for one of
  them only. The two captures show no kept-field difference from the release, and
  the owner accepts the risk.
- Fetch one content version on two releases and compare the trimmed files. If they
  differ, add the release to the key. `meta.json` keeps `sw_version`, so no
  migration is needed.

### 63. A default rule after an implicit allow, with traffic

- **Tag:** test · **Component:** simulate/securitypolicy · **Source:** spec §4.3, I6, O5
- proteus evaluates the default rules after the implicit pass. The test command
  never lists a default rule, so this order is measured only indirectly (I6). With
  only an implicit candidate, the implicit rule is the result.
- Send real traffic on a lab device where an allow rule matches only through
  implicit use and a deny default rule follows. Check which rule the traffic log
  names.

### 64. The open protocol of routing and NAT in path mode

- **Tag:** qa · **Component:** simulate/pathpolicy, simulate/routing, simulate/nat · **Source:** plan
  `docs/plans/2026-10-16-app-id.md` D10, D14, Risks
- With `--application` and no `--protocol`, the security check takes the
  protocol of the application's default. Routing, NAT and PBF see the protocol as
  given: open. A NAT or PBF rule that names a service then stays in doubt
  (`path.nat-no-protocol`), and the hop can be undecided. `--protocol` decides it.
- Give routing and NAT the protocol of the application's default when the default
  has one protocol, on each hop with its own content data.

### 65. A content file without containers serves until the trim version changes

- **Tag:** qa · **Component:** store, fetch · **Source:** spec §2.2, plan
  `docs/plans/2026-10-16-app-id.md` C11, Risks
- When the device returns the applications but not the containers, the content file
  records that the containers are missing. A later fetch of that content version
  finds the file and does not ask again: the store does not look inside the file.
  Every rule that names a container then stays in doubt, until a user deletes the
  file in `<store>/.content/` or the trim version changes.
- Let a hit read the file's header and count a file without containers as a miss,
  or ask the device for the containers only.

## User-ID follow-ups

Source for each: spec `docs/specs/2026-10-17-user-id-design.md`, unless the item
names another. The lab facts come from fw01 (PAN-OS 11.2.5) and, read only, from
fw02 (PAN-OS 12.2.3).

### 66. Parse every document at fetch time and load snapshot data lazily

- **Tag:** perf · **Component:** fetch, store, estate · **Source:** spec §11
- `fetch` parses the User-ID answers into one file at fetch time, and a question
  loads that file only when it needs it. The other documents are stored as the
  device sent them and are parsed at each load.
- Parse every document at fetch time in the same way, and load each part of a
  snapshot only for a question that needs it.

### 67. Identity data of a multi-vsys firewall and the User-ID hub

- **Tag:** feature · **Component:** fetch, identity, simulate/securitypolicy · **Source:** spec D10, §3.4, §11
- `fetch` stores no User-ID data for a firewall with several vsys, and adds
  `note.identity-multi-vsys`. Each vsys can have its own mappings and group
  mapping, and a User-ID hub vsys can share its data with the others.
- Fetch the data per vsys with the `vsys` request parameter (U12), keep one file
  per vsys or one file with a vsys key, and model the hub. Verify on a multi-vsys
  lab firewall first.

### 68. A Cloud Identity Engine lab

- **Tag:** test · **Component:** identity, simulate/securitypolicy · **Source:** spec D1, §5.6, U16
- A rule that names a CIE group stays a candidate with `doubt.user-cie-group`. The
  CIE profiles of fw01 never synced, so no CIE group was seen on a device.
- Set up a working CIE tenant and a rule with a CIE group. Record the group form in
  `user-ids all` and `group list`, and check the documented fact that CIE fetches
  only the users and groups that security rules name. Then evaluate CIE groups as
  directory groups, and make the CIE flow of `make uid-lab` a compared flow.

### 69. Traffic tests of `unknown` and of `known-user` against `pre-logon`

- **Tag:** test · **Component:** simulate/securitypolicy · **Source:** spec §5.4, O1, SG12
- A flow without a user matches `any` and `unknown`, not `known-user`, as the
  admin guide defines them. `test security-policy-match` matches `known-user` here
  (M4) and refuses `unknown` as input (M5). `pre-logon` matches neither keyword.
  These answers are `inferred`.
- Send traffic from an unmapped source against an `unknown` rule, and from a
  `pre-logon` user against a `known-user` rule. Read the traffic log. When it
  confirms the admin guide, the fidelity becomes `exact`.

### 70. A path with NAT and a mapping on the later hop

- **Tag:** test · **Component:** simulate/pathpolicy · **Source:** spec D11, §5.1, O2
- A hop after source NAT looks up the translated address in the mappings of its
  own firewall, with `note.user-after-nat`, and is `inferred`. No lab path with NAT
  and User-ID exists.
- Build a lab path of two firewalls with source NAT on the first, map the
  translated address on the second, and compare the second hop with its
  `test security-policy-match`.

### 71. The user tables of 10,000 users

- **Tag:** test · **Component:** fetch, identity · **Source:** spec §3.3, O3
- `user-ids all` and `user-attributes user all` have no paging. The lab directory
  is small, so their size and whether they cut a large answer are not known. A user
  count that differs from `Total: N` makes `users.groups` missing.
- Read both on a directory of 10,000 users. Record the size, check the count, and
  check the time-out of 60 s per call.

### 72. How an XML API group goes away

- **Tag:** research · **Component:** identity, tools/uidlab · **Source:** spec O4
- A `<groups>` entry with empty `<members>` empties an XML API group, but the
  `xmlapi` list still names it. `xmlapi-group delete` of the op schema was not
  tried. Three empty lab groups stay on fw01 for this reason.
- Try the delete command on a lab group, check the group list, and remove the
  three groups when it works. Then let the lab cleanup use it.

### 73. Why `email-lookup` and `user-attributes` differ

- **Tag:** research · **Component:** identity · **Source:** spec U15, O5
- `email-lookup email all` returned fewer users than `user-attributes user all`
  shows with an email. proteus reads the email from `user-attributes` and does not
  use `email-lookup`.
- Find out which users `email-lookup` leaves out, and why.

### 74. Mapping history and mapping changes in `snapshot diff`

- **Tag:** feature · **Component:** identity, query, drift · **Source:** spec §11, D9
- `snapshot diff` compares users and identity sources, not mappings: a mapping
  changes at each login and time-out. Each snapshot keeps the mappings of its own
  time only.
- Decide what a mapping change worth a report is, such as an address that moved to
  another user, and whether a question can ask for the user of an address at a past
  time.

### 75. The cause of the NetBIOS form of a mapping (N6)

- **Tag:** research · **Component:** identity, simulate/securitypolicy · **Source:** spec N4, N6
- fw01 stores a login sent as `example.com\alice` as `example\alice`. That form
  matches no user rule and no group (M2). It is not known whether the NetBIOS name
  of the domain or the domain of a CIE profile gives the short form. fw01 has CIE
  profiles, and `group-mapping state all` names no NetBIOS domain.
- Check on a firewall without CIE profiles. proteus compares a mapped user as
  stored, so no code depends on the answer.

### 76. An email that is no alternate name (N7)

- **Tag:** test · **Component:** identity, simulate/securitypolicy · **Source:** spec N7, D7, §5.2
- On fw01 each email equals the UPN, which is also an alternate name. So it is not
  known whether the firewall resolves an email. Until then, an email as `--user`
  or as a search term resolves with fidelity `inferred` (`identity.InputEmail`),
  and an email in a rule matches no user (`identity.RuleEmail`).
- On a firewall with a user whose email is no alternate name, check how a `login`
  by email is stored, whether `user-attributes` by email returns the user, and
  whether a rule that names the email matches. Then set both constants.

### 77. The pushed template of a managed firewall without a template (C7)

- **Tag:** test · **Component:** fetch · **Source:** spec C7, §2.1
- fw02 has no Panorama, and `show config pushed-template` answers
  `No template pushed to device`. proteus reads that as no template, with no note.
  A firewall that Panorama manages without a template was not seen.
- Read the answer on such a firewall. When it differs, add its form to the
  no-template case, or let it give `note.config-no-template`.

### 78. User-ID answers with data on PAN-OS 12.2

- **Tag:** test · **Component:** fetch, identity · **Source:** spec C7, X1
- fw02 (12.2.3) holds no User-ID data. Its empty answers have the layouts of fw01,
  but the layouts with data on 12.2 were not seen.
- Read every User-ID answer with data on a 12.2 firewall and compare the layouts
  with the fixtures.

### 79. Uncommitted changes of another admin in `show config running` (C12)

- **Tag:** research · **Component:** fetch · **Source:** spec C12, X4, D2
- On fw01, `show config running` held no uncommitted change of the lab admin or
  of another admin, and the export held both. Two cases are not shown: a firewall
  where the owner cannot make the change of another admin, and PAN-OS 12.2, where
  the export can also be the candidate.
- Check both. A difference changes the fallback note, not the source.

### 80. A template that pushes an interface, and a template with variables (C11)

- **Tag:** test · **Component:** fetch · **Source:** spec C11, §2.2
- The fw01 template holds one zone without interfaces and no interface, and no
  template variable. The merge copies each value as the answer holds it.
- Push a template with an interface and one with a variable to a lab firewall.
  Check that the merged configuration agrees with `show config effective-running`
  and `show interface all`, and how the answer writes a variable.

### 81. A nested test group in the lab directory (X3)

- **Tag:** test · **Component:** identity, simulate/securitypolicy · **Source:** spec X3
- `user-ids all` lists a user under each group that holds it, nested groups too,
  and the firewall agrees. The lab directory showed this only with the Active
  Directory default, where the builtin Users group holds Domain Users.
- Add a nested test group to the lab directory and repeat the X3 check.

### 82. Two directory groups with one cn

- **Tag:** research · **Component:** identity · **Source:** plan
  `docs/plans/2026-10-18-user-id.md` Task 5
- The short name `example.com\<cn>` names a directory group by its cn (M12). Two
  groups with one cn in one domain give a short name of two groups. proteus keeps
  a rule that names such a short name in doubt.
- Check which group the firewall takes, or whether it refuses the name.

### 83. A short name with an escaped cn

- **Tag:** research · **Component:** identity · **Source:** plan
  `docs/plans/2026-10-18-user-id.md` Task 5
- A cn can hold an escaped character, such as `cn=smith\, john`. proteus compares
  the short name of such a group as stored. No device showed the short name of
  such a group.
- Check how the firewall writes and matches it.

### 84. One domain for LDAP and CIE

- **Tag:** research · **Component:** identity · **Source:** plan
  `docs/plans/2026-10-18-user-id.md` Task 5
- When a domain is the domain of an LDAP profile and of a CIE profile, proteus
  reads a short name that resolves as the LDAP group. While the LDAP domain is not
  known, the name is in doubt.
- Check which source the firewall takes. This needs the CIE lab (item 68).

### 85. A registered user in two cases

- **Tag:** research · **Component:** identity · **Source:** plan
  `docs/plans/2026-10-18-user-id.md` Task 5
- `registered-user all` can hold one user under two cases of its name. proteus
  merges the tags of both. No device showed it.
- Register tags under two cases of one name and read the answer.

### 86. One alternate name or email on two users

- **Tag:** research · **Component:** identity · **Source:** plan
  `docs/plans/2026-10-18-user-id.md` Task 5
- When two users share an alternate name or an email, proteus reads the name as
  the first of them in the file. A primary name comes before an alternate name,
  and an alternate name before an email.
- Check what the firewall does with such a name in a rule and in a `login`.

### 87. The App-ID lab on PAN-OS 11.2

- **Tag:** test · **Component:** tools/applab · **Source:** plan
  `docs/plans/2026-10-18-user-id.md` Task 3
- fw01 (11.2.5) refuses an application container in the `exclude` list of an
  application filter. fw02 (12.2.3) takes it. So `lab-filter-excont`, and
  `lab-rule-s13`, which names it, are missing in an App-ID lab run on fw01. The 3
  P13 flows stay undecided on fw01, because a production rule with `any` zones and
  `application-default` stands behind the lab rules.
- Add an 11.2 variant of the filter to the lab files, and isolate the P13 flows
  from production rules.

### 88. A local user group given as `--user`

- **Tag:** research · **Component:** index, simulate/securitypolicy · **Source:** plan
  `docs/plans/2026-10-18-user-id.md` Task 13
- A directory group, a dynamic user group or a short name given as `--user` is no
  user and matches no rule by its text (M12). A local user group given as `--user`
  still matches a rule that names it, by its text. No device fact shows what the
  firewall does, and no lab flow covers it.
- Check the case on a lab firewall with a local user group, and add a lab flow.

### 89. The source of an empty directory group

- **Tag:** qa · **Component:** card · **Source:** plan
  `docs/plans/2026-10-18-user-id.md` Task 14
- For a directory group without members, `show user group name` names no source.
  `lookup` names the source `ldap:<profile>`, such as `ldap:example.com`, by the
  form of the group's DN. The lab check compares no source for such a group.
- Decide whether the card should say that the device names no source.

### 90. A partial commit clears another admin's journal entries on a shared list

- **Tag:** research · **Component:** tools/uidlab, tools/applab · **Source:** plan
  `docs/plans/2026-10-18-user-id.md` Task 14
- On fw01, a partial commit of the lab admin that covered a list, such as `tag`,
  cleared the journal entries of another admin on that list. That admin's entries
  held no content difference, so the net change was nil.
- The lab rules forbid a change to other admins' pending changes. Keep lab changes
  off lists that other admins have changed, or check the journal before each
  commit, and find out whether a content change of another admin can be committed
  this way.

### 91. Other User-ID facts the lab rounds could not show

- **Tag:** research · **Component:** identity, simulate/securitypolicy · **Source:** spec M14, U17
- The precedence and the parentheses of a DUG tag filter were not tested (M14).
  proteus takes DUG membership from the firewall's own user list (D13), so no
  answer depends on it today.
- The capacity of the mapping tables comes from the official docs only (U17). The
  fetch keeps at most 512,000 mappings, the start-point limit of the command.
- Check both on a lab firewall when a change depends on them.

### 92. The default mode of the device probe compares stale text

- **Tag:** bug · **Component:** scripts · **Source:** plan
  `docs/plans/2026-10-18-user-id.md` Tasks 3 and 16
- The default mode of `scripts/device-probe.sh` says in its header and its summary
  that proteus ignores zones and applications. On fw01, 2 of 7 flows agree in that
  mode, in Task 3 and in Task 16, with each binary.
- Update the text and the comparison of the default mode to the current
  `simulate policy`, or remove the mode.
