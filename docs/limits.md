# Limits

proteus reports each of these limits in its answers. It does not hide them.

## Versions

- **Only PAN-OS 11.2 digests ship.** A configuration from another version loads
  with the nearest digest. Every answer then carries an unresolved entry that names
  both versions, and the command exits with code 3. `simulate policy` is the
  exception: the gap is a note, and it lowers the fidelity to `inferred`.
- **Panorama configurations are refused.** Read each firewall's own export
  instead. A managed firewall already carries the rules that Panorama pushed to it.

## What a configuration does not hold

- **Predefined content.** Regions, predefined applications and PAN-DB URL
  categories live in content that the firewall downloads. A rule that names one of
  them stays in a simulation's candidate list, in doubt.
- **External dynamic lists.** The firewall fetches their contents at runtime.
- **User-to-group mapping.** It comes from User-ID. Give proteus a
  [user snapshot](configuration.md#the-user-snapshot).

## simulate policy

- **No return path.** Only the forward path is checked. Asymmetric routing is not
  detected.
- **Doubtful rules can leave a hop undecided.** Application, `application-default`,
  predefined or absent services, user, HIP, schedule, PAN-DB URL categories,
  regions, external dynamic lists and dynamic address groups are not evaluated. A
  rule that names one of them before the match makes the hop undecided, unless it
  has the same action as the match.
- **Default-rule overrides that disagree.** When the local and the pushed override
  of a default rule have different actions, the hop is undecided. The precedence is
  not verified on a Panorama-managed firewall.
- **Routing limits apply to the path.** See [simulate routing](#simulate-routing).
  An ECMP, a PBF rule that can match, or a start that only a default route places
  leaves the hop undecided.
- **Shared gateways are not verified.** A shared gateway's vsys name comes from
  routing; such a path is not verified on a device.
- **Hidden firewalls are named, not evaluated.** A firewall in virtual wire or
  Layer 2 mode on the path is not checked.
- **The answer is static.** It is an analysis of stored snapshots, not of live
  sessions.
- **`--file` does not check NAT.** It reads one configuration without interfaces or
  a forwarding table. A derived destination zone is the zone before destination
  NAT, and a given zone gets no note when NAT would give another. Path mode applies
  NAT on each hop.
- **Derived zones are inferred.** With `--file` and no zones, the zones come from
  the configuration. Measured against a lab firewall's own
  `test security-policy-match`: with zones given, 7 of 7 probe flows agreed; with
  derived zones, 3 of 7. The misses are traffic that arrives through a tunnel zone,
  and destinations that the firewall sends by policy-based forwarding.

### Measured agreement of path mode

`scripts/device-probe.sh --path <flows-file>` runs path mode per flow and asks each
hop's firewall the same question with `test security-policy-match`. On fw02,
2026-10-08:

- 9 of 9 decided hops agreed. 7 named the same rule. 2 agreed by action: the test
  sends no application, so the firewall stops at a rule that proteus holds in
  doubt. That rule has the same action as proteus's answer.
- 1 hop was undecided: a rule on fw01 with service `application-default`.
- fw01 is not probed yet.

## simulate nat

- A DIPP port, a dynamic-IP pool address and a dynamic destination's distribution
  are chosen at runtime. proteus shows candidates.
- NAT64 and NPTv6 are not simulated.
- A rule's active/active binding is ignored, with a note.

## simulate routing

- IPv4 only.
- Policy-based forwarding is named, not followed.
- ECMP follows the lowest next hop and names the others.
- A path ends where it leaves the inventory, also into a tunnel.
- Firewalls in virtual wire or Layer 2 mode are not seen on a path.

## search

- **A prefix cannot decide a wildcard address object.** A wildcard object, such as
  `10.88.2.1/0.0.255.0`, matches an address by mask, and a simulation or a search
  for one address decides it. A search for a prefix or a range, or with `--within`
  or `--exact`, lists each wildcard object that can hold one of its addresses as
  unresolved, with `gap.address-wildcard`, and exits with code 3.

## Host names

- **Only the first IPv4 address is checked.** A source or destination given as a
  host name is resolved with this machine's DNS. proteus checks the first IPv4
  address in the answer; IPv6 is not simulated. `simulate routing` and
  `simulate nat` name the other addresses in a note.
- **The canonical name is this machine's view.** A note gives the name's
  canonical name as this machine's resolver reports it. Resolvers differ: one
  reports the first name of a CNAME chain, another the last.
- **A rule matched only through an FQDN object is in doubt.** The firewall
  resolves an FQDN address object itself, and its addresses can differ from the
  ones this machine gets. Such a rule stays a candidate with the doubt
  `doubt.fqdn-resolution`, also when the name resolves to nothing. A rule that
  also matches the address by an address object or `any` is not in doubt.

## The MCP server

`proteus mcp` answers with the limits above. These limits are its own:

- **No authorisation.** proteus does not decide who can call a tool. The gateway
  in front of it, such as Portkey, owns that.
- **A token holder can forge the identity.** The token proves that a request comes
  through the gateway. proteus does not verify the identity header, and the audit
  records the identity as the gateway claimed it.
- **Data is as fresh as the fetch schedule.** The server reads the store and never
  contacts a firewall. A note says when a snapshot is older than
  `max_snapshot_age`.
- **Application and predefined services stay undecidable.** A rule that names an
  application, `application-default` or a predefined service can leave a flow
  undecided, and no input can decide it (`needs: []`).
- **Configuration text reaches the model unchanged.** Rule names, descriptions
  and object names go into the answer as the configuration holds them.
- **An inventory change needs a restart.** The device enum of the tools comes from
  the export when the server starts.
- **A host name: only its first IPv4 address is checked.** See
  [Host names](#host-names).
- **The timeout cannot interrupt a load or an index build.** A call past
  `call_timeout` gets `call.timeout` at once. Its work keeps the call's slot until
  it returns, and a load it started still fills the cache.

### Lab acceptance

On 2026-10-10 a scripted MCP client called the server on a copy of the lab store,
over stdio and over Streamable HTTP. fw02 (PAN-OS 12.2.3) was fetched fresh. fw01
was unreachable, so its snapshot was 33 hours old, and its answers carried the
stale-snapshot note.

- 10 tool calls over six tools (five policy flows, routing, NAT, search, lookup and
  a snapshot diff), with `detail: full`: the structured envelope equalled
  `proteus … --output json --detail full` in 10 of 10 calls over stdio and 10 of 10
  over HTTP, apart from `elapsed_ms`.
- The answers matched the policy path probe: fw02 to fw01 on tcp/443 allowed; the
  reverse on tcp/22 undecided at fw01 (service `application-default`); a
  destination outside the estate undecided; udp/443 denied by a rule.
- A device name outside the enum was refused and audited as `usage`.
- HTTP: no token and a wrong token gave 401, a wrong Host 403, `/healthz` 200, a
  2 MB body 413. The audit file had mode 0600, and the token was in no audit line
  and no log. SIGTERM exited 143.
- Not tested: the path through the Portkey SaaS gateway, which needs a public URL.

### Model check

The [model check](guides/mcp.md#model-check) asks a model 12 questions through the
server and checks its replies against four rules. It has not run yet. Record each
run here: the date, the model and its version, the gateway, the proteus version,
and the result per question.

## URL matching

The URL matching rules come from PAN-OS documentation. A firewall's validator
checks the syntax. It cannot check matching, because `test url` reports PAN-DB
categories only.

## Memory

A parsed configuration uses about ten times the size of the file.
