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

## URL matching

The URL matching rules come from PAN-OS documentation. A firewall's validator
checks the syntax. It cannot check matching, because `test url` reports PAN-DB
categories only.

## Memory

A parsed configuration uses about ten times the size of the file.
