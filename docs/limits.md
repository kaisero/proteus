# Limits

proteus reports each of these limits in its answers. It does not hide them.

## Versions

- **Only PAN-OS 11.2 digests ship.** A configuration from another version loads
  with the nearest digest. Every answer then carries an unresolved entry that names
  both versions, and the command exits with code 3.
- **Panorama configurations are refused.** Read each firewall's own export
  instead. A managed firewall already carries the rules that Panorama pushed to it.

## What a configuration does not hold

- **Predefined content.** Regions, predefined applications and PAN-DB URL
  categories live in content that the firewall downloads. A rule that names one of
  them stays in a simulation's candidate list, marked `overmatch`.
- **External dynamic lists.** The firewall fetches their contents at runtime.
- **User-to-group mapping.** It comes from User-ID. Give proteus a
  [user snapshot](configuration.md#the-user-snapshot).

## simulate policy

- **Application and user are not evaluated.** The flags are accepted and the
  answer says `not evaluated`.
- **Service `application-default` is not evaluated.** Its ports depend on the
  application. Such a rule stays in the candidate list.
- **Derived zones are inferred.** Measured against a lab firewall's own
  `test security-policy-match`: with zones given, 7 of 7 probe flows agreed; with
  derived zones, 3 of 7. The misses are traffic that arrives through a tunnel zone,
  and destinations that the firewall sends by policy-based forwarding.

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

## URL matching

The URL matching rules come from PAN-OS documentation. A firewall's validator
checks the syntax. It cannot check matching, because `test url` reports PAN-DB
categories only.

## Memory

A parsed configuration uses about ten times the size of the file.
