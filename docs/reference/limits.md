# Limits

Each answer names the limits that apply to it, as a note, a doubt or an unresolved
entry. The sections below group the limits by command.

## Versions

- **One schema digest reads every version.** It comes from PAN-OS 11.2. A field
  that a release added or moved, and that the digest does not describe, gives no
  reference. The answer does not say so.
- **Panorama configurations are refused.** Read each firewall's own export
  instead. A managed firewall already carries the rules that Panorama pushed to it.

## What a configuration does not hold

- **Predefined content.** Regions and PAN-DB URL categories live in content that
  the firewall downloads. A rule that names one of them stays in a simulation's
  candidate list, in doubt.
- **Predefined applications come from the device.** `fetch` stores the App-ID data
  of each content version once, in the store. A snapshot without it keeps a rule
  that names an application in doubt. See [Applications](#applications).
- **Predefined services come from the device.** `fetch` stores `service-http` and
  `service-https` with each snapshot, in `predefined.xml`. A snapshot stored
  before, a firewall that refused them, or `--file` without `predefined.xml` next
  to the configuration keeps a rule that names one, or a service group that
  holds one, in doubt.
- **External dynamic lists.** The firewall fetches their contents at runtime.
- **User-to-group mapping.** It comes from User-ID. Give proteus a
  [user snapshot](configuration.md#the-user-snapshot).

## simulate policy

- **No return path.** Only the forward path is checked. Asymmetric routing is not
  detected.
- **Doubtful rules can leave a hop undecided.** Absent services, predefined
  services the snapshot does not hold, user, HIP, schedule, PAN-DB URL categories,
  regions, external dynamic lists and dynamic address groups are not evaluated. A
  rule that names one of them before the match makes the hop undecided, unless it
  has the same action as the match. The application and `application-default` are
  evaluated with `--application` and App-ID data; see
  [Applications](#applications).
- **Default-rule overrides that disagree.** When the local and the pushed override
  of a default rule have different actions, the hop is undecided. The precedence is
  not verified on a Panorama-managed firewall.
- **Routing limits apply to the path.** See [simulate routing](#simulate-routing).
  An ECMP, a PBF rule that can match, or a start that only a default route places
  leaves the hop undecided.
- **Shared gateways are not verified.** A shared gateway's vsys name comes from
  routing; such a path is not verified on a device.
- **Hidden firewalls are only named.** proteus names a firewall in virtual wire or
  Layer 2 mode on the path, and does not check its policy.
- **The answer is static.** It analyzes stored snapshots and never sees live
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

## Applications

`simulate policy --application` matches the flow's application against the
names, groups, filters and containers of each rule, with implicit use and the
default ports of `application-default`. These cases stay in doubt or are not
evaluated:

- **No App-ID data.** A snapshot that names no content version, a content file
  that is missing or cannot be read, or `--file` without `apps.xml.gz` beside the
  configuration gives the note `note.app-data-missing`. The answer is then as
  without `--application`: a rule that names an application stays in doubt.
- **No `--application`.** A rule that names an application other than `any`, or
  uses `application-default`, stays in doubt.
- **A name the data does not hold.** A rule, a group or a filter `exclude` that
  names an application or a container that neither the content data nor the
  configuration holds stays a candidate with `doubt.application-unknown`. It never
  decides. A content update can remove an application, and the content data does
  not hold the internal preview applications.
- **An unknown flow application.** With `--file`, an unknown name or a container
  as `--application` exits 2 with up to five suggestions. In path mode the hop is
  undecided, and the reason names the device and its content version.
- **Policy-based forwarding.** A PBF rule that names an application stays in
  doubt. The firewall matches PBF by application only after the App-ID cache
  knows the application.
- **The App-ID shift.** The firewall identifies an application over the first
  packets of a session and can match the session again when it knows the
  application. proteus evaluates one application per flow, as
  `test security-policy-match` does. Every answer with an application carries
  `note.app-shift`.
- **An open protocol.** Without `--protocol`, the protocol comes from the
  application's default. An application with several default protocols, or with
  no default, leaves the protocol open. A rule that depends on it then stays in
  doubt. In path mode, routing and NAT see the open protocol: a NAT or PBF rule
  that names a service stays in doubt. `--protocol` decides them.
- **An ICMP type.** An application identified by ICMP type matches its protocol.
  The type is not checked, and a note says so.
- **A default rule after an implicit allow.** proteus evaluates the default rules
  after the rules that allow the application through implicit use. The lab
  device's test command does not list default rules, so this order is not
  verified with traffic.
- **One content version on two releases.** The content file is stored once per
  content version and shared by all devices. Two PAN-OS releases with the same
  content version can answer differently. The captures show no such difference.
- **A content file without containers.** When a device returns its applications
  but not its containers, the file records that. A rule that names a container
  then stays in doubt, also on later fetches of that content version. Delete the
  file in `<store>/.content/` to fetch it again.
- **`apps.xml.gz` is not checked.** With `--file`, nothing checks that the file
  beside the configuration has the device's content version. The note
  `note.app-data-file` names the file and its version.

### Measured agreement on fw02

`make app-lab` compares `simulate policy --file` with the device's own
`test security-policy-match`, flow by flow. On fw02 (PAN-OS 12.2.3), 2026-10-17,
all 108 flows agreed: the rule, the action and the implicit marker. See
`docs/lab/app-id-lab.md`.

## Users

### Measured agreement on fw01

`make uid-lab` compares the User-ID answers of proteus with the device's own
answers, case by case. On fw01 (PAN-OS 11.2.5), 2026-10-19, all 56 cases passed:

- 45 policy flows. 41 agreed by rule and action. One of them agreed on its second
  try, because the device applies new User-ID data late. For 4 flows the check
  records the device answer only: 3 flows with no user, which proteus marks
  `inferred`, and 1 rule with a CIE group, which proteus keeps in doubt.
- 3 users: the primary name, the alternate names and the groups agreed.
- 4 addresses: the mapped user and its type, or no mapping, agreed.
- 4 groups: the source and the members agreed.

## simulate nat

- A DIPP port, a dynamic-IP pool address and a dynamic destination's distribution
  are chosen at runtime. proteus shows candidates.
- NAT64 and NPTv6 are not simulated.
- A rule's active/active binding is ignored, with a note.

## simulate routing

- IPv4 only.
- Policy-based forwarding is named, and the path does not follow it.
- ECMP follows the lowest next hop and names the others.
- A path ends where it leaves the inventory, also into a tunnel.
- Firewalls in virtual wire or Layer 2 mode are not seen on a path.

## search

- **A prefix cannot decide a wildcard address object.** A wildcard object, such as
  `10.88.2.1/0.0.255.0`, matches an address by mask, and a simulation or a search
  for one address decides it. One address can also be written as a /32 or as a
  range of one address. A search for a larger prefix or range, or with `--within`
  or `--exact`, lists each wildcard object that can hold one of its addresses as
  unresolved, with `gap.address-wildcard`, and exits with code 3.
- **A device-level reference is matched by name alone.** A static route, an IKE
  gateway or other configuration outside any vsys that names an object is listed
  as a reference with scope `config`. proteus does not decide which vsys's object
  that name refers to: a search in any vsys that finds an object of that name
  lists the reference.

## Host names

- **Only the first IPv4 address is checked.** A source or destination given as a
  host name is resolved with this machine's DNS. proteus checks the first IPv4
  address in the answer; IPv6 is not simulated. `simulate policy`,
  `simulate routing` and `simulate nat` name the other addresses in a note.
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

- **No authorization.** proteus does not decide who can call a tool. The gateway
  in front of it, such as Portkey, owns that.
- **A token holder can forge the identity.** The token proves that a request comes
  through the gateway. proteus does not verify the identity header, and the audit
  records the identity as the gateway claimed it.
- **Data is as fresh as the fetch schedule.** The server reads the store and never
  contacts a firewall. A note says when a snapshot is older than
  `max_snapshot_age`.
- **Some inputs cannot be given.** A rule that names an application the App-ID
  data does not hold can leave a flow undecided, and no input can decide it
  (`needs: []`). So can a predefined service in a snapshot that does not hold it.
  With App-ID data, `needs` asks for `application`.
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

The [model check](../commands/mcp.md#model-check) asks a model 12 questions through the
server and checks its replies against four rules. It has not run yet. Record each
run here: the date, the model and its version, the gateway, the proteus version,
and the result per question.

## URL matching

The URL matching rules come from PAN-OS documentation. A firewall's validator
checks the syntax. It cannot check matching, because `test url` reports PAN-DB
categories only.

## Memory

A parsed configuration uses about ten times the size of the file.
