# App-ID lab check

This check compares proteus with a lab device, flow by flow (spec 2026-10-16 §9.1).
For each flow, the tool `internal/tools/applab` sends `test security-policy-match`
to the device and runs `proteus simulate policy --file` on a fresh snapshot of the
same device. It compares the matched rule, the action and the implicit marker.

The lab device is fw02 while the lab VM is down. fw02 is a production-like
firewall. Every run on fw02 follows the rules in "Run on fw02" below (spec §9.3).
This file names the device fw02 only: no host, address or serial.

The check is not in CI. `make app-lab` runs it by hand.

## Files

| File | Content |
|---|---|
| `app-id-lab-set.tsv` | The lab configuration: one XML API `set` per line, `xpath<TAB>element`, in apply order. |
| `app-id-lab-delete.tsv` | One XML API `delete` per line, `xpath`: the entries of the set file in reverse order, so the rules go first and the zones last. |
| `app-id-flows.tsv` | The flows: case, fact, from, to, source, destination, protocol, port, application, expected. |
| `app-id-lab.vars` | The real values of the placeholders. Local only: `.gitignore` names it, and a test fails when git tracks it. |

The tracked files hold placeholders only. `${SRC_1}` to `${SRC_40}` are the
sources, `${DST_1}` is the destination, and `${APP_NEW}` is an application with
`new-appid yes` in the device's content. A test fails when a tracked lab file holds
an address outside the RFC 5737 and RFC 2544 ranges, or a serial.

The variables file holds `KEY=value` lines. Example, with RFC 2544 addresses:

```text
SRC_1=198.18.0.1
SRC_2=198.18.0.2
DST_1=198.19.0.1
APP_NEW=<an application with new-appid yes>
```

Give each source a unique address in a private test range that no fw02 rule
names. The tool stops when a placeholder has no value.

## Lab design

### Isolation

- The zones `lab-zone-in` and `lab-zone-out` are new, layer3, without interfaces.
- Every rule names `lab-zone-in` in `from`, `lab-zone-out` in `to`, and one
  source placeholder. The destination is `any`.
- Each case group has its own source. A flow of a group reaches only the lab rules
  of its group. Two groups share a source with two rules each: I2 and I4, where the
  order of the two rules is the test.
- Every entry of the set file is new, and its name starts with `lab-`.
  `TestLabConfigIsIsolated` checks this, and that the delete file removes every
  entry.

The set file adds these entries, in this order:

| Kind | Names |
|---|---|
| zone | `lab-zone-in`, `lab-zone-out` |
| tag | `lab-tag-sanctioned` |
| application | `lab-app-erp` (tcp/7002), `lab-app-tagged` (tcp/7001), `lab-app-nodef` (no `default`), `lab-app-proto` (`ident-by-ip-protocol 99`), `lab-app-Case` (tcp/7004, mixed case) |
| application-tag | `lab-app-tagged`: tag `lab-tag-sanctioned` |
| application-filter | `lab-filter-or`, `lab-filter-risk`, `lab-filter-none`, `lab-filter-tag-and`, `lab-filter-webapp`, `lab-filter-tag`, `lab-filter-exclude`, `lab-filter-custom`, `lab-filter-saas-risk`, `lab-filter-saas-risk2`, `lab-filter-saas-cert`, `lab-filter-saas-cert2`, `lab-filter-new`, `lab-filter-s8`, `lab-filter-tunnel`, `lab-filter-pervasive`, `lab-filter-excont`, `lab-filter-notag` |
| application-group | `lab-group-inner` (ssh, `lab-filter-s8`), `lab-group-outer` (`lab-group-inner`, ping) |
| service | `lab-svc-tcp2222`, `lab-svc-udp5000`, `lab-svc-tcp22` |
| service-group | `lab-svcgrp-ssh` (`lab-svc-tcp2222`, `lab-svc-udp5000`), `lab-svcgrp-tcp22` (`lab-svc-tcp22`) |
| security rule | `lab-rule-s1`, `lab-rule-s2`, `lab-rule-s2-none`, `lab-rule-s3`, `lab-rule-s3-web`, `lab-rule-s12`, `lab-rule-s4`, `lab-rule-s5`, `lab-rule-s6-risk`, `lab-rule-s11-risk`, `lab-rule-s6-cert`, `lab-rule-s11-cert`, `lab-rule-s7`, `lab-rule-s8`, `lab-rule-s9`, `lab-rule-s10-tunnel`, `lab-rule-s10-pervasive`, `lab-rule-s13`, `lab-rule-s14`, `lab-rule-i1`, `lab-rule-i2-implicit`, `lab-rule-i2-explicit`, `lab-rule-i3`, `lab-rule-i4-implicit`, `lab-rule-i4-deny`, `lab-rule-i5`, `lab-rule-i8`, `lab-rule-p1`, `lab-rule-p3`, `lab-rule-p4`, `lab-rule-p5`, `lab-rule-p6`, `lab-rule-p7`, `lab-rule-p8`, `lab-rule-p8-grp`, `lab-rule-p11`, `lab-rule-p12`, `lab-rule-p13-any`, `lab-rule-p13-grp`, `lab-rule-p13-ospf`, `lab-rule-p14`, `lab-rule-p15` |

### Coverage

`TestFlowListCoversTheFacts` checks that the flow list has a case for each fact
S1–S15, I1–I8 and P1–P15. It also checks a flow for a custom service, a service
group, a custom application with and without `default`, a protocol without ports,
and a refusal. The `fact` column lists the facts of a case. I6 marks each case
where the device lists no rule: proteus must then answer with a default rule.

### Expected doubt and refusals

- `refused`: P10. The device refuses a container name (`giphy`) and an unknown name
  (`lab-no-such-app`) as the flow's application. proteus must refuse them with
  exit 2.
- `doubt`: `NOAPP-doubt`. A flow without an application meets a rule with a named
  application. proteus stays in doubt (spec §4.1). The device answer does not count.
- A flow marked `doubt` on which proteus decides fails too, so the marks stay true.

### Protocols without ports

The device command needs `destination-port` in 1–65535, also for a protocol
without ports (P9). So the device gets port 1 for such a flow. proteus gets the
protocol number and no port. Such a protocol matches no custom service and no
service group (P13), and an application default decides it by the protocol alone
(§4.4), so a port has no meaning there. The flow list writes `-` as the port.

A flow without an application leaves the `application` element out of the device
command, and proteus gets no `--application`.

### S12 on fw02

S12 has two parts. An `application-tag` entry adds configured tags to an
application, and an empty entry removes no predefined tag.

- The lab gives the configured tag `lab-tag-sanctioned` to the custom application
  `lab-app-tagged`, through the `application-tag` entry `lab-app-tagged`. The
  schema of a custom application has no `tag` list of its own, so the
  `application-tag` entry is the only way. Its name is the application's name, so
  it starts with `lab-`.
- `lab-filter-tag` (tag `lab-tag-sanctioned`) must select `lab-app-tagged` (S12,
  S5). `lab-filter-tag-and` (tags `lab-tag-sanctioned` and `[Web App]`) must select
  nothing for it, because a custom application has no predefined tag (S3).
- The part for a predefined application is not run on fw02: an `application-tag`
  entry for a predefined application has that application's name, which does not
  start with `lab-`. The empty-entry part is not run for the same reason. The lab VM
  measured both parts (spec §1.2).

## Verify on the device before the run

The names below are public PAN-OS names. Content changes them. Before Task 12
applies the set file, check each name against the content of fw02, for example
with `proteus lookup <name>` on a fresh snapshot. Replace a name that is gone with
one that has the same property, in the set file and the flow list.

- Applications: `airdroid`, `apple-siri`, `ask.fm`, `direct-connect`, `etelos-crm`
  (obsolete), `facebook-base`, `giphy-base`, `gre`, `isatap`, `ldap`,
  `moxa-router-telnet`, `moxa-router-web`, `mssql-mon`, `nvgre`, `okta`,
  `onelogin`, `ospf`, `ping`, `ping6`, `pingone`, `spotify`, `ssh`, `ssl`,
  `telnet`, `traceroute`, `unknown-tcp`, `velpic`, `web-browsing`.
- The container `giphy`. The name `lab-no-such-app` must be unknown.
- `${APP_NEW}`: pick an application with `new-appid yes` from the content.
- The properties each case needs: airdroid implies ssl on tcp/80, 443 and 8090
  (I7); apple-siri implies ssl and web-browsing, and ask.fm implies ssl only, with
  port 9977 (I8); web-browsing has `tcp/443/secure` and ldap
  `tcp/636,3269/secure` (P2); direct-connect has `tcp/dynamic` (P3); spotify has
  `tcp/any` or `tcp/80,dynamic` (P11); traceroute has `icmp/dynamic` and
  `icmp6/dynamic` (P11); isatap, nvgre and unknown-tcp have no `default` (P6);
  telnet and mssql-mon carry `ident-by-dport` (P12); etelos-crm is obsolete, in
  business-systems, erp-crm, risk 1 (S15, P15); ssl and ssh are in
  networking, encrypted-tunnel (S4, S10, S14); the predefined tag `[Web App]` exists (S3).
- The filter values: the subcategories `encrypted-tunnel`, `it-management`,
  `internet-utility`, `auth-service`, `photo-video` and `erp-crm`; the SaaS fields
  `is-data-breaches`, `is-poor-terms-of-service`, `is-hipaa`, `is-soc1` and
  `is-soc2`.
- The answer shape of `test security-policy-match` through the XML API:
  `result/rules/entry` with `@name` and `action`, and the marker `(implicit)` in
  the entry. `ParseDevice` also reads the older form `name; index: N`. It reads a
  refusal by the text "Unrecognized application".
- That the device takes the command without `application` (the P13 cases and
  `NOAPP-doubt`).
- That PAN-OS takes an `application-tag` entry for a custom application.

A wrong guess makes a case weaker, not wrong: the tool compares the device with
proteus, and the flow list names no expected rule.

## Run the tool

```sh
make app-lab DEVICE=fw02 APPLAB_KEY_HEADER=/path/outside/the/repo/fw02.key
```

Run it from the repository root. The tool:

1. reads `docs/lab/app-id-flows.tsv` and `docs/lab/app-id-lab.vars`, and stops
   when a placeholder has no value;
2. reads the API key header file. The file holds one line, `X-PAN-KEY: <key>`. The
   tool sends the key in that header only. It never prints, logs or copies it, and
   never asks the device for a key;
3. reads the host, `insecure_tls` and the time-out of the device from the proteus
   inventory (`$PROTEUS_CONFIG` or proteus's default path; `-config` names another);
4. builds proteus from `./cmd/proteus` into a temporary directory;
5. runs `proteus fetch <device>` with `PROTEUS_STORE` set to a second temporary
   directory. proteus fetch logs in with the inventory's credentials, as always;
6. copies `config.xml`, `predefined.xml` and the content file, as `apps.xml.gz`,
   into the first temporary directory;
7. per flow, sends the device command and runs `proteus simulate policy --file
   <copy>/config.xml --vsys vsys1 --from-zone … --to-zone … --protocol … --output
   json`, with `--port` and `--application` where the flow gives them;
8. prints one line per flow: the case, the facts, the device answer, the proteus
   answer, and `ok` or `DIFF` with the reason;
9. removes both temporary directories, also after a failure or an interrupt.

The tool sends only `<show>` and `<test><security-policy-match>` op commands
(AGENTS.md R2). A 403 from the device stops the run: renew the key header file.

Options:

| Flag | Variable | Default |
|---|---|---|
| `-device` | `DEVICE` | none: required |
| `-key-header` | `APPLAB_KEY_HEADER` | none: required |
| `-out` | `APPLAB_OUT` | a new temporary directory; a directory in the repository is refused |
| `-proteus` | `APPLAB_PROTEUS` | built from `./cmd/proteus` |
| `-config` | `PROTEUS_CONFIG` | proteus's default inventory |
| `-flows` | | `docs/lab/app-id-flows.tsv` |
| `-vars` | | `docs/lab/app-id-lab.vars` |
| `-vsys` | | `vsys1` |
| `-render <file>` | | print a lab file with its placeholders filled, and stop |

The output directory keeps each answer, `<case>.device.xml` and
`<case>.proteus.json`, and the proteus run logs. These hold lab data: keep them
out of the repository.

## Run on fw02

Use the API key of the user `claude`. Send every call as a POST to the device's
`/api/` with the key header file, for example `curl -H @"$APPLAB_KEY_HEADER"`.
Follow every step in order. A step that fails stops the run: ask the owner.

1. **Before.** Send `type=op`, `cmd=<check><pending-changes></pending-changes></check>`.
   The answer must be `no`.
2. **Variables.** Fill `docs/lab/app-id-lab.vars`. `git status` must not list it.
3. **Apply.** Fill the placeholders, into a file outside the repository:
   `go run ./internal/tools/applab -render docs/lab/app-id-lab-set.tsv > <file>`.
   For each line of that file that is not a comment, send `type=config`,
   `action=set`, `xpath=<xpath>`, `element=<element>`.
4. **Order.** Move each lab rule to the top, the last rule of the set file first:
   `type=config`, `action=move`,
   `xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='<rule>']`,
   `where=top`. The rules then stand at the top in file order.
5. **Commit.** Send `type=commit`,
   `cmd=<commit><partial><admin><member>claude</member></admin></partial></commit>`.
   Wait for the job with `<show><jobs><id>N</id></jobs></show>`. Never a full
   commit. Never `load config`.
6. **Run.** `make app-lab DEVICE=fw02 APPLAB_KEY_HEADER=<file>`. Every case must
   agree. A difference stops the run: record it under "Results" and ask the owner.
7. **Remove.** For each line of `app-id-lab-delete.tsv`, send `type=config`,
   `action=delete`, `xpath=<line>`. Then send the partial commit of step 5 again.
8. **After.** `pending-changes` must answer `no`. Each line of the delete file must
   answer no entry with `action=get`: no `lab-` object stays.
9. **Revert.** If an uncommitted change stays, send `type=op`,
   `cmd=<revert><config><partial><admin><member>claude</member></admin></partial></config></revert>`.
   Then check step 8 again.
10. **Clean up.** Check that the tool removed its temporary store and copy. Remove
    the rendered set file.

Risks on fw02:

- A production rule with `from any` or `to any` and source `any` can match a lab
  flow after the lab rules. proteus reads the same configuration, so both sides
  see it. A rule with a user, a HIP profile or a URL category can leave proteus in
  doubt there.
- A Panorama pre-rule comes before the lab rules. proteus reads it from the same
  snapshot.
- fw02 runs one vsys, `vsys1`. The device command names no vsys.

## Results

Task 12 records the run here: the date, the PAN-OS version and the content version
of fw02, the result of each case, and every difference with its cause. Generic
values only.
