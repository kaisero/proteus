# Scripting: JSON output and exit codes

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The answer is complete. "No results" is a complete answer. |
| 1 | An error stopped the command. |
| 2 | A usage error: a bad flag, a missing argument, or a name with several kinds. |
| 3 | An answer with holes (a device or vsys not read) or unresolved entries. |

A script must treat code 3 as "the answer may be incomplete". The output is still
valid, but it may miss matches.

## JSON output

`--output json` prints one envelope per command. `holes`, `unresolved` and `notes`
are at the top level, so a script cannot miss them.

```
$ proteus search 10.124.0.1 --vsys vsys1 --show objects --output json \
    --file testdata/config/firewall-multivsys.xml
{
  "format": 2,
  "command": "search",
  "input": {
    "direct": false,
    "fields": null,
    "kinds": null,
    "limit": 0,
    "mode": "covers",
    "selection": {
      "file": "testdata/config/firewall-multivsys.xml",
      "vsys": [
        "vsys1"
      ]
    },
    "show": [
      "objects"
    ],
    "term": "10.124.0.1"
  },
  "results": [
    {
      "answer": "file/vsys1: address corp-dc-vienna",
      "device": "file",
      "vsys": "vsys1",
      "stage": "object",
      "kind": "address",
      "name": "corp-dc-vienna",
      "via": "10.124.0.1/32",
      "scope": "vsys:vsys1"
    },
    {
      "answer": "file/vsys1: address corp-location-vienna",
      "device": "file",
      "vsys": "vsys1",
      "stage": "object",
      "kind": "address",
      "name": "corp-location-vienna",
      "via": "10.124.0.0/16",
      "scope": "vsys:vsys1"
    }
  ],
  "summary": {
    "answer": "1 with results, 0 without, 0 holes",
    "found": 2,
    "with": 1,
    "without": 0,
    "omitted": 0
  },
  "holes": [],
  "unresolved": [],
  "notes": []
}
```

`format` is the version of the envelope. It changes only when a field changes its
meaning or is removed.

Each result of `simulate`, `search`, `lookup` and `snapshot diff` has an
`answer`: one line of the text output that says what the result found, such as
`denied at hop 2: fw01 / vsys1, rule block-servers (deny)`. `search`,
`lookup` and `snapshot diff` also print a `summary` with the counts and the
count line as its `answer`. With `--limit N`, `results` holds the first N
results, and `summary.omitted` counts the ones left out; it is 0 when nothing
is left out. For `snapshot diff`, N counts single changes: `results` holds the
scopes up to the one where the limit falls, and `summary.omitted` counts the
changes left out.

A simulate result that is undecided, or whose fidelity is `undermatch`, has a
`needs` list: the inputs that, given in a second question, can change the
answer. Each entry has a `code` (`input.port`, `input.protocol`, `input.url`,
and for `--file` with derived zones `input.from-zone` and `input.to-zone`), the
`input` name and a `text` that names the rules it decides. The list stops at the
first rule in doubt that no input can settle, such as a rule that names only an
application or a user: past that rule, no input changes the verdict. A rule in
doubt for a port and for a user still lists the port, which can rule it out. An
empty list means no input can help. A result that is decided and not
`undermatch` has no `needs` key; a decided result with fidelity `undermatch` can
have one. `simulate nat` asked without a protocol lists `input.protocol` beside
`input.port`; asked with a port but no protocol, it lists `input.protocol` for
each NAT rule whose service holds that port.

The questions also take `--detail summary`. The envelope then says
`"detail": "summary"`, and each result keeps the answer, the verdict, the
fidelity, the reasons and the needs, and of a path each hop's device, vsys,
snapshot, zones, route and policy verdict. It leaves out candidates, stage
tables and each hop's interfaces and lookups. Holes, unresolved entries and
notes stay. The default is `--detail full`; the envelope says
`"detail": "full"`.

Format 2 gives every reason a stable code. A hole, an unresolved entry and a
note are objects with `code` and `text` beside `device` and `vsys`. A list of
reasons, such as `fidelity.reasons`, a doubt's `reasons` or a check's `reasons`,
holds `{"code", "text"}` objects. A script matches the `code`; the `text` is for
people and may change. A reason built from several parts lists each part with
its own code. Text may join consecutive unresolved entries of one composite on
one line; JSON lists them separately.

```
"unresolved": [
  {
    "device": "file",
    "vsys": "vsys1",
    "code": "doubt.not-evaluated.user",
    "text": "dmz-user (deny) at position 7 may match first: user not evaluated (corp\\alice)"
  }
]
```

### Reason codes and schemas

Every code comes from one closed registry, `internal/reason/registry.go`. A code
reads `<class>.<name>`; the class says what kind of reason it is: `doubt`, `gap`,
`path`, `zone`, `default`, `dns`, `input`, `note`, `call` or `verdict`. Each
entry has a one-line description. A code that is not in the registry never
appears in an answer.

The JSON schema of each question's envelope is in `schemas/out/`, one file per
command and detail: `simulate-policy.full.json`, `search.summary.json`, and so
on. `simulate-policy-file.*` is `simulate policy --file`. Every JSON example the
tests hold validates against them.

## A version without a digest

A configuration from a PAN-OS version without a schema digest is read with the
nearest digest. Every answer then carries an unresolved entry and exits with
code 3:

```
$ proteus search 198.18.10.100 --vsys vsys1 --show objects \
    --file testdata/config/firewall-version-12.2.xml
search 198.18.10.100 (covers)

file / vsys1   testdata/config/firewall-version-12.2.xml
  object     address              dc01                     198.18.10.100/32
  object     address              net-labor                198.18.0.0/15
unresolved: file/vsys1: the configuration is PAN-OS 12.2.0 but was read with the 11.2.0 schema, the nearest this build carries; a field added or moved between them yields no reference, so this answer can miss rules

1 with results, 0 without, 0 holes
```

## Example: fail a pipeline on an incomplete answer

```bash
proteus simulate policy 10.20.1.5 10.1.250.10 --port 443 --output json > answer.json
case $? in
  0) echo "complete" ;;
  3) echo "incomplete or undecided: check holes and unresolved"; exit 1 ;;
  *) echo "error"; exit 1 ;;
esac
```

## Shell completion

```bash
proteus completion bash > /etc/bash_completion.d/proteus
proteus completion zsh  > "${fpath[1]}/_proteus"
```
