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
      "device": "file",
      "vsys": "vsys1",
      "stage": "object",
      "kind": "address",
      "name": "corp-dc-vienna",
      "via": "10.124.0.1/32",
      "scope": "vsys:vsys1"
    },
    {
      "device": "file",
      "vsys": "vsys1",
      "stage": "object",
      "kind": "address",
      "name": "corp-location-vienna",
      "via": "10.124.0.0/16",
      "scope": "vsys:vsys1"
    }
  ],
  "holes": [],
  "unresolved": [],
  "notes": []
}
```

`format` is the version of the envelope. It changes only when a field changes its
meaning or is removed.

Format 2 gives every reason a stable code. A hole, an unresolved entry and a
note are objects with `code` and `text` beside `device` and `vsys`. A list of
reasons, such as `fidelity.reasons`, a doubt's `reasons` or a check's `reasons`,
holds `{"code", "text"}` objects. A script matches the `code`; the `text` is for
people and may change. A reason built from several parts lists each part with
its own code.

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
