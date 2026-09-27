#!/usr/bin/env python3
"""Refresh the GENERATED:api blocks in .agents/context/*.md from the real package API.

A block looks like this, and names the package it documents:

    <!-- GENERATED:api ./index -->
    ...replaced...
    <!-- /GENERATED:api -->

Run with --check to fail instead of writing, which is what CI does. An agent doc
that has drifted from the code is worse than no doc: it reads as current.
"""

import pathlib
import re
import subprocess
import sys

BLOCK = re.compile(
    r"(<!-- GENERATED:api (?P<pkg>[^\s>]+) -->\n)(?P<body>.*?)(<!-- /GENERATED:api -->)",
    re.S,
)


def go_doc(*args: str) -> str:
    return subprocess.run(
        ["go", "doc", *args], capture_output=True, text=True, check=True,
    ).stdout


def api_of(pkg: str) -> str:
    # Types come from the compact listing, which renders a struct as "type T struct{ ... }".
    # The -all listing prints the whole body, and taking its first line leaves an
    # unclosed brace. Functions and methods come from -all, which is the only form
    # that includes methods.
    types = sorted(l.rstrip() for l in go_doc("-short", pkg).splitlines()
                   if l.startswith("type "))
    funcs = sorted(l.rstrip() for l in go_doc("-all", "-short", pkg).splitlines()
                   if l.startswith("func "))
    body = ["```go"]
    body += types
    if types and funcs:
        body.append("")
    body += funcs
    body.append("```")
    return "\n".join(body) + "\n"


def main() -> int:
    check = "--check" in sys.argv
    root = pathlib.Path(__file__).resolve().parent.parent
    stale = []
    for md in sorted((root / ".agents" / "context").glob("*.md")):
        text = md.read_text()

        def repl(m: re.Match) -> str:
            return m.group(1) + api_of(m.group("pkg")) + m.group(4)

        new = BLOCK.sub(repl, text)
        if new == text:
            continue
        if check:
            stale.append(md.relative_to(root))
        else:
            md.write_text(new)
            print(f"updated {md.relative_to(root)}")
    if stale:
        for p in stale:
            print(f"{p} is out of date; run make context", file=sys.stderr)
        return 1
    print("agent context API blocks match the code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
