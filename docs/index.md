# proteus

Ask your PAN-OS firewalls questions. proteus answers from a stored copy of each
firewall's configuration and operational state.

```text
$ proteus search 10.124.0.1 --file testdata/config/firewall-multivsys.xml
search 10.124.0.1 (covers)

file / vsys1   testdata/config/firewall-multivsys.xml
  object    address       corp-dc-vienna       10.124.0.1/32
  object    address       corp-location-vienna 10.124.0.0/16
  group     address-group corp-dc              holds corp-dc-vienna
  group     address-group corp-location        holds corp-location-vienna
  reference security rule Corp DC Access       destination -> corp-dc
  reference security rule Corp DC Access       source -> corp-location
1 with results, 2 without, 0 holes
```

<div class="grid cards" markdown>

-   **[Get started](get-started/index.md)**

    ---

    Use when you install proteus, ask your first question, or connect your
    firewalls.

-   **[Commands](commands/index.md)**

    ---

    Use when you need the examples, the output and the flags of one command.

-   **[Reference](reference/index.md)**

    ---

    Use when you need a setting, a path, the JSON envelope or an exit code.

-   **[Concepts](concepts/index.md)**

    ---

    Use when you want to know how proteus reaches an answer and how certain it is.

</div>
