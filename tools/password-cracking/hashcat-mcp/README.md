# Dictionary-Only Hashcat MCP Server

An MCP server for authorized password recovery using Hashcat's dictionary attack mode only.

## Restrictions

- Exposes only `hashcat_dictionary_crack`.
- Always invokes Hashcat with `--attack-mode 0`.
- Does not accept masks, rules, hybrid modes, restore files, custom commands, or caller-selected wordlists.
- Uses the SecLists `10k-most-common.txt` dictionary only.
- Caps each attempt at five minutes.

## Bundled SecLists dictionary

The image build pins and bundles SecLists `10k-most-common.txt` at
`/app/wordlists/10k-most-common.txt`. The adapter never downloads a wordlist at
runtime and never accepts an alternate path from an agent.

## Authorized use

Use only for credentials and systems included in written authorization. The MCP intentionally stops at low-risk dictionary recovery; any broader password-cracking strategy is a human-operated decision outside this server.
