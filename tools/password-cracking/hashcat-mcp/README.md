# Dictionary-Only Hashcat MCP Server

An MCP server for authorized password recovery using Hashcat's dictionary attack mode only.

## Restrictions

- Exposes only `hashcat_dictionary_crack`.
- Always invokes Hashcat with `--attack-mode 0`.
- Does not accept masks, rules, hybrid modes, restore files, custom commands, or caller-selected wordlists.
- Uses the SecLists `10k-most-common.txt` dictionary only.
- Caps each attempt at five minutes.

## SecLists runtime download

The image contains no wordlists. On container start, it downloads the fixed `10k-most-common.txt` URL from the official SecLists GitHub repository over HTTPS if it is not already present in `/app/wordlists`.

For Compose deployments, mount a named volume at `/app/wordlists` to cache the downloaded dictionary between container starts. Delete that volume to force a fresh download.

## Authorized use

Use only for credentials and systems included in written authorization. The MCP intentionally stops at low-risk dictionary recovery; any broader password-cracking strategy is a human-operated decision outside this server.
