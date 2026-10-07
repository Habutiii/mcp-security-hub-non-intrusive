# Bundled SecLists manifest

The AGW image intentionally bundles a small, pinned subset of
[SecLists](https://github.com/danielmiessler/SecLists), rather than the full
repository. This keeps the image practical to distribute while ensuring tools
never download mutable wordlists at runtime.

The source revision is the `SECLISTS_REV` build argument in `Dockerfile`.
Only these files are copied into the immutable image:

- `Passwords/Common-Credentials/10k-most-common.txt` — Hashcat's only allowed dictionary.
- `Discovery/Web-Content/common.txt` — FFUF `common` and `dirb-common`.
- `Discovery/Web-Content/directory-list-2.3-medium.txt` — FFUF `dirbuster-medium`.
- `Discovery/Web-Content/raft-large-directories.txt` — FFUF `raft-large-dirs`.
- `Discovery/Web-Content/raft-large-files.txt` — FFUF `raft-large-files`.
- `Discovery/DNS/subdomains-top1million-5000.txt` — FFUF `subdomains-top1mil`.
- `Discovery/Web-Content/burp-parameter-names.txt` — FFUF `params-top`.

The adapter exposes aliases only for this manifest. Adding a wordlist requires
an explicit Dockerfile change, an adapter allowlist update when applicable, and
a security review of its request volume and target effect.
