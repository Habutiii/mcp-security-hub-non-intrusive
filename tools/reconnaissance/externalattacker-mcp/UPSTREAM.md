# Upstream provenance

The unmodified source from `MorDavid/ExternalAttacker-MCP` is vendored in `vendor/` at commit `62df49ef500ec113bd7ee47e98caafb70dc7fae7`.

This directory's `server.py` is the only runtime entrypoint. The upstream generic `/api/run` command runner, self-updater, ffuf, gobuster, nuclei, file targets, arbitrary wordlists, arbitrary methods, and arbitrary output paths are not used or exposed.
