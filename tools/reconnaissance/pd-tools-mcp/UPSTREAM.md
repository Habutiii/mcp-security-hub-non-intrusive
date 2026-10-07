# Upstream provenance

The unmodified upstream source from `intelligent-ears/pd-tools-mcp` is vendored in `vendor/` at commit `0698fb966114435233bf20e85483694d6ef0e450`.

The runtime entrypoint is this directory's `server.py`, not `vendor/src/index.ts`. The upstream `nuclei` tool, free-form template selection, screenshots, redirect following, and the automated bug-bounty workflow are deliberately not exposed. Only bounded, non-mutating discovery operations are available.
