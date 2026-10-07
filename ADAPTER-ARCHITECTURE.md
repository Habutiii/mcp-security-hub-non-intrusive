# Python adapter architecture

The security hub uses one AGW image. It does not run Docker inside Docker or
community MCP servers at runtime. Every agent-callable component is an
AGW-owned Python adapter that exposes a reviewed MCP schema and invokes only a
fixed native binary/API argument vector.

```text
agent -> gateway scope/capability policy -> Python adapter -> native binary/API
```

## Adapter requirements

Each adapter must define a positive tool allowlist, typed inputs, target-field
scope mapping, fixed executable(s), bounded concurrency/time/output, a
dedicated runtime directory, and structured results. It must never receive an
arbitrary command, plugin, template, HTTP method/body/header, path, or
credential from an agent.

`adapters/runtime.py` is the shared fixed-command runner. It only executes an
argument vector constructed by adapter code and bounds child lifetime/output.

## Privileges

Most adapters use the `standard` profile and run as `mcpuser` with all Linux
capabilities dropped. Nmap and Masscan are marked `raw_network`; the gateway
refuses to start them unless `AGW_RAW_NETWORK_ENABLED=true`. An authorized
deployment must additionally add only `NET_RAW` to the container. This is an
explicit deployment-level exception, not a broad privilege mode.

Docker cannot assign a capability to just one child process in the same
container. Deployments requiring strict raw-scan isolation should use a tiny
separate helper boundary for those two adapters; all other adapters stay in the
single image.

## Migration

Existing local Python MCPs are migrated incrementally to this adapter contract.
Community MCP projects are reference-only: their semantics may inform a new
adapter, but their server process is not included in the AGW image.

The AGW image tracks the current supported Python 3.14 release line. Adapters
must remain compatible with current CPython rather than retaining an older
runtime solely for an upstream tool; incompatible tools are rewritten behind
the adapter boundary.
