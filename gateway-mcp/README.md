# Security Hub Gateway MCP

One stdio MCP endpoint in the single security-hub AGW image. It starts a local,
registered MCP process only when a tool is first used or when the agent
explicitly calls `gateway_prewarm`. `gateway_shutdown` releases an idle process;
the gateway refuses to interrupt active work and closes all children on exit.

## Build and run

```powershell
docker compose build
docker run -i --rm security-hub-agw:latest
```

`docker compose build` builds the gateway and all reviewed runtime binaries.
The gateway does not need a Docker socket and does not accept executable paths,
commands, or environment variables from an agent. Do not expose it to a network.

Target-facing tools fail closed unless `AGW_ALLOWED_TARGETS` is configured by
the deployment. It accepts a comma-separated allowlist of registrable domains
and/or IP networks, for example `example.com,10.10.0.0/16`. Subdomains of an
allowed domain and IP subnets contained by an allowed network are permitted.

```powershell
docker run -i --rm -e AGW_ALLOWED_TARGETS=example.com,10.10.0.0/16 security-hub-agw:latest
```

For a direct `docker run`, use the same immutable runtime controls as Compose:

```bash
docker run -i --rm --read-only \
  --tmpfs /tmp:rw,size=128m --tmpfs /var/lib/security-hub:rw,size=512m \
  --cap-drop=ALL --security-opt=no-new-privileges \
  -e AGW_ALLOWED_TARGETS=example.com security-hub-agw:latest
```

The image's source code, bundled tools, wordlists, and grammar files are
root-owned and non-writable. Tool processes run as `mcpuser` and can write only
to the runtime tmpfs directory; container changes cannot alter a built image
layer in any case.

`*`, `0.0.0.0/0`, and `::/0` are rejected: scope must be explicit. The gateway
also writes structured allow/reject scope events to its standard-error log.

## Warm-process and resource policy

The image stays warm while individual MCP processes start lazily. By default,
`AGW_IDLE_TIMEOUT_SECONDS=0`, so started MCP processes remain available for the
whole AGW session. `AGW_MAX_WARM_PROCESSES` defaults to `10`, allowing every
reviewed tool process to stay warm at once. Set a positive idle timeout or lower
the limit only when a deployment needs to conserve memory. At a configured
limit, the least-recently-used idle process is released; if every warm process
is active, a new start is rejected. Each child receives
code-owned address-space, CPU-time, and output-file limits before its server
starts. Agents cannot alter those values.

The Compose file drops every Linux capability by default. There is no broad
capability mode; deployments that require raw Nmap scans must explicitly add
only `NET_RAW` after setting a bounded scope and
`AGW_RAW_NETWORK_ENABLED=true`. See [the Python adapter architecture](../ADAPTER-ARCHITECTURE.md).

## Future screening stage

An optional screening agent is documented in [FUTURE-TASKS.md](../FUTURE-TASKS.md).
It will remain advisory; immutable scope and capability enforcement stay in the
deterministic AGW dispatcher.

## MCP client configuration

```json
{
  "mcpServers": {
    "security-hub": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "security-hub-agw:latest"
      ]
    }
  }
}
```

Use `gateway_list_component_tools` to retrieve the local child tool schema, then
call it through `gateway_call`. Lifecycle inputs are fixed registry IDs; commands
and executable paths are never accepted from the agent.

Call `gateway_list_capabilities` before selecting a component. It provides the code-owned capability type, expected target effect, scope requirement, and exact allowed child tools. Startup fails closed if a child advertises a tool set different from its reviewed capability contract.
