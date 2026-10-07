# Orchestrator capability contract

The gateway is an execution boundary, not an agent. An orchestrator must first load the relevant skill, establish target scope, and select a capability from `gateway_list_capabilities`. It must never infer permission from a scanner name or a user instruction.

| Capability type | Meaning | Agent use |
| --- | --- | --- |
| `local_read` | Reads supplied local material or generates local data. | No target traffic. |
| `passive_intelligence` | Queries an archive or indexed intelligence provider. | No direct target traffic. |
| `bounded_observation` | Sends a reviewed discovery probe. | Only after scope confirmation; normal audit logs are expected. |
| `human_approved` | May change state or cannot prove it will not. | Never gateway-callable. |
| `forbidden` | Exploitation, target writes, arbitrary execution, or disruptive traffic. | Never agent-callable. |

Every gateway capability has target effect `none` or `audit_logs_only`. This limits exposed primitives; it cannot prove that a remote application has no unsafe GET endpoint. A true target-state guarantee needs a target-owner read-only interface, a staging snapshot, or a target-side policy control.

## Execution contract

1. Confirm immutable target scope before selecting `bounded_observation`.
2. Query `gateway_list_capabilities` and use only its exact `allowed_tools` binding. The gateway independently rejects other tools.
3. Preserve capability ID, scope ID, arguments, timestamp, and source evidence in the orchestrator's evidence store.
4. Treat a child schema mismatch as a policy failure, not an opportunity to call a newly advertised tool.
5. Escalate bodies, headers, cookies, credentials, callbacks, payloads, target writes, high-rate/broad scans, and arbitrary execution to a human-only workflow.

The canonical machine-readable contract is [gateway-mcp/capability_policy.py](./gateway-mcp/capability_policy.py); the gateway returns its public form through `gateway_list_capabilities`.

The gateway does not itself know whether a target is authorized. `scope_required`
is deliberately a label for the orchestrator to enforce before dispatch. Connect
the gateway only behind an orchestrator that rejects out-of-scope targets and
persists its scope decision with the tool call.

## Deliberately not gateway-callable

The repository may contain additional upstream wrappers, but they are not in
the capability registry if their entire advertised surface has not been
locally reviewed. This includes Nikto and all opaque external wrappers. They
remain human-only until a positive capability contract, schema-drift test, and
safe execution limits are added.
