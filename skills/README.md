# Orchestrator skills

These packages are the intelligence and safe-use layer for an external
orchestrator. Discover their `SKILL.md` files by name and load only the skill
needed for the current stage.

| Skill | Use for | Permitted capability types |
| --- | --- | --- |
| `non-intrusive-security-assessment` | Scope, planning, coverage, and evidence coordination. | All, subject to its escalation rules. |
| `local-security-review` | Source, configuration, API-specification, and artifact review. | `local_read` |
| `asset-discovery` | Scoped host, DNS, TLS, port, and service inventory. | `passive_intelligence`, `bounded_observation` |
| `web-surface-observation` | Historical URL inventory and constrained web discovery. | `passive_intelligence`, `bounded_observation` |

## Required dispatch sequence

1. Load `non-intrusive-security-assessment` and freeze the approved scope.
2. Query the gateway with `gateway_list_capabilities`.
3. Load the matching specialist skill.
4. Permit a call only when the exact `(component_id, tool_name)` is in the
   gateway's `allowed_tools` and the capability type is allowed by the skill.
5. Persist the scope decision, capability ID, tool arguments, timestamp, and
   result/evidence reference.

Do not connect an agent directly to individual child MCPs. That bypasses the
gateway's capability contract and drift detection. See
[`../CAPABILITIES.md`](../CAPABILITIES.md) for the complete policy.
