---
name: non-intrusive-security-assessment
description: Plan and coordinate an authorized non-intrusive security assessment using this repository's capability contract. Use when an orchestrator must establish scope, select safe specialist skills and MCP tools, track coverage and evidence, or produce a finding without exploit delivery or target-state changes.
---

# Non-Intrusive Security Assessment

Load `CAPABILITIES.md` before selecting a networked tool. Treat the gateway's `gateway_list_capabilities` result as authoritative.

1. Record immutable scope: approved hosts/repositories, owner, time window, exclusions, maximum traffic, and staging/read-only guarantees if present.
2. Build an asset and evidence inventory from source, API specifications, supplied logs, and passive intelligence before sending target traffic.
3. Select a specialist skill: `$local-security-review` for local artifacts, `$asset-discovery` for network inventory, or `$web-surface-observation` for constrained HTTP discovery.
4. Permit only `local_read` or `passive_intelligence` until scope is confirmed. For `bounded_observation`, record the capability ID and exact tool binding.
5. Maintain coverage as `asset × surface × check × evidence × outcome`. A missing check is not a negative finding.
6. Report observations with evidence and remediation. Do not claim an exploit, read protected data, mutate a request, use credentials, or retry an action after a safety rejection.

Escalate to a human-only process for uncertain target effect, request mutation, credential workflows, payload delivery, broad/high-rate traffic, or any action outside the immutable scope.
