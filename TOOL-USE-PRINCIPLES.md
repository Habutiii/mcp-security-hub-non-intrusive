# Tool Use Principles

## Purpose

This repository is for authorized security assessment where an agent can discover, verify, and describe exposure without changing the analyzed target. Active network and application requests are permitted. Target-side audit logs, rate-limit events, and other normal evidence of scanning are acceptable consequences of that work.

The safety boundary is **target state**, not whether a tool sends traffic.

## Permitted agent activity

An MCP tool may perform bounded, authorized discovery or detection, including:

- Port, service, TLS, DNS, and HTTP fingerprinting.
- Asset discovery, endpoint crawling, content discovery, and non-mutating fuzzing.
- Read-only vulnerability checks that do not create, modify, or delete target data.
- Passive intelligence lookups and local analysis or payload generation.

All active tools must have target scope, concurrency, timeout, rate, and result-size limits appropriate to their protocol.

## Prohibited agent activity

An MCP tool must not provide an agent with a way to:

- Insert, update, delete, truncate, drop, or otherwise alter database content or schema.
- Write, delete, upload, rename, encrypt, or otherwise modify files on the target.
- Create, disable, reset, or change accounts, credentials, permissions, sessions, or configuration.
- Deploy payloads, obtain a shell, execute target-side commands, or establish persistence.
- Send requests intended to cause denial of service, exhaustion, or disruption.
- Invoke a destructive or state-changing action indirectly through an unrestricted script, template, plugin, HTTP method/body, or command argument.

These actions require a person to make an explicit decision and use a separately controlled process.

## MCP interface requirements

Every MCP server in this repository must enforce its own boundary; prompting alone is not a control.

- Use argument-vector process execution, never a shell. Do not accept `extra_args`, command strings, pipes, redirects, or command separators from MCP inputs.
- Validate every input with an allowlist and typed schema. Paths must remain within approved mounted directories.
- Expose fixed, purpose-specific operations. Do not expose arbitrary code execution, arbitrary local scripts, generic command runners, or raw terminal access.
- Allowlist scanner scripts, plugins, and templates. Only reviewed non-mutating checks may be agent-callable.
- Do not expose arbitrary HTTP methods, request bodies, headers, credentials, or callbacks when they could make a state-changing request or exfiltrate data.
- Pin and review upstream dependencies before exposing their tools. An upstream wrapper that can run commands or invoke state-changing capabilities is not suitable without local restriction.
- Run containers as non-root with the minimum capabilities and read-only mounts whenever possible.

## Human approval boundary

The following classes are human-only, even in an authorized engagement:

- SQL injection exploitation or any database-changing request.
- Credential attacks against live services, account lifecycle actions, and password resets.
- Exploitation, payload delivery, remote command execution, persistence, lateral movement, or changes to Active Directory.
- High-rate scanning or broad scans that could affect availability.
- Any action whose target-side effect cannot be proven non-mutating.

## Gateway lifecycle and resource management

When these MCPs are exposed through the security-hub gateway, the gateway is
the only long-lived process. Individual tool MCP containers follow a
least-lifetime policy:

- **Lazy start by default:** start a child MCP container only when the gateway
  receives its first tool call. Starting a container is not permission to scan;
  it must not send target traffic until its specific tool is called.
- **Agent prewarming is allowed:** an agent may ask the gateway to start an
  already-approved MCP in advance when it reasonably expects to use it later.
  Prewarming prepares local resources only and must not invoke a scanner,
  perform a lookup, or contact a target.
- **Reuse while needed:** reuse a started container for related calls in the
  same gateway session so that in-memory results remain available.
- **Graceful idle shutdown:** an agent may ask the gateway to stop an idle MCP
  after it is no longer needed to release CPU and memory. The gateway must not
  stop a container with an active scan, fetch, or local analysis job.
- **Session cleanup:** when the gateway exits, it must gracefully stop and
  remove every child MCP container it started. A bounded timeout may be used
  before forced termination, and `--rm` must remove the stopped container.
- **Fixed registry only:** prewarming and shutdown accept only registered MCP
  identifiers. They must not accept Docker image names, container IDs, shell
  commands, or arbitrary Docker arguments from the agent.

## Review checklist for new tools

Before adding or updating an MCP server, verify:

1. Each tool has a narrow, documented, non-mutating purpose.
2. All executable options, templates, scripts, paths, URLs, and request methods are allowlisted.
3. No input can introduce shell syntax or invoke a generic command runner.
4. Active traffic is rate-limited, scoped, timed out, and concurrency-limited.
5. The implementation and its upstream dependency are reviewed and pinned or vendored.
6. Tests cover input validation and rejection of state-changing or command-execution escape hatches.
7. Gateway-managed containers have tests for lazy start, prewarm without target
   traffic, idle-only shutdown, and complete session cleanup.

If any answer is uncertain, the capability is human-only until it has been redesigned and reviewed.
