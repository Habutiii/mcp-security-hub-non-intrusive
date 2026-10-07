---
name: web-surface-observation
description: Map an approved web surface using only reviewed bounded-observation tools. Use when an orchestrator needs technology fingerprints, historical URLs, or GET-only content and parameter discovery while forbidding modified requests, bodies, cookies, credentials, exploit payloads, and target writes.
---

# Web Surface Observation

1. Require a confirmed host/path scope and check `gateway_list_capabilities`.
2. Use `whatweb_scan` for fingerprinting and `fetch_wayback_urls` for archive inventory before live discovery.
3. Use only the FFUF bindings in the capability contract. They are discovery operations, not a generic HTTP client: do not use a custom method, body, header, cookie, authorization token, callback, redirect bypass, or supplied wordlist.
4. Treat every discovered path as an observation. Do not replay it, submit a form, invoke an action endpoint, or infer safety merely because an endpoint accepts GET.
5. Record request bounds and source evidence. Report exposed surface, version signals, and configuration observations with confidence and remediation.

Escalate to human-only validation for authentication flows, IDOR, injection, file upload, account actions, business logic, or any request mutation.
