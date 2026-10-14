# ZAP MCP

This local adapter starts a pinned ZAP daemon on the container loopback address. It exposes only a bounded GET observation, passive alert retrieval, and form login to a deployment-owned profile. ZAP's generic request, spider, active scan, and script APIs are not exposed to the agent. WhatWeb remains available as a separate lightweight fingerprinting tool.

## Tools

| Tool | Action |
| --- | --- |
| `zap_observe` | GET one authorized URL without following redirects; optionally reuse a profile-bound cookie session. |
| `zap_login` | Submit the configured username and agent-supplied password to one configured login path; return an opaque session ID. |
| `zap_passive_alerts` | Read at most 50 alerts already recorded for an authorized origin. |

The gateway checks `target` against `AGW_ALLOWED_TARGETS` on every call. The adapter accepts no arbitrary method, body, headers, query, browser action, crawl, or active scan. It returns at most 16 KiB of page text. A GET or login can still change target application state when the application implements it that way; use a test account with target-side read-only authorization where possible.
Each MCP process permits at most three login attempts per profile, four cookie sessions, and 100 observed pages.

## Login profiles

Mount a reviewed UTF-8 JSON file read-only at `/opt/security-hub/zap_profiles.json`. The default file has no profiles, so login is unavailable until one is configured. Example:

```json
{
  "profiles": {
    "test_account": {
      "origin": "https://app.example.com",
      "login_path": "/login",
      "verify_path": "/account/",
      "verify_contains": "My account",
      "username": "approved-test-user",
      "username_field": "username",
      "password_field": "password",
      "allowed_path_prefixes": ["/account/", "/reports/"]
    }
  }
}
```

`zap_login` requires `target` to equal the profile's origin. It sends only the configured form fields and follows no redirects. It then GETs the configured verification path and requires a 200 response containing the configured marker before returning a session ID. The profile must be reviewed by the target owner; a password found in JavaScript is not, by itself, authorization to log in. Login currently supports simple cookie-backed URL-encoded forms. CSRF-token, JavaScript, SSO, and OAuth login flows are not supported by this adapter yet.

ZAP is bundled into the single image at build time, so normal use does not require internet access. The daemon writes its local session data under `/var/lib/security-hub/zap`. The ZAP HTTP API listens only on `127.0.0.1` and uses a random key generated at startup.
