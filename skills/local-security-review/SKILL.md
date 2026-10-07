---
name: local-security-review
description: Review supplied source, configuration, API specifications, hashes, and other local artifacts using local-read capabilities. Use when an orchestrator needs high-signal security findings, dependency or secret observations, and remediation evidence without sending target traffic or running a live exploit.
---

# Local Security Review

1. Confirm the repository or artifact path is approved and mounted read-only.
2. Inventory manifests, lockfiles, infrastructure configuration, API specs, authentication/authorization paths, upload/download paths, and secret handling before choosing tools.
3. Use only `local_read` capabilities such as the reviewed Gitleaks and local grammar-generation bindings. Do not start a target service, transmit a test case, or use recovered credentials against a live service.
4. Tie each finding to a concrete file/location, data-flow or configuration evidence, affected surface, confidence, and a safe remediation.
5. Distinguish verified local facts from runtime hypotheses. Mark hypotheses for a separate human-approved staging validation rather than attempting a proof of concept.
