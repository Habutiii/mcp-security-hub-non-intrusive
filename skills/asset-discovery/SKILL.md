---
name: asset-discovery
description: Discover approved network assets and services with the reviewed passive-intelligence and bounded-observation capabilities. Use when an orchestrator needs a scoped inventory of domains, hosts, ports, TLS metadata, or service fingerprints without exploit delivery, credential attacks, or disruptive scanning.
---

# Asset Discovery

1. Confirm every requested domain, IP, and CIDR is in immutable scope. Reject wildcard expansion, broad ranges, and private ranges unless the scope names them explicitly.
2. Prefer passive historical data first (`waybackurls`), then use a single `bounded_observation` capability selected from the gateway catalog.
3. Use only the exact gateway binding: `pd_subfinder`, `pd_dns_resolve`, `pd_port_scan`, Nmap discovery tools, or `externalattacker` discovery tools. Never construct commands, NSE names, port expressions, templates, or rate options outside the exposed schema.
4. Keep requests narrow: one asset class, smallest port set, lowest available rate, bounded timeout, and no repeated retries after errors or rate limits.
5. Preserve the capability ID, scope ID, tool arguments, timestamp, and output as evidence. Return an inventory and confidence level, not exploitation claims.

Stop and escalate when discovery would require broad/high-rate scanning, authenticated access, a custom payload, or an uncertain target-side effect.
