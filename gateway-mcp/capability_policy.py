"""Code-owned capability contract for the non-intrusive gateway.

This file is intentionally small and dependency-free.  An orchestrator obtains
the same data through ``gateway_list_capabilities``; it must not infer safety
from a scanner name or an LLM instruction.
"""

from dataclasses import asdict, dataclass
from enum import Enum


class StringEnum(str, Enum):
    """Python 3.10-compatible string enum."""


class CapabilityType(StringEnum):
    """The only execution classes an agent can receive from this gateway."""

    LOCAL_READ = "local_read"
    PASSIVE_INTELLIGENCE = "passive_intelligence"
    BOUNDED_OBSERVATION = "bounded_observation"


class TargetEffect(StringEnum):
    """Expected target-side effect; audit logs are not treated as mutation."""

    NONE = "none"
    AUDIT_LOGS_ONLY = "audit_logs_only"


class PrivilegeProfile(StringEnum):
    """Kernel privileges a component may require from its deployment."""

    STANDARD = "standard"
    RAW_NETWORK = "raw_network"


@dataclass(frozen=True)
class Capability:
    """A reviewed, positive capability set for exactly one local MCP process."""

    component_id: str
    image: str
    capability_type: CapabilityType
    target_effect: TargetEffect
    description: str
    allowed_tools: frozenset[str]
    scope_required: bool
    human_approval_required: bool = False
    privilege_profile: PrivilegeProfile = PrivilegeProfile.STANDARD

    def public(self) -> dict[str, object]:
        data = asdict(self)
        data["capability_type"] = self.capability_type.value
        data["target_effect"] = self.target_effect.value
        data["privilege_profile"] = self.privilege_profile.value
        data["allowed_tools"] = sorted(self.allowed_tools)
        return data


# Do not add a component here merely because it is present in the repository.
# A component is gateway-callable only after every advertised tool has been
# reviewed and named here.  Opaque upstream wrappers remain outside the agent
# boundary until they are locally constrained to a positive tool set.
CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        "dharma", "dharma-mcp:latest", CapabilityType.LOCAL_READ,
        TargetEffect.NONE, "Generate test cases locally; never sends them.",
        frozenset({"dharma_generate", "dharma_generate_custom"}), False,
    ),
    Capability(
        "boofuzz", "boofuzz-mcp:latest", CapabilityType.LOCAL_READ,
        TargetEffect.NONE, "Read restriction status and stored results only.",
        frozenset({"boofuzz_list_scripts", "boofuzz_get_results"}), False,
    ),
    Capability(
        "hashcat", "hashcat-mcp:latest", CapabilityType.LOCAL_READ,
        TargetEffect.NONE, "Recover supplied local hashes with the reviewed dictionary.",
        frozenset({"hashcat_dictionary_crack"}), False,
    ),
    Capability(
        "gitleaks", "gitleaks-mcp:latest", CapabilityType.LOCAL_READ,
        TargetEffect.NONE, "Read-only secret scanning of approved local input.",
        frozenset({"gitleaks_scan_repo", "gitleaks_scan_dir", "gitleaks_detect", "get_scan_results", "list_active_scans"}), False,
    ),
    Capability(
        "waybackurls", "waybackurls-mcp:latest", CapabilityType.PASSIVE_INTELLIGENCE,
        TargetEffect.NONE, "Retrieve historical URLs from the archive, not the target.",
        frozenset({"fetch_wayback_urls", "get_fetch_results", "list_active_fetches"}), True,
    ),
    Capability(
        "nmap", "nmap-mcp:latest", CapabilityType.BOUNDED_OBSERVATION,
        TargetEffect.AUDIT_LOGS_ONLY, "Reviewed network discovery and fixed NSE catalog.",
        frozenset({"port_scan", "service_scan", "os_detection", "script_scan", "quick_scan", "get_scan_results", "list_active_scans"}), True,
        privilege_profile=PrivilegeProfile.RAW_NETWORK,
    ),
    Capability(
        "whatweb", "whatweb-mcp:latest", CapabilityType.BOUNDED_OBSERVATION,
        TargetEffect.AUDIT_LOGS_ONLY, "HTTP technology fingerprinting only.",
        frozenset({"whatweb_scan", "get_scan_results", "list_active_scans"}), True,
    ),
    Capability(
        "ffuf", "ffuf-mcp:latest", CapabilityType.BOUNDED_OBSERVATION,
        TargetEffect.AUDIT_LOGS_ONLY, "Bounded GET discovery with reviewed wordlists.",
        frozenset({"ffuf_dir", "ffuf_vhost", "ffuf_param", "list_wordlists", "get_fuzz_results", "list_active_scans"}), True,
    ),
    Capability(
        "pd_tools", "pd-tools-mcp:latest", CapabilityType.BOUNDED_OBSERVATION,
        TargetEffect.AUDIT_LOGS_ONLY, "Bounded ProjectDiscovery reconnaissance operations.",
        frozenset({"pd_subfinder", "pd_dns_resolve", "pd_port_scan", "pd_http_probe", "pd_crawl"}), True,
    ),
    Capability(
        "externalattacker", "externalattacker-mcp:latest", CapabilityType.BOUNDED_OBSERVATION,
        TargetEffect.AUDIT_LOGS_ONLY, "Fixed, low-rate attack-surface discovery.",
        frozenset({"discover_subdomains", "scan_ports", "analyze_http", "check_cdn", "analyze_tls"}), True,
    ),
    Capability(
        "masscan", "local", CapabilityType.BOUNDED_OBSERVATION,
        TargetEffect.AUDIT_LOGS_ONLY, "Low-rate scan of a bounded CIDR using a fixed top-port set.",
        frozenset({"masscan_top_ports", "get_scan_results", "list_active_scans"}), True,
        privilege_profile=PrivilegeProfile.RAW_NETWORK,
    ),
    Capability(
        "sqlmap", "local", CapabilityType.LOCAL_READ,
        TargetEffect.NONE, "Read existing SQLMap result state only; execution and extraction are disabled.",
        frozenset({"get_scan_results", "list_active_scans"}), False,
    ),
    Capability(
        "nikto", "local", CapabilityType.BOUNDED_OBSERVATION,
        TargetEffect.AUDIT_LOGS_ONLY, "Fixed read-only Nikto observation checks.",
        frozenset({"nikto_observe", "nikto_get_result"}), True,
    ),
)

CAPABILITY_BY_COMPONENT = {capability.component_id: capability for capability in CAPABILITIES}
