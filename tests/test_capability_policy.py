"""Contract tests for the code-owned gateway capability labels."""

import importlib.util
from pathlib import Path


POLICY_PATH = Path(__file__).parent.parent / "gateway-mcp" / "capability_policy.py"
SPEC = importlib.util.spec_from_file_location("capability_policy", POLICY_PATH)
assert SPEC and SPEC.loader
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


def test_every_capability_has_one_safe_execution_label():
    assert policy.CAPABILITIES
    for capability in policy.CAPABILITIES:
        assert capability.capability_type in set(policy.CapabilityType)
        assert capability.target_effect in set(policy.TargetEffect)
        assert capability.allowed_tools
        assert not capability.human_approval_required


def test_component_ids_and_tool_names_are_unique():
    component_ids = [capability.component_id for capability in policy.CAPABILITIES]
    assert len(component_ids) == len(set(component_ids))
    for capability in policy.CAPABILITIES:
        assert len(capability.allowed_tools) == len(set(capability.allowed_tools))
