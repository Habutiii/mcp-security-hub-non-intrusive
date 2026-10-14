"""Deployment-owned switches for the fixed local MCP capability registry."""

from configparser import ConfigParser
from dataclasses import dataclass
from pathlib import Path

from capability_policy import CAPABILITIES


DEFAULT_PATH = Path(__file__).resolve().parent.parent / "tool_setting.ini"


@dataclass(frozen=True)
class ToolSettings:
    enabled_components: frozenset[str]
    enabled_tools: dict[str, frozenset[str]]

    def tools_for(self, component_id: str) -> frozenset[str]:
        return self.enabled_tools.get(component_id, frozenset())


def load_tool_settings(path: Path = DEFAULT_PATH) -> ToolSettings:
    """Require an explicit switch for every registered component and tool."""
    parser = ConfigParser(interpolation=None)
    parser.optionxform = str
    if not parser.read(path, encoding="utf-8"):
        raise ValueError(f"Tool settings file is missing: {path}")
    if set(parser.sections()) != {"components", "tools"}:
        raise ValueError("Tool settings must contain only [components] and [tools]")

    components = {cap.component_id for cap in CAPABILITIES}
    tools = {f"{cap.component_id}.{name}" for cap in CAPABILITIES for name in cap.allowed_tools}
    if set(parser["components"]) != components or set(parser["tools"]) != tools:
        raise ValueError("Tool settings must exactly match the reviewed component and tool registry")

    try:
        enabled_components = frozenset(
            component for component in components if parser.getboolean("components", component)
        )
        enabled_tools = {
            cap.component_id: frozenset(
                name for name in cap.allowed_tools
                if cap.component_id in enabled_components
                and parser.getboolean("tools", f"{cap.component_id}.{name}")
            )
            for cap in CAPABILITIES
        }
        # Parse even the switches under disabled components so bad values fail at startup.
        for key in tools:
            parser.getboolean("tools", key)
    except ValueError as error:
        raise ValueError("Tool settings switches must be true or false") from error
    return ToolSettings(enabled_components, enabled_tools)
