"""Gateway rejects unadvertised fields before a child sees them."""

import sys
from pathlib import Path

import pytest
from mcp.types import Tool


sys.path.insert(0, str(Path(__file__).parent.parent / "gateway-mcp"))
from server import validate_child_arguments  # noqa: E402


TOOL = Tool(
    name="example", description="example",
    inputSchema={"type": "object", "properties": {
        "target": {"type": "string"},
        "rate": {"type": "integer", "minimum": 1, "maximum": 50},
    }, "required": ["target"]},
)


def test_typed_values_are_preserved_as_one_argument_object():
    arguments = {"target": "example.com", "rate": 5}
    assert validate_child_arguments(TOOL, arguments) is arguments


@pytest.mark.parametrize("arguments", [
    {"target": "example.com", "extra_args": "--script unsafe"},
    {"target": "example.com", "rate": "5;id"},
    {"target": "example.com", "rate": 1000},
    {"rate": 5},
    ["example.com"],
])
def test_unknown_or_wrongly_typed_arguments_fail(arguments):
    with pytest.raises(ValueError):
        validate_child_arguments(TOOL, arguments)
