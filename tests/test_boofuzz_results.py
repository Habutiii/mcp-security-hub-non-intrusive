"""Result lookup must remain inside the Boofuzz results directory."""

import asyncio
import importlib.util
import json
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "tools/fuzzing/boofuzz-mcp/server.py"
SPEC = importlib.util.spec_from_file_location("boofuzz_result_server", SOURCE)
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def test_session_id_cannot_escape_results_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(server.settings, "results_dir", str(tmp_path / "results"))
    (tmp_path / "private.txt").write_text("private", encoding="utf-8")

    response = asyncio.run(server.call_tool("boofuzz_get_results", {"session_id": "../private.txt"}))

    assert response[0].text == "Invalid session ID."


def test_results_are_bounded(tmp_path, monkeypatch):
    root = tmp_path / "results"
    session = root / "session_1"
    session.mkdir(parents=True)
    (session / "log.txt").write_text("x" * 6000, encoding="utf-8")
    monkeypatch.setattr(server.settings, "results_dir", str(root))

    response = asyncio.run(server.call_tool("boofuzz_get_results", {"session_id": "session_1"}))

    assert len(json.loads(response[0].text)["files"]["log.txt"]) == 5000
