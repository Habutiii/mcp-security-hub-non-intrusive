#!/usr/bin/env python3
"""Narrow MCP access to local ZAP passive analysis and configured login forms."""

import asyncio
import http.cookiejar
import json
import os
import secrets
import signal
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from adapters.input_validation import http_url


app = Server("zap-mcp")
ZAP_HOME = Path("/var/lib/security-hub/zap")
BUDGET_PATH = ZAP_HOME / "budget.json"
PROFILE_PATH = Path("/opt/security-hub/zap_profiles.json")
MAX_BODY = 16_384
MAX_ALERTS = 50
MAX_SESSIONS = 4
MAX_LOGIN_ATTEMPTS = 3
MAX_OBSERVATIONS = 100
PROCESS: asyncio.subprocess.Process | None = None
API_PORT: int | None = None
API_KEY: str | None = None
PROXY_CERT: str | None = None
SESSIONS: dict[str, tuple[str, str, http.cookiejar.CookieJar]] = {}
START_LOCK = asyncio.Lock()
CALL_LOCK = asyncio.Lock()


def charge_budget(kind: str, profile_id: str | None = None) -> None:
    """Persist call limits across MCP shutdown/restart in this container."""
    ZAP_HOME.mkdir(parents=True, exist_ok=True)
    if BUDGET_PATH.exists():
        budget = json.loads(BUDGET_PATH.read_text(encoding="utf-8"))
    else:
        budget = {"observations": 0, "login_attempts": {}}
    if (not isinstance(budget, dict) or set(budget) != {"observations", "login_attempts"}
            or type(budget["observations"]) is not int or not 0 <= budget["observations"] <= MAX_OBSERVATIONS
            or not isinstance(budget["login_attempts"], dict)
            or any(type(value) is not int or not 0 <= value <= MAX_LOGIN_ATTEMPTS
                   for value in budget["login_attempts"].values())):
        raise ValueError("ZAP budget state is invalid")
    if kind == "login" and profile_id is not None:
        count = budget["login_attempts"].get(profile_id, 0)
        if count >= MAX_LOGIN_ATTEMPTS:
            raise ValueError("login attempt budget exhausted")
        budget["login_attempts"][profile_id] = count + 1
    elif kind == "observe":
        if budget["observations"] >= MAX_OBSERVATIONS:
            raise ValueError("observation budget exhausted")
        budget["observations"] += 1
    else:
        raise ValueError("unknown ZAP budget operation")
    temporary = BUDGET_PATH.with_name(f"budget.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_text(json.dumps(budget), encoding="utf-8")
        temporary.replace(BUDGET_PATH)
    finally:
        temporary.unlink(missing_ok=True)


def origin_of(value: str) -> str:
    value = http_url(value, allow_query=False)
    parsed = urllib.parse.urlsplit(value)
    if parsed.fragment:
        raise ValueError("fragments are not supported")
    return f"{parsed.scheme}://{parsed.netloc.lower()}"


def validate_target(value: Any) -> str:
    value = http_url(value, allow_query=False)
    parsed = urllib.parse.urlsplit(value)
    if "@" in parsed.netloc or "\\" in value or parsed.path.startswith("//") or "%2f" in parsed.path.lower() or "%5c" in parsed.path.lower():
        raise ValueError("ambiguous URL path is not supported")
    return value


def load_profile(profile_id: Any) -> dict[str, Any]:
    if not isinstance(profile_id, str) or not profile_id.isascii() or not profile_id.replace("_", "").replace("-", "").isalnum() or len(profile_id) > 40:
        raise ValueError("invalid profile_id")
    data = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profile = data.get("profiles", {}).get(profile_id)
    if not isinstance(profile, dict):
        raise ValueError("unknown login profile")
    required = {"origin", "login_path", "verify_path", "verify_contains", "username", "username_field", "password_field", "allowed_path_prefixes"}
    if set(profile) != required:
        raise ValueError("login profile has unsupported fields")
    origin = origin_of(profile["origin"])
    if profile["origin"] != origin:
        raise ValueError("profile origin must not include a path or query")
    for name in ("login_path", "verify_path"):
        path = profile[name]
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path or "\\" in path:
            raise ValueError(f"invalid {name}")
    marker = profile["verify_contains"]
    if not isinstance(marker, str) or not 1 <= len(marker) <= 200 or any(ord(c) < 32 for c in marker):
        raise ValueError("invalid login verification marker")
    for key in ("username", "username_field", "password_field"):
        if not isinstance(profile[key], str) or not profile[key] or len(profile[key]) > 128 or any(ord(c) < 33 or ord(c) > 126 for c in profile[key]):
            raise ValueError(f"invalid profile {key}")
    if profile["username_field"] == profile["password_field"]:
        raise ValueError("login field names must be distinct")
    prefixes = profile["allowed_path_prefixes"]
    if not isinstance(prefixes, list) or not 1 <= len(prefixes) <= 20 or any(
        not isinstance(prefix, str) or not prefix.startswith("/") or prefix.startswith("//")
        or "?" in prefix or "#" in prefix or "\\" in prefix for prefix in prefixes
    ):
        raise ValueError("invalid allowed_path_prefixes")
    return profile


def _local_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _api(path: str, params: dict[str, str] | None = None) -> dict[str, Any] | str:
    if API_PORT is None or API_KEY is None:
        raise RuntimeError("ZAP is not running")
    query = urllib.parse.urlencode(params or {})
    url = f"http://127.0.0.1:{API_PORT}{path}" + (f"?{query}" if query else "")
    request = urllib.request.Request(url, headers={"X-ZAP-API-Key": API_KEY})
    with _local_opener().open(request, timeout=5) as response:
        raw = response.read(200_000)
    if path.startswith("/OTHER/"):
        return raw.decode("utf-8")
    result = json.loads(raw)
    if "code" in result and "message" in result:
        raise RuntimeError(f"ZAP API error: {result['code']}")
    return result


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def ensure_zap() -> None:
    global PROCESS, API_PORT, API_KEY, PROXY_CERT
    async with START_LOCK:
        if PROCESS is not None and PROCESS.returncode is None:
            return
        ZAP_HOME.mkdir(parents=True, exist_ok=True)
        API_PORT = _free_port()
        API_KEY = secrets.token_hex(32)
        env = os.environ.copy()
        env["JAVA_TOOL_OPTIONS"] = "-Xmx512m"
        PROCESS = await asyncio.create_subprocess_exec(
            "/opt/zap/zap.sh", "-daemon", "-host", "127.0.0.1", "-port", str(API_PORT),
            "-dir", str(ZAP_HOME), "-config", f"api.key={API_KEY}",
            "-config", "api.addrs.addr.name=127.0.0.1",
            "-config", "api.addrs.addr.regex=false",
            "-config", "api.disablekey=false",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            env=env, start_new_session=True,
        )
        for _ in range(120):
            if PROCESS.returncode is not None:
                raise RuntimeError("local ZAP process exited during startup")
            try:
                await asyncio.to_thread(_api, "/JSON/core/view/version/")
                PROXY_CERT = await asyncio.to_thread(_api, "/OTHER/core/other/rootcert/")
                if "BEGIN CERTIFICATE" not in PROXY_CERT:
                    raise RuntimeError("ZAP did not return a proxy CA certificate")
                return
            except (OSError, TimeoutError, urllib.error.URLError, ValueError, RuntimeError):
                await asyncio.sleep(0.5)
        await stop_zap()
        raise RuntimeError("local ZAP process did not become ready")


async def stop_zap() -> None:
    global PROCESS, API_PORT, API_KEY, PROXY_CERT
    process = PROCESS
    if process is not None and process.returncode is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            await asyncio.wait_for(process.wait(), timeout=5)
        except (ProcessLookupError, TimeoutError):
            if process.returncode is None:
                os.killpg(process.pid, signal.SIGKILL)
                await process.wait()
    PROCESS = None
    API_PORT = None
    API_KEY = None
    PROXY_CERT = None
    SESSIONS.clear()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _fetch(target: str, jar: http.cookiejar.CookieJar, *, form: bytes | None = None) -> dict[str, Any]:
    if API_PORT is None or PROXY_CERT is None:
        raise RuntimeError("ZAP is not ready")
    proxy = f"http://127.0.0.1:{API_PORT}"
    tls = ssl.create_default_context(cadata=PROXY_CERT)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=tls), NoRedirect(),
    )
    headers = {"User-Agent": "security-hub-zap/1.0"}
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(target, data=form, headers=headers, method="POST" if form is not None else "GET")
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(MAX_BODY + 1)
        return {"status": response.status, "body": body[:MAX_BODY].decode("utf-8", errors="replace"),
                "truncated": len(body) > MAX_BODY,
                "content_type": response.headers.get("Content-Type", "")[:160]}


def _alerts(target: str) -> list[dict[str, Any]]:
    result = _api("/JSON/core/view/alerts/", {"baseurl": origin_of(target), "start": "0", "count": str(MAX_ALERTS)})
    return [{"name": alert.get("name"), "risk": alert.get("risk"), "confidence": alert.get("confidence"),
             "url": alert.get("url"), "description": str(alert.get("description", ""))[:1000]}
            for alert in result.get("alerts", [])]


def _pending_records() -> int:
    result = _api("/JSON/pscan/view/recordsToScan/")
    return int(result.get("recordsToScan", 0))


async def wait_for_passive() -> int:
    """Give ZAP a short bounded window to finish queued passive checks."""
    for _ in range(10):
        pending = await asyncio.to_thread(_pending_records)
        if pending <= 0:
            return 0
        await asyncio.sleep(0.5)
    return await asyncio.to_thread(_pending_records)


@app.list_tools()
async def list_tools() -> list[Tool]:
    target = {"type": "string", "description": "Authorized HTTP(S) URL with no query or fragment"}
    return [
        Tool(name="zap_observe", description="GET one in-scope page through local ZAP and return bounded content and passive alerts; no redirects.",
             inputSchema={"type": "object", "properties": {"target": target, "session_id": {"type": "string"}},
                          "required": ["target"], "additionalProperties": False}),
        Tool(name="zap_login", description="POST credentials only to a deployment-owned login profile; no arbitrary method, path, fields or body.",
             inputSchema={"type": "object", "properties": {"target": target,
                          "profile_id": {"type": "string"}, "password": {"type": "string", "minLength": 1, "maxLength": 256}},
                          "required": ["target", "profile_id", "password"], "additionalProperties": False}),
        Tool(name="zap_passive_alerts", description="Read bounded passive findings already observed for this in-scope origin.",
             inputSchema={"type": "object", "properties": {"target": target},
                          "required": ["target"], "additionalProperties": False}),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        allowed = {"zap_observe": {"target", "session_id"},
                   "zap_login": {"target", "profile_id", "password"},
                   "zap_passive_alerts": {"target"}}
        if name not in allowed or not isinstance(arguments, dict) or set(arguments) - allowed[name]:
            raise ValueError("unknown tool or unsupported option")
        target = validate_target(arguments.get("target"))
        async with CALL_LOCK:
            if name == "zap_login":
                profile = load_profile(arguments.get("profile_id"))
                if target != profile["origin"]:
                    raise ValueError("target must equal the configured login origin")
                password = arguments.get("password")
                if not isinstance(password, str) or not 1 <= len(password) <= 256:
                    raise ValueError("password must be a bounded string")
                if len(SESSIONS) >= MAX_SESSIONS:
                    raise ValueError("maximum authenticated sessions reached")
                profile_id = arguments["profile_id"]
                charge_budget("login", profile_id)
                await ensure_zap()
                jar = http.cookiejar.CookieJar()
                form = urllib.parse.urlencode({profile["username_field"]: profile["username"],
                                               profile["password_field"]: password}).encode()
                login_url = profile["origin"] + profile["login_path"]
                response = await asyncio.to_thread(_fetch, login_url, jar, form=form)
                if response["status"] >= 400 or not list(jar):
                    raise ValueError("login did not establish a cookie-backed session")
                verification = await asyncio.to_thread(_fetch, profile["origin"] + profile["verify_path"], jar)
                if verification["status"] != 200 or profile["verify_contains"] not in verification["body"]:
                    raise ValueError("login verification failed")
                session_id = secrets.token_urlsafe(24)
                SESSIONS[session_id] = (profile["origin"], arguments["profile_id"], jar)
                payload = {"session_id": session_id, "status": response["status"], "cookie_count": len(list(jar))}
            elif name == "zap_observe":
                session_id = arguments.get("session_id")
                jar = http.cookiejar.CookieJar()
                if session_id is not None:
                    if not isinstance(session_id, str) or session_id not in SESSIONS:
                        raise ValueError("unknown session")
                    session_origin, profile_id, jar = SESSIONS[session_id]
                    if origin_of(target) != session_origin:
                        raise ValueError("session is bound to another origin")
                    profile = load_profile(profile_id)
                    path = urllib.parse.urlsplit(target).path or "/"
                    if not any(path.startswith(prefix) for prefix in profile["allowed_path_prefixes"]):
                        raise ValueError("path is outside the profile's observation scope")
                charge_budget("observe")
                await ensure_zap()
                response = await asyncio.to_thread(_fetch, target, jar)
                pending = await wait_for_passive()
                payload = {"target": target, **response, "passive_records_pending": pending,
                           "passive_alerts": await asyncio.to_thread(_alerts, target)}
            else:
                await ensure_zap()
                pending = await wait_for_passive()
                payload = {"target": target, "passive_records_pending": pending,
                           "passive_alerts": await asyncio.to_thread(_alerts, target)}
        return [TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))]
    except (ValueError, OSError, RuntimeError, urllib.error.URLError, json.JSONDecodeError) as error:
        return [TextContent(type="text", text=f"Rejected: {error}")]


async def main() -> None:
    try:
        async with stdio_server() as streams:
            await app.run(streams[0], streams[1], app.create_initialization_options())
    finally:
        await stop_zap()


if __name__ == "__main__":
    asyncio.run(main())
