"""Container-only smoke check for the bundled ZAP binary and loopback API."""

import asyncio

from server import _api, ensure_zap, stop_zap


async def main() -> None:
    try:
        await ensure_zap()
        version = await asyncio.to_thread(_api, "/JSON/core/view/version/")
        if not isinstance(version, dict) or not version.get("version"):
            raise RuntimeError("ZAP version API returned no version")
        print(f"ZAP {version['version']} started with its loopback API")
    finally:
        await stop_zap()


if __name__ == "__main__":
    asyncio.run(main())
