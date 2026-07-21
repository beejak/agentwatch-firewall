"""Reload YAML policy packs (smoke / ops)."""
from __future__ import annotations

import argparse
import asyncio

from tracewall.ops.config import load_config
from tracewall.transports.profiles import get_profile, load_policy_for_profile


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Reload YAML policy packs")
    ap.add_argument("--profile", default=None)
    args = ap.parse_args(argv)
    cfg = load_config()
    profile = args.profile or cfg.profile

    async def _run() -> int:
        eng = await load_policy_for_profile(get_profile(profile))
        print(f"reloaded: rules={len(eng._rules)} profile={profile}")
        return 0 if eng._rules else 1

    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(main())
