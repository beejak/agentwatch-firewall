"""Health check: profile loads rules."""
from __future__ import annotations

import argparse
import asyncio
import os
import tempfile
from pathlib import Path

from tracewall.audit.sink import NullAuditSink
from tracewall.ops.config import load_config
from tracewall.transports.profiles import build_firewall_for_profile


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Tracewall health: rules loaded for profile")
    ap.add_argument("--profile", default=None)
    args = ap.parse_args(argv)
    cfg = load_config()
    profile = args.profile or cfg.profile

    async def _run() -> int:
        fd, db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            fw, prof = await build_firewall_for_profile(
                profile, db_path=db, audit=NullAuditSink(),
            )
            n = len(fw._policy._rules)
            print(f"ok: rules_loaded={n} profile={prof.name} zta_pack={prof.load_zta_pack}")
            return 0 if n > 0 else 1
        finally:
            Path(db).unlink(missing_ok=True)

    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(main())
