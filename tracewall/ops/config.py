"""Optional YAML config (TRACEWALL_CONFIG)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class AuditConfig:
    path: str = "tracewall_audit.jsonl"
    stdout: bool = False


@dataclass
class TracewallConfig:
    profile: str = "balanced"
    org_domains: list[str] = field(default_factory=list)
    db_path: str = "tracewall.db"
    audit: AuditConfig = field(default_factory=AuditConfig)
    metrics: bool = True
    normalize_args: bool = True
    canonical_tool_names: bool = True
    require_identity: bool | None = None  # None = follow profile
    require_caps: bool | None = None


def load_config(path: str | None = None) -> TracewallConfig:
    raw_path = path or os.environ.get("TRACEWALL_CONFIG", "").strip()
    if not raw_path:
        return TracewallConfig()
    data = yaml.safe_load(Path(raw_path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"config must be a mapping: {raw_path}")
    audit_raw = data.get("audit") or {}
    if isinstance(audit_raw, str):
        audit = AuditConfig(path=audit_raw)
    else:
        audit = AuditConfig(
            path=str(audit_raw.get("path", "tracewall_audit.jsonl")),
            stdout=bool(audit_raw.get("stdout", False)),
        )
    domains = data.get("org_domains") or []
    if isinstance(domains, str):
        domains = [d.strip() for d in domains.split(",") if d.strip()]
    cfg = TracewallConfig(
        profile=str(data.get("profile", "balanced")),
        org_domains=list(domains),
        db_path=str(data.get("db_path", "tracewall.db")),
        audit=audit,
        metrics=bool(data.get("metrics", True)),
        normalize_args=bool(data.get("normalize_args", True)),
        canonical_tool_names=bool(data.get("canonical_tool_names", True)),
        require_identity=data.get("require_identity", None),
        require_caps=data.get("require_caps", None),
    )
    if cfg.org_domains:
        os.environ["TRACEWALL_ORG_DOMAINS"] = ",".join(cfg.org_domains)
    return cfg


def apply_org_domains(domains: list[str]) -> None:
    if domains:
        os.environ["TRACEWALL_ORG_DOMAINS"] = ",".join(domains)
