"""
String / tool-name normalization for policy matching.

Closes known bypasses: Unicode format chars (ZWSP) in IBAN-like fields,
and PascalCase / mixed-case tool aliases.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any

# Zero-width / BOM / soft hyphen — strip from compared strings.
_FORMAT_CHARS = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u00ad"), None)


def normalize_text(value: str) -> str:
    s = unicodedata.normalize("NFKC", value)
    return s.translate(_FORMAT_CHARS).strip()


def normalize_args(args: dict | None) -> dict:
    """Deep-copy args with string leaves normalized (ZWSP/NFKC)."""
    if not args:
        return {}
    return _norm_obj(args)  # type: ignore[return-value]


def _norm_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return normalize_text(obj)
    if isinstance(obj, dict):
        return {k: _norm_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_norm_obj(v) for v in obj]
    return obj


def canonical_tool_name(name: str) -> str:
    """Lowercase + CamelCase/PascalCase → snake_case for policy lookup."""
    s = normalize_text(name or "")
    s = s.replace("-", "_").replace(".", "_")
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", s)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = re.sub(r"_+", "_", s).strip("_").lower()
    return s
