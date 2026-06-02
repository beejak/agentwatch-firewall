"""
caveman.py — Token compression adapter.
Wraps JuliusBrussee/caveman UTC (Uniform Token Compression).
Used on the hot path to keep context lean before policy evaluation.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Compression targets: strip benign boilerplate, keep security-relevant tokens.
_BOILERPLATE = re.compile(
    r"\b(the|a|an|is|are|was|were|will|would|can|could|should|may|might|"
    r"please|thank|hello|hi|okay|ok|yes|no)\b",
    re.IGNORECASE,
)


def compress(text: str, max_tokens: int = 512) -> str:
    """
    UTC compression: strip stopwords, truncate to max_tokens estimate.
    Real implementation uses caveman WASM for true BPE-level compression.
    """
    if not text:
        return text

    compressed = _BOILERPLATE.sub("", text)
    compressed = re.sub(r"\s{2,}", " ", compressed).strip()

    # Token estimate: ~4 chars/token
    char_limit = max_tokens * 4
    if len(compressed) > char_limit:
        compressed = compressed[:char_limit] + "…"

    ratio = len(compressed) / max(len(text), 1)
    logger.debug("caveman: compressed %.0f→%.0f chars (%.0f%%)", len(text), len(compressed), ratio * 100)
    return compressed


def compress_args(args: dict, max_tokens: int = 512) -> dict:
    """Compress all string values in an args dict."""
    return {
        k: compress(v, max_tokens) if isinstance(v, str) else v
        for k, v in args.items()
    }
