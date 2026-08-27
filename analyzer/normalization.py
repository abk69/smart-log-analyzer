"""Request-string normalization helpers for web-attack detectors.

Keeps the original request intact and produces a bounded, decoded,
case-/whitespace-normalized form for pattern matching.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class NormalizedRequest:
    """Original request plus a normalized copy used for matching."""

    original: str
    normalized: str


def normalize_request(
    request: str,
    *,
    max_decode_passes: int = 2,
) -> NormalizedRequest:
    """Normalize a request path/query for detection.

    Steps (bounded, non-recursive beyond ``max_decode_passes``):

    1. Preserve the original string.
    2. URL-decode up to ``max_decode_passes`` times while encoded escapes remain.
    3. HTML-unescape once (``html.unescape``).
    4. Lower-case.
    5. Collapse whitespace to single spaces.

    Args:
        request: Raw request path/query from a log entry.
        max_decode_passes: Maximum URL-decode iterations (avoids pathological input).

    Returns:
        ``NormalizedRequest`` with both original and normalized forms.
    """
    original = request or ""
    text = original

    for _ in range(max(1, max_decode_passes)):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded

    text = html.unescape(text)
    text = text.lower()
    text = _WHITESPACE.sub(" ", text).strip()

    return NormalizedRequest(original=original, normalized=text)
