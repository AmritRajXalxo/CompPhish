"""Read at most `limit` bytes from a stream of chunks."""

from __future__ import annotations

from typing import Iterable


def read_capped(chunks: Iterable[bytes], limit: int) -> tuple[bytes, bool]:
    """Return (data, truncated).

    Stops reading as soon as more than `limit` bytes have been seen, so a huge or endless
    response can never use more than about `limit` bytes of memory. `truncated` is True
    only when data beyond the limit really existed."""
    if limit <= 0:
        raise ValueError("limit must be positive")
    out: list[bytes] = []
    size = 0
    for chunk in chunks:
        if not chunk:
            continue
        room = limit - size
        if len(chunk) > room:
            if room > 0:
                out.append(chunk[:room])
            return b"".join(out), True
        out.append(chunk)
        size += len(chunk)
    return b"".join(out), False
