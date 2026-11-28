"""URL typed or pasted into the scanner, and plain-language backend errors. Pure Python (testable)."""

from __future__ import annotations

import re

_REPLACEMENTS = (
    (re.compile(r"^\s*hxxp", re.I), lambda m: m.group(0).lower().replace("hxxp", "http")),
    (re.compile(r"\[:\]|\(:\)"), lambda m: ":"),
    (re.compile(r"\[://\]"), lambda m: "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), lambda m: "."),
)


def refang(value: str) -> str:
    """Undo the defanging used when sharing malicious links (hxxp, [.], (.), [dot]).

    Defanged text is only ever turned back into a normal address inside the scanner box,
    where the page is fetched by the server, not opened in the viewer's browser."""
    value = (value or "").strip().strip("<>").strip()
    for pattern, repl in _REPLACEMENTS:
        value = pattern.sub(repl, value)
    # schemes are case-insensitive; keep them lower-case so "HXXPS" does not become "httpS"
    return re.sub(r"^(https?)(?=://)", lambda m: m.group(1).lower(), value, flags=re.I)


def friendly_backend_error(status: int, detail: object) -> str:
    """Turn the API's error detail into a sentence a user can act on."""
    text = detail.get("detail") if isinstance(detail, dict) else detail
    text = str(text or "")
    low = text.lower()
    if "unable to resolve" in low or "no valid ip" in low:
        return ("This website no longer exists, or its address cannot be found. "
                "Phishing pages are often taken down within hours, so try another URL.")
    if "not an html" in low:
        return "That address is not a web page (for example a file or image), so it cannot be analysed."
    if "private" in low or "not allowed" in low or "unsafe" in low:
        return "That address points to a private or restricted network, so it is not scanned."
    if "redirect" in low:
        return "The website redirected too many times, so the scan stopped."
    if status == 429:
        return "Too many scans in a short time. Wait a minute and try again."
    return f"The scan could not be completed (HTTP {status}): {text or 'no details returned'}"
