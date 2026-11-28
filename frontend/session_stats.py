"""Real numbers for the Overview page: this session's scans and the saved evaluation summary.

Pure Python (no Streamlit import) so it can be tested. Nothing here is simulated.
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any

MAX_HISTORY = 50
VERDICTS = ("LEGITIMATE", "LIKELY_LEGITIMATE", "NEEDS_REVIEW", "PHISHING")
VERDICT_LABEL = {
    "PHISHING": "Phishing", "NEEDS_REVIEW": "Needs review",
    "LIKELY_LEGITIMATE": "Likely legitimate", "LEGITIMATE": "Legitimate",
}
VERDICT_COLOUR = {
    "PHISHING": "#ff6e83", "NEEDS_REVIEW": "#f5c451",
    "LIKELY_LEGITIMATE": "#53d8e8", "LEGITIMATE": "#57d6a1",
}
DEFAULT_EVAL_PATH = Path(__file__).resolve().parents[1] / "models" / "evaluation_summary.json"


def record_scan(history: list[dict] | None, data: Any, url: str, now: float | None = None) -> list[dict]:
    """Add one finished scan (newest first, capped). Malformed results are ignored."""
    history = list(history or [])
    if not isinstance(data, dict):
        return history
    pred = str(data.get("prediction", "")).strip().upper()
    if pred not in VERDICTS:
        return history
    try:
        risk = float(data.get("risk_score"))
    except (TypeError, ValueError):
        return history
    if not math.isfinite(risk) or not 0 <= risk <= 100:
        return history
    entry = {"url": str(url)[:300], "verdict": pred, "risk": round(risk, 2),
             "at": float(now if now is not None else time.time())}
    return ([entry] + history)[:MAX_HISTORY]


def summarise(history: list[dict] | None) -> dict:
    history = history or []
    counts = {v: 0 for v in VERDICTS}
    for h in history:
        if h.get("verdict") in counts:
            counts[h["verdict"]] += 1
    n = len(history)
    return {
        "total": n, "counts": counts,
        "flagged": counts["PHISHING"], "review": counts["NEEDS_REVIEW"],
        "avg_risk": (sum(h["risk"] for h in history) / n) if n else None,
    }


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def load_eval_summary(path: Path | str = DEFAULT_EVAL_PATH) -> dict | None:
    """Read models/evaluation_summary.json (written by scripts/evaluate_live.py). None if absent or invalid."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    try:
        out = {
            "generated": str(raw["generated"])[:10],
            "phish_n": int(raw["phish_n"]), "phish_caught": int(raw["phish_caught"]),
            "legit_n": int(raw["legit_n"]), "legit_flagged": int(raw["legit_flagged"]),
            "unseen_domains": bool(raw.get("unseen_domains", False)),
        }
    except (KeyError, TypeError, ValueError):
        return None
    if out["phish_n"] <= 0 or out["legit_n"] <= 0:
        return None
    if not (0 <= out["phish_caught"] <= out["phish_n"] and 0 <= out["legit_flagged"] <= out["legit_n"]):
        return None
    return out


def cards(summary: dict, ev: dict | None) -> list[tuple[str, str, str, str]]:
    """(label, value, footnote, accent) for the four Overview cards."""
    n = summary["total"]
    out = [
        ("SCANS THIS SESSION", str(n), "Scans you ran in this browser" if n else "No scans yet", "#8b7cff"),
        ("FLAGGED PHISHING", str(summary["flagged"]) if n else "—",
         f"{summary['review']} need review" if n else "Run a scan to see this", "#ff6e83"),
        ("AVERAGE RISK", f"{summary['avg_risk']:.1f}%" if n else "—",
         "Mean of this session's scores" if n else "No scans yet", "#f6bd60"),
    ]
    if ev:
        rate = 100 * ev["legit_flagged"] / ev["legit_n"]
        scope = "unseen domains" if ev["unseen_domains"] else "domains not checked against training"
        out.append(("LEGIT FLAGGED (MEASURED)", f"{rate:.1f}%",
                    f"{ev['legit_flagged']}/{ev['legit_n']} legitimate pages · {scope}", "#57d6a1"))
    else:
        out.append(("MODEL MEASURED", "Not yet", "Run scripts/evaluate_live.py", "#57d6a1"))
    return out
