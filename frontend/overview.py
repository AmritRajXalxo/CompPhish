"""Overview-page helpers: real session statistics, API status and the saved evaluation summary.

Pure Python (no Streamlit import) so it can be unit-tested. Every string that came from
outside (URLs, API values, JSON files) is escaped or validated before it reaches markup.
Markup is single-line, with no blank lines or indentation, so Streamlit's Markdown
renderer never turns it into a code block.
"""

from __future__ import annotations

import html
import json
import math
import time
from pathlib import Path
from typing import Any

MAX_HISTORY = 50
VERDICTS = ("PHISHING", "NEEDS_REVIEW", "LIKELY_LEGITIMATE", "LEGITIMATE")
VERDICT_LABEL = {
    "PHISHING": "Phishing",
    "NEEDS_REVIEW": "Needs review",
    "LIKELY_LEGITIMATE": "Likely legitimate",
    "LEGITIMATE": "Legitimate",
}
VERDICT_COLOUR = {"PHISHING": "#ff6e83", "NEEDS_REVIEW": "#f5c451",
                  "LIKELY_LEGITIMATE": "#53d8e8", "LEGITIMATE": "#57d6a1"}
VERDICT_HELP = {
    "LEGITIMATE": "Low risk score and nothing alarming found.",
    "LIKELY_LEGITIMATE": "Established site with no warning signs, even if the raw score was elevated.",
    "NEEDS_REVIEW": "Mixed or weak evidence. Check it yourself before trusting it.",
    "PHISHING": "High risk score, or a threat feed lists it.",
}
DEFAULT_EVAL_PATH = Path(__file__).resolve().parents[1] / "models" / "evaluation_summary.json"


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


# ---------------------------------------------------------------- history

def record_scan(history: list[dict] | None, data: Any, url: str, now: float | None = None) -> list[dict]:
    """Append one finished scan (newest first, capped). Malformed data is ignored."""
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


def summarise_history(history: list[dict] | None) -> dict:
    history = history or []
    counts = {v: 0 for v in VERDICTS}
    for h in history:
        if h.get("verdict") in counts:
            counts[h["verdict"]] += 1
    n = len(history)
    return {
        "total": n,
        "counts": counts,
        "flagged": counts["PHISHING"],
        "review": counts["NEEDS_REVIEW"],
        "avg_risk": (sum(h["risk"] for h in history) / n) if n else None,
    }


def ago(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} d ago"


# ---------------------------------------------------------------- API status

def check_api(base_url: str, timeout: float = 4.0, getter=None) -> dict:
    """online / waking / offline. A slow or failing first answer usually means Render is waking."""
    if getter is None:
        import requests
        getter = requests.get
    start = time.time()
    try:
        r = getter(base_url.rstrip("/") + "/health", timeout=timeout)
        ms = int((time.time() - start) * 1000)
        if getattr(r, "status_code", 0) == 200:
            try:
                body = r.json()
            except ValueError:
                body = {}
            body = body if isinstance(body, dict) else {}
            bands = body.get("bands") if isinstance(body.get("bands"), dict) else {}
            return {"state": "online", "ms": ms, "model": str(body.get("model_name") or ""), "bands": bands}
        return {"state": "offline", "ms": ms, "model": "", "detail": f"HTTP {getattr(r, 'status_code', '?')}"}
    except Exception as exc:  # timeout and connection errors are both "not ready yet"
        name = type(exc).__name__
        state = "waking" if "Timeout" in name else "offline"
        return {"state": state, "ms": None, "model": "", "detail": name}


def status_html(status: dict) -> str:
    state = status.get("state")
    if state == "online":
        colour, text = "#57d6a1", f"API online · {status.get('ms', 0)} ms"
    elif state == "waking":
        colour, text = "#f5c451", "API waking up (free hosting sleeps; allow ~30 seconds)"
    else:
        colour, text = "#ff6e83", "API not reachable"
    return (f"<span style='color:{colour}'>&#9679;</span> {esc(text)}")


# ---------------------------------------------------------------- evaluation summary

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
            "high_threshold": float(raw.get("high_threshold", 0.85)),
        }
    except (KeyError, TypeError, ValueError):
        return None
    if out["phish_n"] <= 0 or out["legit_n"] <= 0:
        return None
    if not (0 <= out["phish_caught"] <= out["phish_n"] and 0 <= out["legit_flagged"] <= out["legit_n"]):
        return None
    return out


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def _rate(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{100 * k / n:.1f}% <span style='color:#6f7c94'>(95% CI {100 * lo:.1f}&ndash;{100 * hi:.1f}%, n={n})</span>"


# ---------------------------------------------------------------- markup

def stat_card(label: str, value: str, foot: str, accent: str) -> str:
    return (f"<div class='metric-card'><span class='metric-accent' style='background:{esc(accent)};box-shadow:0 0 14px {esc(accent)}'></span>"
            f"<div class='metric-label'>{esc(label)}</div><div class='metric-value'>{esc(value)}</div>"
            f"<div class='metric-foot'>{esc(foot)}</div></div>")


def stat_cards(summary: dict, eval_summary: dict | None) -> list[str]:
    n = summary["total"]
    cards = [
        stat_card("SCANS THIS SESSION", str(n), "Counts only scans you ran here" if n else "No scans yet", "#8b7cff"),
        stat_card("FLAGGED PHISHING", str(summary["flagged"]) if n else "—",
                  f"{summary['review']} need review" if n else "Run a scan to see this", "#ff6e83"),
        stat_card("AVERAGE RISK", f"{summary['avg_risk']:.1f}%" if n else "—", "Mean of this session's scores" if n else "No scans yet", "#f6bd60"),
    ]
    if eval_summary:
        miss = 100 * eval_summary["legit_flagged"] / eval_summary["legit_n"]
        cards.append(stat_card("LEGIT FLAGGED (MEASURED)", f"{miss:.1f}%",
                               f"{eval_summary['legit_flagged']}/{eval_summary['legit_n']} legitimate pages · {eval_summary['generated']}", "#57d6a1"))
    else:
        cards.append(stat_card("MODEL MEASURED", "Not yet", "Run scripts/evaluate_live.py", "#57d6a1"))
    return cards


def recent_scans_html(history: list[dict] | None, now: float | None = None) -> str:
    if not history:
        return "<div class='surface'><div class='info-key' style='font-size:12px'>No scans yet. Paste a URL above and press Scan; your last scans will appear here.</div></div>"
    now = now if now is not None else time.time()
    rows = []
    for h in history[:8]:
        v = h.get("verdict", "")
        colour = VERDICT_COLOUR.get(v, "#8792a8")
        rows.append(
            f"<div class='info-row' style='flex-wrap:wrap;gap:4px 14px'><span class='info-val' style='text-align:left;flex:1 1 240px;min-width:0;overflow-wrap:anywhere'>{esc(h.get('url', ''))}</span>"
            f"<span style='color:{colour};font:11px DM Mono,monospace;white-space:nowrap'>{esc(VERDICT_LABEL.get(v, v))}</span>"
            f"<span class='info-key' style='white-space:nowrap;min-width:54px;text-align:right'>{h.get('risk', 0):.1f}%</span>"
            f"<span class='info-key' style='white-space:nowrap;min-width:70px;text-align:right'>{esc(ago(now - h.get('at', now)))}</span></div>")
    return "<div class='surface'>" + "".join(rows) + "</div>"


def verdict_legend_cards() -> list[str]:
    items = []
    for v in ("LEGITIMATE", "LIKELY_LEGITIMATE", "NEEDS_REVIEW", "PHISHING"):
        items.append(f"<div class='surface' style='padding:14px'><div style='color:{VERDICT_COLOUR[v]};font-weight:700;font-size:13px'>&#9679; {esc(VERDICT_LABEL[v])}</div>"
                     f"<div style='color:#aab4c8;font-size:12px;margin-top:6px;line-height:1.5'>{esc(VERDICT_HELP[v])}</div></div>")
    return items


def model_card_html(low: float, high: float, model_name: str, eval_summary: dict | None) -> str:
    if eval_summary:
        scope = "unseen domains" if eval_summary["unseen_domains"] else "domains not checked against the training set"
        measured = (f"<div style='margin-top:12px;color:#cbd4e5;font-size:12px;line-height:1.9'>"
                    f"Phishing caught at {eval_summary['high_threshold']:.2f}: {_rate(eval_summary['phish_caught'], eval_summary['phish_n'])}<br>"
                    f"Legitimate wrongly flagged: {_rate(eval_summary['legit_flagged'], eval_summary['legit_n'])}<br>"
                    f"<span style='color:#6f7c94'>Live test, {esc(eval_summary['generated'])}, {esc(scope)}.</span></div>")
    else:
        measured = ("<div style='margin-top:12px;color:#f6bd60;font-size:12px;line-height:1.7'>"
                    "Not yet measured on live pages. Run <code>scripts/evaluate_live.py</code> and copy its summary.json to "
                    "<code>models/evaluation_summary.json</code> to show real numbers here.</div>")
    return (f"<div class='surface'><div class='eyebrow'>LIVE MODEL</div>"
            f"<p style='color:#dce4f2;font-size:13px;margin:12px 0 4px'>{esc(model_name or 'CompPhish hybrid model')}</p>"
            f"<div class='metric-foot'>28 URL features &middot; 6 HTML features &middot; page-text TF-IDF &middot; fusion</div>"
            f"<div class='metric-foot' style='margin-top:6px'>Legitimate below {low:.2f} &middot; phishing at or above {high:.2f} &middot; between: needs review</div>"
            f"{measured}"
            f"<div style='margin-top:12px;color:#748099;font-size:11px'>Threat-feed &ldquo;no match&rdquo; never means a site is safe.</div></div>")


def compact_result_html(data: Any, url: str = "") -> str | None:
    """One-line verdict strip for the Overview. None when the data is not displayable."""
    if not isinstance(data, dict):
        return None
    pred = str(data.get("prediction", "")).strip().upper()
    if pred not in VERDICTS:
        return None
    try:
        risk = float(data.get("risk_score"))
    except (TypeError, ValueError):
        return None
    if not math.isfinite(risk) or not 0 <= risk <= 100:
        return None
    colour = VERDICT_COLOUR[pred]
    shown = data.get("final_url") or url or ""
    return (f"<div class='surface' style='display:flex;flex-wrap:wrap;gap:6px 18px;align-items:center;margin-top:12px'>"
            f"<span style='color:{colour};font-weight:800;font-size:15px'>&#9679; {esc(VERDICT_LABEL[pred])}</span>"
            f"<span style='color:#edf2fb;font-weight:700'>{risk:.1f}% risk</span>"
            f"<span class='info-key' style='flex:1 1 220px;min-width:0;overflow-wrap:anywhere'>{esc(shown)}</span></div>")
