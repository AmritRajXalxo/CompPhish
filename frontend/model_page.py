"""Model-intelligence page helpers. Pure Python (no Streamlit) so they can be tested.

All text that comes from the API is validated and escaped. Markup is single-line.
"""

from __future__ import annotations

import html
from typing import Any

PIPELINE = [
    ("1", "Fetch the page", "Download the HTML (no JavaScript is run) and record redirects, TLS and load details."),
    ("2", "Score three signals", "URL features (averaged over the cleaned URL and the bare host), six HTML counts, and the page text."),
    ("3", "Fuse the scores", "A logistic regression combines the three probabilities into one risk score."),
    ("4", "Apply the bands", "Below the lower band: legitimate. At or above the upper band: phishing. In between: needs review."),
    ("5", "Check trust evidence", "Domain age (RDAP), TLS validity, shared hosting and cross-domain redirects. A well-established site with no severe page behaviour is not left as PHISHING on the score alone."),
    ("6", "Check threat feeds", "A listing in OpenPhish (or URLhaus / Google Safe Browsing when configured) forces PHISHING. No match never means safe."),
    ("7", "Final verdict", "Page behaviour and the brand-lookalike check can raise concern, or allow LIKELY LEGITIMATE for established sites with no warning signs."),
]

LIMITATIONS = [
    ("Text branch", "Can over-react to pages that talk about phishing, scams or security (for example security vendors and data-science sites)."),
    ("HTML branch", "Uses only six tag counts and reads the downloaded HTML, so pages built by JavaScript look nearly empty to it. Its most influential counts also track page size, so a large legitimate page can look different from a small one for reasons unrelated to phishing."),
    ("URL branch", "Depends on the shape of the URL (host length, entropy, path). Tracking parameters are removed and the bare host is averaged in, but unusual legitimate URLs can still look odd."),
    ("Training data", "Learned from one dataset. Words such as years or news that the text branch treats as legitimate may reflect the dataset's time period, not real phishing behaviour."),
    ("Evidence", "Verdicts are probabilistic estimates. A threat-feed miss and a good domain age are not proof of safety."),
]


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def validate_info(raw: Any) -> dict | None:
    """Keep only well-formed parts of /model-info. None when nothing usable."""
    if not isinstance(raw, dict):
        return None

    def items(key: str, name: str, value: str) -> list[tuple[str, float]]:
        out = []
        for it in raw.get(key) or []:
            if isinstance(it, dict) and isinstance(it.get(name), str):
                try:
                    out.append((it[name][:60], float(it[value])))
                except (TypeError, ValueError):
                    pass
        return out

    fusion = raw.get("fusion") if isinstance(raw.get("fusion"), dict) else None
    weights = None
    if fusion:
        try:
            weights = [("URL", float(fusion["url"])), ("HTML", float(fusion["html"])), ("Text", float(fusion["text"]))]
        except (KeyError, TypeError, ValueError):
            weights = None
    terms = raw.get("text_terms") if isinstance(raw.get("text_terms"), dict) else {}
    bands = raw.get("bands") if isinstance(raw.get("bands"), dict) else {}
    try:
        low, high = float(bands["legitimate_below"]), float(bands["phishing_at_or_above"])
    except (KeyError, TypeError, ValueError):
        low, high = 0.40, 0.85
    branches = raw.get("branches") if isinstance(raw.get("branches"), dict) else {}

    def nfeat(b: str) -> int | None:
        v = (branches.get(b) or {}).get("features") if isinstance(branches.get(b), dict) else None
        return v if isinstance(v, int) and v > 0 else None

    return {
        "name": str(raw.get("model_name") or "CompPhish hybrid model")[:120],
        "weights": weights,
        "url": items("url_importance", "feature", "importance"),
        "html": items("html_importance", "feature", "importance"),
        "terms_phish": items_from(terms.get("phishing")),
        "terms_legit": items_from(terms.get("legitimate")),
        "low": low, "high": high,
        "url_features": nfeat("url"), "html_features": nfeat("html"),
        "retrained": bool(raw.get("retrained_domain_disjoint")),
        "trained_at": str(raw.get("trained_at") or "")[:10],
    }


def items_from(lst: Any) -> list[tuple[str, float]]:
    out = []
    for it in lst or []:
        if isinstance(it, dict) and isinstance(it.get("term"), str):
            try:
                out.append((it["term"][:40], abs(float(it["weight"]))))
            except (TypeError, ValueError):
                pass
    return out


def weights_note(weights: list[tuple[str, float]] | None) -> str:
    base = "A larger weight means that branch moves the final score more. "
    if not weights:
        return base
    vals = [abs(v) for _, v in weights]
    if min(vals) > 0 and max(vals) / min(vals) < 1.5:
        return base + "The three are close, so no single signal dominates."
    top = max(weights, key=lambda w: abs(w[1]))[0]
    return base + f"The {top} branch counts most."


def top_note(rows: list[tuple[str, float]], extra: str) -> str:
    return (f"'{rows[0][0]}' is the most influential. " if rows else "") + extra


def bars_html(rows: list[tuple[str, float]], colour: str = "#8b7cff", fmt: str = "{:.1f}%", scale: float = 100.0) -> str:
    """Horizontal bars. Widths are relative to the largest value so small ones stay visible."""
    if not rows:
        return "<div class='info-key' style='font-size:12px'>No data.</div>"
    top = max(v for _, v in rows) or 1.0
    out = []
    for name, v in rows:
        width = max(2.0, 100.0 * v / top)
        out.append(
            f"<div style='margin:7px 0'><div style='display:flex;justify-content:space-between;font-size:12px;color:#cbd4e5'>"
            f"<span style='overflow-wrap:anywhere'>{esc(name)}</span><span style='color:#9aa6bd'>{esc(fmt.format(v * scale))}</span></div>"
            f"<div class='branch-track'><div style='height:100%;border-radius:8px;width:{width:.1f}%;background:{esc(colour)}'></div></div></div>")
    return "".join(out)


def card(title: str, body: str, note: str = "") -> str:
    n = f"<div style='color:#9aa6bd;font-size:11px;line-height:1.6;margin-top:10px'>{esc(note)}</div>" if note else ""
    return f"<div class='surface'><div class='eyebrow'>{esc(title)}</div><div style='margin-top:10px'>{body}</div>{n}</div>"


def pipeline_cards() -> list[str]:
    return [
        f"<div class='surface' style='padding:14px'><div style='color:#8b7cff;font:11px DM Mono,monospace'>STEP {n}</div>"
        f"<div style='color:#edf2fb;font-weight:700;font-size:13px;margin:6px 0 4px'>{esc(t)}</div>"
        f"<div style='color:#aab4c8;font-size:12px;line-height:1.55'>{esc(d)}</div></div>"
        for n, t, d in PIPELINE
    ]


def limitations_html() -> str:
    rows = "".join(
        f"<div class='info-row'><span class='info-key' style='min-width:110px;color:#f6bd60'>{esc(a)}</span><span class='info-val' style='text-align:left;flex:1'>{esc(b)}</span></div>"
        for a, b in LIMITATIONS)
    return f"<div class='surface'>{rows}</div>"


def status_rows(info: dict | None, eval_summary: dict | None) -> list[tuple[str, str, str]]:
    """(component, status, evidence). Status is one of Implemented / Partly / Planned."""
    url_n = (info or {}).get("url_features") or 28
    html_n = (info or {}).get("html_features") or 6
    retrained = bool(info and info.get("retrained"))
    rows = [
        ("URL branch", "Implemented", f"{url_n} lexical features, tree ensemble"),
        ("HTML branch", "Implemented", f"{html_n} structural counts, tree ensemble"),
        ("Text branch", "Implemented", "TF-IDF with logistic regression"),
        ("Fusion and bands", "Implemented", "Logistic regression on three probabilities; three-way decision"),
        ("Domain age, TLS, hosting checks", "Implemented", "RDAP and live TLS handshake"),
        ("Threat feeds", "Implemented", "OpenPhish always; URLhaus and Google Safe Browsing with keys"),
        ("Brand-lookalike check", "Implemented", "Compares the domain with well-known brands"),
        ("Score explanations", "Implemented", "Exact fusion breakdown and tree-path contributions (not SHAP)"),
        ("Domain-disjoint retraining", "Implemented" if retrained else "Partly",
         "Live model trained with unseen-domain splits" if retrained else "Script available; the live model has not been retrained with it yet"),
        ("Live accuracy measurement", "Implemented" if eval_summary else "Partly",
         f"Measured {eval_summary['generated']} on live pages" if eval_summary else "Script available; no results saved yet"),
        ("Graph intelligence", "Planned", "Not part of the live app"),
        ("Genetic-algorithm feature selection", "Planned", "Not part of the live app"),
        ("Fuzzy decision layer", "Planned", "Not part of the live app"),
        ("SHAP explanations", "Planned", "Not part of the live app"),
    ]
    return rows


STATUS_COLOUR = {"Implemented": "#57d6a1", "Partly": "#f5c451", "Planned": "#8792a8"}


def status_table_html(info: dict | None, eval_summary: dict | None) -> str:
    out = []
    for comp, status, ev in status_rows(info, eval_summary):
        out.append(
            f"<div class='info-row' style='flex-wrap:wrap;gap:4px 14px'><span class='info-val' style='text-align:left;flex:1 1 220px'>{esc(comp)}</span>"
            f"<span style='color:{STATUS_COLOUR[status]};font:11px DM Mono,monospace;min-width:92px'>{esc(status)}</span>"
            f"<span class='info-key' style='flex:2 1 260px'>{esc(ev)}</span></div>")
    return "<div class='surface'>" + "".join(out) + "</div>"
