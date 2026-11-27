from __future__ import annotations

import html
import math
import os
from typing import Any
from urllib.parse import urlparse

import requests
import streamlit as st

try:
    import plotly.graph_objects as go
    import plotly.express as px
except ImportError as exc:  # clear setup message if Plotly is not installed
    raise RuntimeError("Plotly is required. Install it with: pip install plotly") from exc

# ============================================================
# 1. PAGE CONFIGURATION + API CONFIGURATION
# ============================================================
try:  # Streamlit puts the script folder on sys.path
    import ui_components as ui
    import overview as ov
    import model_page as mp
except ImportError:  # pragma: no cover - e.g. run from another working directory
    from frontend import ui_components as ui
    from frontend import overview as ov
    from frontend import model_page as mp

st.set_page_config(
    page_title="CompPhish | Security Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_BASE_URL = os.getenv(
    "API_URL",
    "https://compphishapi.onrender.com"
).strip().rstrip("/")
API_URL = f"{API_BASE_URL}/scan"
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "90"))

# ============================================================
# 2. FLAGSHIP DARK UI
# ============================================================
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700;800&display=swap');

    :root {
      --bg: #090b10; --panel: #10141d; --panel2: #131925;
      --line: rgba(155,170,198,.14); --muted: #8792a8;
      --text: #edf2fb; --violet: #8b7cff; --cyan: #53d8e8;
      --green: #57d6a1; --red: #ff6e83; --amber: #f6bd60;
    }
    html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
    .stApp { background: radial-gradient(ellipse at 50% -20%, #1a2040 0%, #0b0e16 42%, #090b10 78%); color: var(--text); }
    [data-testid="stHeader"] { background: rgba(9,11,16,.78); }
    /* Hide unnecessary menu and footer */
#MainMenu,
footer {
    visibility: hidden;
    height: 0;
}

/* Keep Streamlit toolbar visible */
[data-testid="stToolbar"] {
    visibility: visible !important;
}

/* Keep sidebar reopening button visible */
[data-testid="stSidebarCollapsedControl"] {
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
}
    [data-testid="stDecoration"] { display:none; }
    .block-container { max-width: 1450px; padding: 3.4rem 2.4rem 3rem; }
    [data-testid="stPlotlyChart"] { background:linear-gradient(145deg,rgba(20,26,38,.88),rgba(14,18,27,.92));border:1px solid var(--line);border-radius:16px;padding:10px 8px 4px; }
    .info-key, .metric-foot, .section-meta { color:#9aa6bd; }
    .empty-state { text-align:center;color:#9aa6bd;font-size:13px;line-height:1.7;padding:46px 12px; }
    [data-testid="stSidebar"] { background: linear-gradient(180deg,#10141d 0%,#0c1017 100%); border-right:1px solid var(--line); }
    [data-testid="stSidebar"] > div:first-child { padding-top: 1.5rem; }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:var(--muted); }
    .brand { display:flex; align-items:center; gap:12px; padding:8px 4px 26px; border-bottom:1px solid var(--line); margin-bottom:22px; }
    .brand-mark { width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#8274ff,#46d6e6);box-shadow:0 0 28px rgba(126,112,255,.25);font-size:19px; }
    .brand-name { color:var(--text);font-weight:800;font-size:16px;letter-spacing:-.4px; }
    .brand-sub { color:#758198;font:10px 'DM Mono',monospace;letter-spacing:1.5px;margin-top:3px; }
    .side-label { color:#66728a;font:10px 'DM Mono',monospace;letter-spacing:1.8px;text-transform:uppercase;margin:18px 0 8px 5px; }
    .side-note { border:1px solid var(--line);border-radius:12px;padding:13px;background:rgba(255,255,255,.025);font-size:12px;color:var(--muted);line-height:1.6;margin-top:20px; }
    .topline { display:flex;justify-content:space-between;align-items:center;margin:2px 0 28px;gap:16px; }
    .eyebrow { color:#8995b0;font:10px 'DM Mono',monospace;letter-spacing:2px;text-transform:uppercase; }
    .page-title { color:var(--text);font-size:clamp(27px,3vw,38px);font-weight:800;letter-spacing:-1.5px;margin:7px 0 4px; }
    .page-sub { color:var(--muted);font-size:13px; }
    .live-pill { border:1px solid rgba(87,214,161,.28);background:rgba(87,214,161,.08);color:#79e2b5;border-radius:99px;padding:7px 11px;font:10px 'DM Mono',monospace;letter-spacing:1px;white-space:nowrap; }
    .metric-card { position:relative;overflow:hidden;background:linear-gradient(145deg,rgba(24,31,46,.94),rgba(15,20,30,.94));border:1px solid var(--line);border-radius:16px;padding:18px 19px;min-height:122px;transition:all .22s ease; }
    .metric-card:hover { border-color:rgba(139,124,255,.48);box-shadow:0 12px 36px rgba(0,0,0,.22),0 0 24px rgba(139,124,255,.08);transform:translateY(-2px); }
    .metric-label { color:var(--muted);font-size:11px;letter-spacing:.5px; }
    .metric-value { color:var(--text);font-size:27px;font-weight:800;letter-spacing:-1px;margin:10px 0 3px; }
    .metric-foot { color:#6f7c94;font:10px 'DM Mono',monospace; }
    .metric-accent { position:absolute;right:17px;top:17px;width:7px;height:7px;border-radius:50%;background:var(--cyan);box-shadow:0 0 14px var(--cyan); }
    .section-head { display:flex;justify-content:space-between;align-items:center;margin:29px 0 12px; }
    .section-title { color:#e8edf8;font-size:14px;font-weight:700;letter-spacing:-.2px; }
    .section-meta { color:#748099;font:10px 'DM Mono',monospace;letter-spacing:.8px; }
    .surface { background:linear-gradient(145deg,rgba(20,26,38,.88),rgba(14,18,27,.92));border:1px solid var(--line);border-radius:16px;padding:18px; }
    .scanner-box { background:linear-gradient(135deg,rgba(24,30,46,.95),rgba(14,19,29,.96));border:1px solid rgba(139,124,255,.26);border-radius:18px;padding:20px;box-shadow:0 12px 42px rgba(0,0,0,.18); }
    div[data-testid="stTextInput"] input { background:#0d121c!important;color:#eef2fb!important;border:1px solid rgba(155,170,198,.2)!important;border-radius:10px!important;min-height:46px; }
    div[data-testid="stTextInput"] input:focus { border-color:#8b7cff!important;box-shadow:0 0 0 1px #8b7cff!important; }
    div[data-testid="stForm"] { background:linear-gradient(135deg,rgba(24,30,46,.95),rgba(14,19,29,.96));border:1px solid rgba(139,124,255,.26)!important;border-radius:18px;padding:20px; }
    div[data-testid="stFormSubmitButton"] button, div.stButton>button { background:linear-gradient(100deg,#8b7cff,#6d9cff)!important;color:#090b10!important;border:0!important;border-radius:10px!important;font-weight:800!important;min-height:44px;transition:all .2s ease; }
    div[data-testid="stFormSubmitButton"] button:hover, div.stButton>button:hover { box-shadow:0 0 24px rgba(139,124,255,.28);filter:brightness(1.08);transform:translateY(-1px); }
    .result-hero { background:linear-gradient(130deg,rgba(27,34,52,.98),rgba(15,20,31,.98));border:1px solid var(--line);border-radius:18px;padding:22px; }
    .risk-kicker { color:#8995ad;font:10px 'DM Mono',monospace;letter-spacing:1.8px;text-transform:uppercase; }
    .risk-number { font-size:48px;font-weight:800;letter-spacing:-2px;line-height:1.1;margin:10px 0 6px; }
    .status-tag { display:inline-block;padding:7px 11px;border-radius:7px;font:10px 'DM Mono',monospace;letter-spacing:1px;margin-top:10px; }
    .tag-bad { color:#ff91a0;background:rgba(255,110,131,.1);border:1px solid rgba(255,110,131,.25); }
    .tag-good { color:#75e3b5;background:rgba(87,214,161,.1);border:1px solid rgba(87,214,161,.25); }
    .tag-warn { color:#f5c451;background:rgba(245,196,81,.1);border:1px solid rgba(245,196,81,.25); }
    .branch-tile { background:rgba(255,255,255,.025);border:1px solid var(--line);border-radius:13px;padding:15px; }
    .branch-title { color:#8995ad;font:10px 'DM Mono',monospace;letter-spacing:1px; }
    .branch-num { color:#edf2fb;font-size:24px;font-weight:800;margin-top:8px; }
    .branch-track { height:4px;border-radius:8px;background:#242c3b;margin-top:11px;overflow:hidden; }
    .branch-fill { height:100%;border-radius:8px;background:linear-gradient(90deg,#8b7cff,#53d8e8); }
    .info-row { display:flex;justify-content:space-between;gap:16px;padding:11px 0;border-bottom:1px solid var(--line);font-size:12px; }
    .info-row:last-child { border-bottom:0; }
    .info-key { color:var(--muted); }
    .info-val { color:#e5eaf5;text-align:right;overflow-wrap:anywhere; }
    .notice { color:#748099;font-size:10px;line-height:1.7;text-align:center;margin:26px 0 5px; }
    .demo-chip { display:inline-block;color:#f4c879;background:rgba(246,189,96,.08);border:1px solid rgba(246,189,96,.2);border-radius:6px;padding:4px 7px;font:9px 'DM Mono',monospace;letter-spacing:.8px; }
    .stAlert { border-radius:12px!important; }
    [data-testid="stExpander"] { background:rgba(255,255,255,.025);border:1px solid var(--line);border-radius:12px; }
    [data-testid="stMetric"] { background:transparent; }
    @media(max-width:800px){.live-pill{white-space:normal}.block-container{padding:3rem 1rem 2rem}.page-title{font-size:27px}.topline{align-items:flex-start}.risk-number{font-size:40px}}
    </style>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# 3. HELPERS
# ============================================================
def normalise_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Enter a website URL to scan.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname or "." not in parsed.hostname:
        raise ValueError("Enter a valid website hostname, such as example.com.")
    return value


def probability(value: Any, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {label} returned by the API.") from exc
    if not math.isfinite(number) or not 0 <= number <= 1:
        raise ValueError(f"{label} must be between 0 and 1.")
    return number


def scan_website(url: str, include_preview: bool = False) -> dict[str, Any]:
    try:
        response = requests.post(API_URL, json={"url": url, "include_preview": include_preview}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.exceptions.Timeout as exc:
        raise RuntimeError("The scan timed out. Try again in a moment.") from exc
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(f"Cannot reach the API at {API_URL}. Check that FastAPI is running.") from exc
    except requests.exceptions.HTTPError as exc:
        try:
            detail = response.json()
        except ValueError:
            detail = response.text[:500]
        raise RuntimeError(f"Backend returned HTTP {response.status_code}: {detail}") from exc
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Request failed: {exc}") from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError("The backend did not return valid JSON.") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Unexpected API response format.")
    required = {"prediction", "hybrid_probability", "risk_score", "threshold", "branch_probabilities"}
    missing = required - data.keys()
    if missing:
        raise RuntimeError("API response missing fields: " + ", ".join(sorted(missing)))
    if not isinstance(data["branch_probabilities"], dict):
        raise RuntimeError("branch_probabilities must be a JSON object.")
    return data


def esc(value: Any) -> str:
    return html.escape("—" if value is None or value == "" else str(value))


def rows_html(rows: list[tuple[str, Any]]) -> str:
    return "<div class='surface'>" + "".join(
        f"<div class='info-row'><span class='info-key'>{html.escape(k)}</span><span class='info-val'>{esc(v)}</span></div>"
        for k, v in rows
    ) + "</div>"


def section(title: str, meta: str = "") -> None:
    st.markdown(f"<div class='section-head'><div class='section-title'>{html.escape(title)}</div><div class='section-meta'>{html.escape(meta)}</div></div>", unsafe_allow_html=True)


def submit_report(url: str, category: str, comment: str) -> dict[str, Any]:
    try:
        resp = requests.post(f"{API_BASE_URL}/report", json={"url": url, "category": category, "comment": comment}, timeout=15)
        if resp.status_code == 429:
            raise RuntimeError("Too many reports from your network. Try again later.")
        resp.raise_for_status()
        return resp.json()["community_reports"]
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Could not send the report: {exc}") from exc


def render_scan_details(data: dict[str, Any]) -> None:
    """Evidence panels shown below the model breakdown (all text is HTML-escaped)."""
    st.markdown(f"<style>{ui.CSS}</style>", unsafe_allow_html=True)

    # --- What we checked + next steps -----------------------------------
    explanation = data.get("explanation")
    explanation = explanation if isinstance(explanation, list) else []
    if explanation:
        section("What we checked", "EVIDENCE BEHIND THE VERDICT")
        items = "".join(f"<div class='info-row'><span class='info-val' style='text-align:left'>{esc(x)}</span></div>" for x in explanation)
        st.markdown(f"<div class='surface'>{items}</div>", unsafe_allow_html=True)
    steps = data.get("next_steps")
    steps = steps if isinstance(steps, list) else []
    if steps:
        section("Recommended next steps", "GUIDANCE")
        items = "".join(f"<div class='info-row'><span class='info-val' style='text-align:left'>• {esc(x)}</span></div>" for x in steps)
        st.markdown(f"<div class='surface'>{items}</div>", unsafe_allow_html=True)

    tls_html = ui.connection_card(data.get("tls"))
    domain_html = ui.domain_card(data.get("trust_signals"))
    threat_html = ui.threat_card(data.get("threat_feeds"))
    behaviour_html = ui.behaviour_card(data.get("page_behaviour"))

    # --- Preview beside connection, domain, threat intel and behaviour ----
    if data.get("preview_url"):
        section("Site preview and security evidence", "SCREENSHOT BY THUM.IO (THIRD PARTY) · TLS · RDAP · THREAT FEEDS · PAGE HTML")
        left, right = st.columns([1.15, 1], gap="medium")
        with left:
            st.markdown(ui.preview_card(data["preview_url"]), unsafe_allow_html=True)
        with right:
            st.markdown(tls_html + domain_html + threat_html + behaviour_html, unsafe_allow_html=True)
    else:
        section("Connection and domain", "TLS CERTIFICATE · RDAP REGISTRATION RECORD")
        left, right = st.columns(2, gap="medium")
        with left:
            st.markdown(tls_html, unsafe_allow_html=True)
        with right:
            st.markdown(domain_html, unsafe_allow_html=True)
        section("Threat intelligence and page behaviour", "'NO MATCH' IS NOT 'SAFE'")
        t1, t2 = st.columns(2, gap="medium")
        with t1:
            st.markdown(threat_html, unsafe_allow_html=True)
        with t2:
            st.markdown(behaviour_html, unsafe_allow_html=True)

    # --- Navigation / redirects -----------------------------------------
    chain = data.get("redirect_chain")
    chain = [h for h in chain if isinstance(h, dict)] if isinstance(chain, list) else []
    if chain:
        section("Navigation path", f"{max(len(chain) - 1, 0)} REDIRECT(S)")
        st.markdown(rows_html([(f"Step {i + 1} · HTTP {h.get('status')}", h.get("url")) for i, h in enumerate(chain)]), unsafe_allow_html=True)

    # --- Statistics + server location ------------------------------------
    stats = ui._d(data.get("statistics"))
    net = ui._d(data.get("network_footprint"))
    section("Statistics and server location", "FETCHED BY THE SCANNER · TEAM CYMRU DNS")
    s1, s2 = st.columns([1.6, 1], gap="medium")
    with s1:
        st.markdown(ui.stats_grid(stats, net), unsafe_allow_html=True)
    with s2:
        st.markdown(ui.location_card(data.get("server_location")), unsafe_allow_html=True)

    section("Brand lookalike and score explanation", "HEURISTIC CHECK · WHAT THE MODEL BASED ITS SCORE ON")
    b1, b2 = st.columns([1, 2], gap="medium")
    with b1:
        st.markdown(ui.brand_card(data.get("brand_check")), unsafe_allow_html=True)
    with b2:
        st.markdown(ui.explain_card(data.get("model_explanation")), unsafe_allow_html=True)

    section("Network footprint", "ESTIMATED FROM PAGE HTML · NOT A BROWSER TRACE")
    ext = ", ".join(str(d) for d in (net.get("external_domains") or []) if isinstance(d, str)) or None
    st.markdown(rows_html([("Domains referenced", net.get("domains")), ("IP addresses", net.get("ips")), ("Outbound links", net.get("links")), ("External domains", ext)]), unsafe_allow_html=True)

    # --- Community reports ---------------------------------------------
    section("Community reports", "OPINIONS, NOT VERIFIED EVIDENCE")
    cr = ui._d(st.session_state.get("last_reports") or data.get("community_reports"))
    st.markdown(rows_html([("Reports on this page", cr.get("total", 0)), ("Marked scam", cr.get("scam", 0)), ("Marked safe", cr.get("safe", 0)), ("Other", cr.get("other", 0))]), unsafe_allow_html=True)
    for r in cr.get("recent") or []:
        if isinstance(r, dict) and r.get("comment"):
            st.caption(f"{r.get('category', '').upper()}: {r['comment']}")
    with st.form("report_form", clear_on_submit=True):
        cat = st.selectbox("Report this page as", ["scam", "safe", "other"])
        note = st.text_input("Optional comment (max 300 characters)", max_chars=300)
        if st.form_submit_button("Leave a report"):
            try:
                st.session_state["last_reports"] = submit_report(data.get("final_url") or data.get("submitted_url", ""), cat, note)
                st.success("Thanks, your report was saved.")
            except RuntimeError as exc:
                st.error(str(exc))


def plot_layout(fig: go.Figure, height: int = 270) -> go.Figure:
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="DM Sans", color="#9aa6bd", size=11),
        margin=dict(l=8, r=8, t=14, b=8),
        legend=dict(orientation="h", y=1.12, x=0, font=dict(size=10)),
        hoverlabel=dict(bgcolor="#171e2b", bordercolor="#39445a", font=dict(color="#edf2fb")),
    )
    fig.update_xaxes(showgrid=False, zeroline=False, color="#748099")
    fig.update_yaxes(showgrid=True, gridcolor="rgba(155,170,198,.09)", zeroline=False, color="#748099")
    return fig


def metric_card(label: str, value: str, foot: str, accent: str = "#53d8e8") -> str:
    return f"""<div class='metric-card'><span class='metric-accent' style='background:{accent};box-shadow:0 0 14px {accent}'></span><div class='metric-label'>{label}</div><div class='metric-value'>{value}</div><div class='metric-foot'>{foot}</div></div>"""

def go_to_scanner() -> None:
    st.session_state["page"] = "Live scanner"


def scanner_section(key: str, title: str = "Run a live website assessment", compact: bool = False) -> None:
    """URL form plus the result of the last scan. `key` keeps widget ids unique per page.
    compact=True (Overview): short form and a one-line verdict, with a button to the full report."""
    section(title, "QUICK CHECK" if compact else "FASTAPI · POST /SCAN")
    with st.form(f"live_scan_form_{key}", clear_on_submit=False):
        url_input = st.text_input("Website URL", placeholder="https://example.com", label_visibility="collapsed")
        want_preview = False if compact else st.checkbox("Also show a site screenshot (sends the address to the third-party service thum.io)", value=False)
        scan_clicked = st.form_submit_button("Check website  →" if compact else "Analyse website  →", use_container_width=True)
    st.markdown("<div style='color:#8792a8;font-size:11px;margin-top:7px'>Only scan websites you are authorised to assess. Do not submit credentials or sensitive URLs.</div>", unsafe_allow_html=True)

    if scan_clicked:
        try:
            clean_url = normalise_url(url_input)
            with st.spinner("Retrieving page and evaluating model signals…"):
                scan_data = scan_website(clean_url, want_preview)
            st.session_state.pop("last_reports", None)
            st.session_state["last_scan"] = scan_data
            st.session_state["scan_history"] = ov.record_scan(st.session_state.get("scan_history"), scan_data, clean_url)
            st.session_state["last_submitted_url"] = clean_url
            st.session_state.pop("last_scan_error", None)
        except (ValueError, RuntimeError) as exc:
            st.session_state.pop("last_scan", None)
            st.session_state["last_scan_error"] = str(exc)

    if st.session_state.get("last_scan_error"):
        st.error(st.session_state["last_scan_error"])

    if compact:
        strip = ov.compact_result_html(st.session_state.get("last_scan"), st.session_state.get("last_submitted_url", ""))
        if strip:
            st.markdown(strip, unsafe_allow_html=True)
            st.button("View full report  →", key=f"full_report_{key}", on_click=go_to_scanner)
        return

    if "last_scan" in st.session_state:
        data = st.session_state["last_scan"]
        try:
            pred = str(data["prediction"]).strip().upper()
            if pred not in {"PHISHING", "LEGITIMATE", "NEEDS_REVIEW", "LIKELY_LEGITIMATE"}:
                raise ValueError("Unexpected prediction label from API.")
            hybrid = probability(data["hybrid_probability"], "Hybrid probability")
            threshold = probability(data["threshold"], "Decision threshold")
            risk = float(data["risk_score"])
            if not math.isfinite(risk) or not 0 <= risk <= 100:
                raise ValueError("Risk score must be between 0 and 100.")
            branches = data["branch_probabilities"]
            branch_values = {k: probability(branches.get(k), f"{k} probability") for k in ("url", "html", "text")}
        except (TypeError, ValueError) as exc:
            st.error(f"Unable to display API response: {exc}")
            return

        phishing = pred == "PHISHING"
        review = pred == "NEEDS_REVIEW"
        tint = "#ff6e83" if phishing else ("#f5c451" if review else "#57d6a1")
        badge = "tag-bad" if phishing else ("tag-warn" if review else "tag-good")
        status_text = {
            "PHISHING": "PHISHING DETECTED",
            "NEEDS_REVIEW": "NEEDS REVIEW - UNCERTAIN",
            "LIKELY_LEGITIMATE": "LIKELY LEGITIMATE",
            "LEGITIMATE": "CLASSIFIED AS LEGITIMATE",
        }[pred]
        raw_label = "RAW MODEL SCORE" if data.get("model_prediction") not in (None, pred) else "HYBRID PHISHING PROBABILITY"
        submitted = html.escape(str(data.get("submitted_url", st.session_state.get("last_submitted_url", "—"))))
        final_url = html.escape(str(data.get("final_url", data.get("url", "—"))))
        content_type = html.escape(str(data.get("content_type", "—")))
        html_size = html.escape(str(data.get("html_size", "—")))

        st.markdown("<div class='section-head'><div class='section-title'>Assessment result</div><div class='section-meta'>LIVE MODEL RESPONSE</div></div>", unsafe_allow_html=True)
        result_cols = st.columns([1.25, 1], gap="large")
        with result_cols[0]:
            st.markdown(f"<div class='result-hero'><div class='risk-kicker'>{raw_label}</div><div class='risk-number' style='color:{tint}'>{hybrid*100:.2f}%</div><div style='color:#8b97ad;font-size:12px'>Risk score {risk:.2f}% · Decision threshold {threshold*100:.0f}%</div><span class='status-tag {badge}'>{status_text}</span></div>", unsafe_allow_html=True)
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
            st.progress(risk / 100)
            if data.get("decision_note"):
                st.info(str(data["decision_note"]))
        with result_cols[1]:
            gauge = go.Figure(go.Indicator(mode="gauge+number", value=risk, number={"suffix": "%", "font": {"color": "#edf2fb", "size": 29}}, gauge={"axis": {"range": [0, 100], "tickcolor": "#748099", "tickfont": {"color": "#748099"}}, "bar": {"color": tint, "thickness": .22}, "bgcolor": "rgba(0,0,0,0)", "borderwidth": 0, "steps": [{"range": [0, 40], "color": "rgba(83,216,232,.08)"}, {"range": [40, 70], "color": "rgba(139,124,255,.10)"}, {"range": [70, 100], "color": "rgba(255,110,131,.10)"}]}))
            st.plotly_chart(plot_layout(gauge, 220), use_container_width=True, config={"displayModeBar": False})
        st.markdown("<div class='section-head'><div class='section-title'>Branch signal breakdown</div><div class='section-meta'>MODEL OUTPUTS · PROBABILITY</div></div>", unsafe_allow_html=True)
        bcols = st.columns(3, gap="medium")
        for col, (name, key) in zip(bcols, [("URL INTELLIGENCE", "url"), ("HTML STRUCTURE", "html"), ("PAGE TEXT", "text")]):
            val = branch_values[key] * 100
            with col:
                st.markdown(f"<div class='branch-tile'><div class='branch-title'>{name}</div><div class='branch-num'>{val:.2f}%</div><div class='branch-track'><div class='branch-fill' style='width:{val:.2f}%'></div></div></div>", unsafe_allow_html=True)

        st.markdown("<div class='section-head'><div class='section-title'>Retrieved page metadata</div><div class='section-meta'>SCAN DETAILS</div></div>", unsafe_allow_html=True)
        st.markdown(f"<div class='surface'><div class='info-row'><span class='info-key'>Submitted URL</span><span class='info-val'>{submitted}</span></div><div class='info-row'><span class='info-key'>Final URL</span><span class='info-val'>{final_url}</span></div><div class='info-row'><span class='info-key'>Content type</span><span class='info-val'>{content_type}</span></div><div class='info-row'><span class='info-key'>HTML retrieved</span><span class='info-val'>{html_size} bytes</span></div></div>", unsafe_allow_html=True)
        render_scan_details(data)
        with st.expander("Model response details"):
            st.json(data)


@st.cache_data(ttl=30, show_spinner=False)
def _api_status(base_url: str) -> dict:
    return ov.check_api(base_url)


@st.cache_data(ttl=300, show_spinner=False)
def _model_info(base_url: str):
    try:
        r = requests.get(base_url + "/model-info", timeout=8)
        r.raise_for_status()
        return mp.validate_info(r.json())
    except Exception:
        return None


API_STATUS = _api_status(API_BASE_URL)
_b = API_STATUS.get("bands") or {}
API_STATUS_LOW = float(_b.get("legitimate_below", 0.40))
API_STATUS_HIGH = float(_b.get("phishing_at_or_above", 0.85))

# ============================================================
# 4. SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown(
        "<div class='brand'><div class='brand-mark'>⌁</div><div><div class='brand-name'>CompPhish</div><div class='brand-sub'>SECURITY INTELLIGENCE</div></div></div>",
        unsafe_allow_html=True,
    )
    st.markdown("<div class='side-label'>WORKSPACE</div>", unsafe_allow_html=True)
    page = st.radio("Navigation", ["Overview", "Live scanner", "Model intelligence"], key="page", label_visibility="collapsed")
    st.markdown("<div class='side-label'>SYSTEM</div>", unsafe_allow_html=True)
    st.markdown(
        f"<div class='side-note'><b style='color:#e9eef8'>API endpoint</b><br><span style='font-family:DM Mono;font-size:10px'>{html.escape(API_BASE_URL)}</span><br><br>{ov.status_html(API_STATUS)}</div>",
        unsafe_allow_html=True,
    )
    st.markdown("<div class='side-note'>CompPhish analyses URL structure, HTML structure and page text using the currently configured hybrid model.</div>", unsafe_allow_html=True)

# ============================================================
# 5. HEADER
# ============================================================
st.markdown(
    f"<div class='topline'><div><div class='eyebrow'>THREAT MONITORING / COMPPHISH</div><div class='page-title'>Website Security Intelligence</div><div class='page-sub'>A multi-layer view of web risk, signals and model decisions.</div></div><div class='live-pill'>{ov.status_html(API_STATUS)}</div></div>",
    unsafe_allow_html=True,
)

# ============================================================
# 6. OVERVIEW PAGE (real data only)
# ============================================================
if page == "Overview":
    scanner_section("overview", "Check a website", compact=True)
    history = st.session_state.get("scan_history") or []
    summary = ov.summarise_history(history)
    eval_summary = ov.load_eval_summary()

    section("Session summary", "REAL SCANS YOU RAN IN THIS BROWSER SESSION")
    for col, card in zip(st.columns(4, gap="medium"), ov.stat_cards(summary, eval_summary)):
        with col:
            st.markdown(card, unsafe_allow_html=True)

    section("Scan activity", "THIS SESSION")
    chart_col, donut_col = st.columns([1.65, 1], gap="large")
    with chart_col:
        if history:
            ordered = list(reversed(history))
            fig = go.Figure(go.Scatter(
                x=list(range(1, len(ordered) + 1)), y=[h["risk"] for h in ordered],
                mode="lines+markers", line=dict(color="#53d8e8", width=2.5), marker=dict(size=7, color=[ov.VERDICT_COLOUR[h["verdict"]] for h in ordered]),
                text=[ov.esc(h["url"]) for h in ordered], hovertemplate="%{text}<br>Risk %{y:.1f}%<extra></extra>"))
            fig.update_layout(xaxis_title="Scan number (oldest to newest)", yaxis_title="Risk score (%)", showlegend=False)
            fig.update_yaxes(range=[0, 100])
            fig.add_hline(y=85, line_dash="dot", line_color="rgba(255,110,131,.45)", annotation_text="phishing band", annotation_font_color="#ff91a0")
            fig.add_hline(y=40, line_dash="dot", line_color="rgba(83,216,232,.4)", annotation_text="legitimate band", annotation_font_color="#7fe3ef")
            st.plotly_chart(plot_layout(fig, 320), use_container_width=True, config={"displayModeBar": False, "responsive": True})
        else:
            st.markdown("<div class='surface'><div class='empty-state'>No scans yet.<br>Run a scan above and its risk score will be charted here.</div></div>", unsafe_allow_html=True)
    with donut_col:
        if history:
            labels = [ov.VERDICT_LABEL[v] for v in ov.VERDICTS if summary["counts"][v]]
            values = [summary["counts"][v] for v in ov.VERDICTS if summary["counts"][v]]
            colours = [ov.VERDICT_COLOUR[v] for v in ov.VERDICTS if summary["counts"][v]]
            donut = go.Figure(go.Pie(labels=labels, values=values, hole=.7, sort=False, marker=dict(colors=colours, line=dict(color="#111722", width=3)), textinfo="value", hovertemplate="%{label}: %{value} (%{percent})<extra></extra>"))
            donut.update_layout(showlegend=True, legend=dict(orientation="h", y=-.05, x=0), annotations=[dict(text=f"{summary['total']}<br>scans", x=.5, y=.5, showarrow=False, font=dict(size=16, color="#edf2fb", family="DM Sans"))])
            st.plotly_chart(plot_layout(donut, 320), use_container_width=True, config={"displayModeBar": False, "responsive": True})
        else:
            st.markdown("<div class='surface'><div class='empty-state'>Verdict mix appears<br>after your first scan.</div></div>", unsafe_allow_html=True)

    section("Recent scans", "NEWEST FIRST")
    st.markdown(ov.recent_scans_html(history), unsafe_allow_html=True)

    section("How to read a verdict", "FOUR OUTCOMES")
    for col, card in zip(st.columns(4, gap="medium"), ov.verdict_legend_cards()):
        with col:
            st.markdown(card, unsafe_allow_html=True)

    section("About the live model", "WHAT IS RUNNING")
    st.markdown(ov.model_card_html(API_STATUS_LOW, API_STATUS_HIGH, API_STATUS.get("model", ""), eval_summary), unsafe_allow_html=True)

elif page == "Live scanner":
    scanner_section("scanner")

# ============================================================
# 8. MODEL INTELLIGENCE PAGE
# ============================================================
elif page == "Model intelligence":
    info = _model_info(API_BASE_URL)
    eval_summary = ov.load_eval_summary()

    section("How a verdict is made", "FROM PAGE TO FINAL VERDICT")
    cards = mp.pipeline_cards()
    for row in (cards[:4], cards[4:]):
        for col, c in zip(st.columns(len(row), gap="medium"), row):
            with col:
                st.markdown(c, unsafe_allow_html=True)
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    if info is None:
        st.info("Model details are not available right now. The API may be waking up (try again in about 30 seconds) or it may be an older version without /model-info.")
    else:
        section("How much each signal counts", "FUSION MODEL WEIGHTS")
        wcol, bcol = st.columns([1.4, 1], gap="large")
        with wcol:
            if info["weights"]:
                st.markdown(mp.card("Fusion weights (log-odds per unit of branch probability)", mp.bars_html(info["weights"], "#8b7cff", "{:.2f}", 1.0),
                                    mp.weights_note(info["weights"])), unsafe_allow_html=True)
        with bcol:
            body = (f"<div style='color:#dce4f2;font-size:13px'>{mp.esc(info['name'])}</div>"
                    f"<div class='metric-foot' style='margin-top:8px'>URL: {info['url_features'] or '?'} features &middot; HTML: {info['html_features'] or '?'} features &middot; text: TF-IDF</div>"
                    f"<div class='metric-foot' style='margin-top:6px'>Legitimate below {info['low']:.2f} &middot; phishing at or above {info['high']:.2f}</div>"
                    + (f"<div class='metric-foot' style='margin-top:6px'>Retrained {mp.esc(info['trained_at'])} with unseen-domain splits</div>" if info["retrained"] else ""))
            st.markdown(mp.card("Live model", body), unsafe_allow_html=True)

        section("What each branch looks at", "FROM THE TRAINED MODELS")
        c1, c2, c3 = st.columns(3, gap="medium")
        with c1:
            st.markdown(mp.card("URL branch: top features", mp.bars_html(info["url"], "#53d8e8", "{:.1f}%", 100.0), "Share of the trees' decisions. Lengths and entropy describe URL shape, not meaning."), unsafe_allow_html=True)
        with c2:
            st.markdown(mp.card("HTML branch: feature importance", mp.bars_html(info["html"], "#8b7cff", "{:.1f}%", 100.0), mp.top_note(info["html"], "Counts such as links and tags also track page size.")), unsafe_allow_html=True)
        with c3:
            body = ("<div style='color:#ff91a0;font-size:11px;margin-bottom:2px'>Push toward phishing</div>" + mp.bars_html(info["terms_phish"][:6], "#ff6e83", "{:.1f}", 1.0)
                    + "<div style='color:#75e3b5;font-size:11px;margin:12px 0 2px'>Push toward legitimate</div>" + mp.bars_html(info["terms_legit"][:6], "#57d6a1", "{:.1f}", 1.0))
            st.markdown(mp.card("Text branch: strongest words", body, "Years or generic words in these lists would be dataset artefacts, not phishing behaviour."), unsafe_allow_html=True)

    section("Known limitations", "READ BEFORE TRUSTING A SCORE")
    st.markdown(mp.limitations_html(), unsafe_allow_html=True)

    section("Component status", "WHAT IS AND IS NOT IN THE LIVE APP")
    st.markdown(mp.status_table_html(info, eval_summary), unsafe_allow_html=True)

# ============================================================
# 9. FOOTER
# ============================================================
st.markdown("<div class='notice'>CompPhish is a research prototype. Model outputs are probabilistic estimates, not a guarantee of website safety. Overview figures count only the scans you run in this session.</div>", unsafe_allow_html=True)
