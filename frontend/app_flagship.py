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

# Demo metrics are synthetic UI preview data. They are never model results.S
DEMO_METRICS = {
    "scans": "2,481",
    "threats": "384",
    "avg_risk": "18.6%",
    "uptime": "99.9%",
}

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
    .block-container { max-width: 1450px; padding: 1.6rem 2.4rem 3rem; }
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
    div[data-testid="stForm"] { background:transparent;border:0;padding:0; }
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
    @media(max-width:800px){.block-container{padding:1.2rem 1rem 2rem}.page-title{font-size:27px}.topline{align-items:flex-start}.risk-number{font-size:40px}}
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
    # --- What we checked + next steps -----------------------------------
    explanation = data.get("explanation") or []
    if explanation:
        section("What we checked", "EVIDENCE BEHIND THE VERDICT")
        items = "".join(f"<div class='info-row'><span class='info-val' style='text-align:left'>{esc(x)}</span></div>" for x in explanation)
        st.markdown(f"<div class='surface'>{items}</div>", unsafe_allow_html=True)
    steps = data.get("next_steps") or []
    if steps:
        section("Recommended next steps", "GUIDANCE")
        items = "".join(f"<div class='info-row'><span class='info-val' style='text-align:left'>• {esc(x)}</span></div>" for x in steps)
        st.markdown(f"<div class='surface'>{items}</div>", unsafe_allow_html=True)

    # --- Site preview ----------------------------------------------------
    if data.get("preview_url"):
        section("Site preview", "SCREENSHOT BY THUM.IO (THIRD PARTY)")
        st.image(data["preview_url"], width=720)

    # --- Navigation / redirects -----------------------------------------
    chain = data.get("redirect_chain") or []
    if chain:
        section("Navigation path", f"{max(len(chain) - 1, 0)} REDIRECT(S)")
        st.markdown(rows_html([(f"Step {i + 1} · HTTP {h.get('status')}", h.get("url")) for i, h in enumerate(chain)]), unsafe_allow_html=True)

    # --- Connection security + domain ----------------------------------
    tls = data.get("tls") or {}
    trust = data.get("trust_signals") or {}
    c1, c2 = st.columns(2, gap="medium")
    with c1:
        section("Connection security", "TLS CERTIFICATE")
        if tls.get("status") == "ok" and tls.get("valid"):
            st.markdown(rows_html([("Certificate", "Valid"), ("Issuer", tls.get("issuer")), ("Issued to", tls.get("subject")), ("Valid until", tls.get("not_after")), ("Days left", tls.get("days_left")), ("Protocol", tls.get("protocol"))]), unsafe_allow_html=True)
        elif tls.get("status") == "ok":
            st.markdown(rows_html([("Certificate", "FAILED verification"), ("Reason", tls.get("error"))]), unsafe_allow_html=True)
        else:
            st.markdown(rows_html([("Certificate", "Could not be checked")]), unsafe_allow_html=True)
    with c2:
        section("Domain age", "RDAP REGISTRATION RECORD")
        age = trust.get("domain_age_days")
        st.markdown(rows_html([("Registered domain", trust.get("registered_domain")), ("Age", f"{age} days (~{age / 365:.1f} years)" if isinstance(age, (int, float)) else "Unknown"), ("Established", "Yes" if trust.get("established") else "No / unknown"), ("Shared hosting", "Yes" if trust.get("shared_hosting") else "No")]), unsafe_allow_html=True)

    # --- Threat intelligence + page behaviour ---------------------------
    t1, t2 = st.columns(2, gap="medium")
    with t1:
        section("Threat intelligence", "'NO MATCH' IS NOT 'SAFE'")
        feeds = (data.get("threat_feeds") or {}).get("sources") or []
        label = {"match": "LISTED", "no_match": "No match", "unavailable": "Unavailable"}
        st.markdown(rows_html([(f.get("name"), label.get(f.get("status"), f.get("status"))) for f in feeds] or [("Feeds", "Unavailable")]), unsafe_allow_html=True)
    with t2:
        section("Page behaviour", "FROM THE PAGE HTML")
        beh = data.get("page_behaviour") or {}
        found = beh.get("findings") or []
        st.markdown(rows_html([(f.get("severity", "").upper(), f.get("text")) for f in found] or [("Result", "Nothing significant found" if beh.get("status") == "ok" else "Could not be checked")]), unsafe_allow_html=True)

    # --- Statistics + server location + network footprint ---------------
    stats = data.get("statistics") or {}
    net = data.get("network_footprint") or {}
    loc = data.get("server_location") or {}
    s1, s2 = st.columns(2, gap="medium")
    with s1:
        section("Statistics", "FETCHED BY THE SCANNER")
        st.markdown(rows_html([("Page load", f"{stats.get('load_seconds')} s" if stats.get("load_seconds") is not None else None), ("HTTP status", stats.get("status_code")), ("HTML size", f"{stats.get('html_bytes')} bytes"), ("Resources referenced", net.get("resources")), ("HTTPS share of resources", f"{net.get('https_share')}%" if net.get("https_share") is not None else None), ("Cookies set", stats.get("cookies_set"))]), unsafe_allow_html=True)
    with s2:
        section("Server location", "TEAM CYMRU DNS")
        if loc.get("status") == "ok":
            st.markdown(rows_html([("IP address", loc.get("ip")), ("Country", loc.get("country")), ("ASN", f"{loc.get('asn')} ({loc.get('asn_name')})" if loc.get("asn_name") else loc.get("asn"))]), unsafe_allow_html=True)
        else:
            st.markdown(rows_html([("Location", "Could not be determined")]), unsafe_allow_html=True)
    section("Network footprint", "ESTIMATED FROM PAGE HTML · NOT A BROWSER TRACE")
    ext = ", ".join(net.get("external_domains") or []) or None
    st.markdown(rows_html([("Domains referenced", net.get("domains")), ("IP addresses", net.get("ips")), ("Outbound links", net.get("links")), ("External domains", ext)]), unsafe_allow_html=True)

    # --- Community reports ---------------------------------------------
    section("Community reports", "OPINIONS, NOT VERIFIED EVIDENCE")
    cr = st.session_state.get("last_reports") or data.get("community_reports") or {}
    st.markdown(rows_html([("Reports on this page", cr.get("total", 0)), ("Marked scam", cr.get("scam", 0)), ("Marked safe", cr.get("safe", 0)), ("Other", cr.get("other", 0))]), unsafe_allow_html=True)
    for r in cr.get("recent") or []:
        if r.get("comment"):
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

# ============================================================
# 4. SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown(
        "<div class='brand'><div class='brand-mark'>⌁</div><div><div class='brand-name'>CompPhish</div><div class='brand-sub'>SECURITY INTELLIGENCE</div></div></div>",
        unsafe_allow_html=True,
    )
    st.markdown("<div class='side-label'>WORKSPACE</div>", unsafe_allow_html=True)
    page = st.radio("Navigation", ["Overview", "Live scanner", "Model intelligence"], label_visibility="collapsed")
    st.markdown("<div class='side-label'>SYSTEM</div>", unsafe_allow_html=True)
    st.markdown(
        f"<div class='side-note'><b style='color:#e9eef8'>API endpoint</b><br><span style='font-family:DM Mono;font-size:10px'>{html.escape(API_BASE_URL)}</span><br><br><span style='color:#57d6a1'>●</span> Endpoint configured<br><span style='font-size:10px'>Connection is verified when a scan is submitted.</span></div>",
        unsafe_allow_html=True,
    )
    st.markdown("<div class='side-note'>CompPhish analyses URL structure, HTML structure and page text using the currently configured hybrid model.</div>", unsafe_allow_html=True)

# ============================================================
# 5. HEADER
# ============================================================
st.markdown(
    "<div class='topline'><div><div class='eyebrow'>THREAT MONITORING / COMPPhISH</div><div class='page-title'>Website Security Intelligence</div><div class='page-sub'>A multi-layer view of web risk, signals and model decisions.</div></div><div class='live-pill'>● LOCAL WORKSPACE</div></div>",
    unsafe_allow_html=True,
)

# ============================================================
# 6. OVERVIEW PAGE (synthetic dashboard preview)
# ============================================================
if page == "Overview":
    st.markdown("<span class='demo-chip'>ILLUSTRATIVE DASHBOARD DATA · NOT LIVE TELEMETRY</span>", unsafe_allow_html=True)
    cols = st.columns(4, gap="medium")
    cards = [
        ("TOTAL SCANS", DEMO_METRICS["scans"], "Synthetic preview volume", "#8b7cff"),
        ("THREATS FLAGGED", DEMO_METRICS["threats"], "Synthetic preview count", "#ff6e83"),
        ("AVERAGE RISK", DEMO_METRICS["avg_risk"], "Synthetic preview average", "#f6bd60"),
        ("SERVICE TARGET", DEMO_METRICS["uptime"], "Illustrative target only", "#57d6a1"),
    ]
    for col, (label, value, foot, accent) in zip(cols, cards):
        with col:
            st.markdown(metric_card(label, value, foot, accent), unsafe_allow_html=True)

    st.markdown("<div class='section-head'><div class='section-title'>Detection activity</div><div class='section-meta'>SAMPLE SERIES · LAST 7 DAYS</div></div>", unsafe_allow_html=True)
    chart_col, donut_col = st.columns([1.65, 1], gap="large")
    with chart_col:
        # Clearly synthetic sample series for the dashboard preview.
        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        safe = [182, 205, 194, 231, 218, 247, 239]
        flagged = [24, 31, 28, 39, 34, 42, 37]
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=days, y=safe, name="Low-risk", mode="lines+markers", line=dict(color="#53d8e8", width=2.5), marker=dict(size=5), fill="tozeroy", fillcolor="rgba(83,216,232,.08)"))
        fig.add_trace(go.Scatter(x=days, y=flagged, name="Flagged", mode="lines+markers", line=dict(color="#ff6e83", width=2.5), marker=dict(size=5), fill="tozeroy", fillcolor="rgba(255,110,131,.08)"))
        fig.update_layout(hovermode="x unified")
        st.markdown("<div class='surface'>", unsafe_allow_html=True)
        st.plotly_chart(plot_layout(fig, 300), use_container_width=True, config={"displayModeBar": False, "responsive": True})
        st.markdown("</div>", unsafe_allow_html=True)
    with donut_col:
        donut = go.Figure(go.Pie(labels=["Low risk", "Elevated", "High risk"], values=[71, 18, 11], hole=.76, sort=False, marker=dict(colors=["#53d8e8", "#8b7cff", "#ff6e83"], line=dict(color="#111722", width=3)), textinfo="none", hovertemplate="%{label}: %{percent}<extra></extra>"))
        donut.update_layout(showlegend=True, legend=dict(orientation="h", y=-.08, x=.02), annotations=[dict(text="Risk<br>mix", x=.5, y=.5, showarrow=False, font=dict(size=16, color="#edf2fb", family="DM Sans"))])
        st.markdown("<div class='surface'>", unsafe_allow_html=True)
        st.plotly_chart(plot_layout(donut, 300), use_container_width=True, config={"displayModeBar": False, "responsive": True})
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='section-head'><div class='section-title'>Intelligence layers</div><div class='section-meta'>CURRENT MODEL CONFIGURATION</div></div>", unsafe_allow_html=True)
    layer_cols = st.columns(3, gap="medium")
    layer_info = [("01 / URL INTELLIGENCE", "Hostname, path, query and lexical URL signals", "28 engineered features"), ("02 / HTML STRUCTURE", "Forms, inputs, scripts and anchor structure", "6 structural features"), ("03 / PAGE TEXT", "Page text represented for text classification", "TF-IDF text branch")]
    for col, (title, desc, foot) in zip(layer_cols, layer_info):
        with col:
            st.markdown(f"<div class='surface'><div class='eyebrow'>{title}</div><p style='color:#dce4f2;font-size:13px;margin:13px 0 9px'>{desc}</p><div class='metric-foot'>{foot}</div></div>", unsafe_allow_html=True)

# ============================================================
# 7. LIVE SCANNER
# ============================================================
elif page == "Live scanner":
    st.markdown("<div class='section-head'><div class='section-title'>Run a live website assessment</div><div class='section-meta'>FASTAPI · POST /SCAN</div></div>", unsafe_allow_html=True)
    st.markdown("<div class='scanner-box'>", unsafe_allow_html=True)
    with st.form("live_scan_form", clear_on_submit=False):
        url_input = st.text_input("Website URL", placeholder="https://example.com", label_visibility="collapsed")
        want_preview = st.checkbox("Also show a site screenshot (sends the address to the third-party service thum.io)", value=False)
        scan_clicked = st.form_submit_button("Analyse website  →", use_container_width=True)
    st.markdown("<div style='color:#77839b;font-size:10px;margin-top:7px'>Only scan websites you are authorised to assess. Do not submit credentials or sensitive URLs.</div></div>", unsafe_allow_html=True)

    if scan_clicked:
        try:
            clean_url = normalise_url(url_input)
            with st.spinner("Retrieving page and evaluating model signals…"):
                scan_data = scan_website(clean_url, want_preview)
            st.session_state.pop("last_reports", None)
            st.session_state["last_scan"] = scan_data
            st.session_state["last_submitted_url"] = clean_url
            st.session_state.pop("last_scan_error", None)
        except (ValueError, RuntimeError) as exc:
            st.session_state.pop("last_scan", None)
            st.session_state["last_scan_error"] = str(exc)

    if st.session_state.get("last_scan_error"):
        st.error(st.session_state["last_scan_error"])

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
            st.stop()

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
            st.markdown("<div class='surface'>", unsafe_allow_html=True)
            st.plotly_chart(plot_layout(gauge, 220), use_container_width=True, config={"displayModeBar": False})
            st.markdown("</div>", unsafe_allow_html=True)

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

# ============================================================
# 8. MODEL INTELLIGENCE PAGE
# ============================================================
elif page == "Model intelligence":
    st.markdown("<div class='section-head'><div class='section-title'>Model architecture</div><div class='section-meta'>IMPLEMENTED IN CURRENT BUNDLE</div></div>", unsafe_allow_html=True)
    st.info("This view describes the currently configured three-branch CompPhish model. Domain intelligence, graph intelligence, GA feature selection, fuzzy logic and SHAP are not represented as implemented components here.")
    architecture = go.Figure(go.Sankey(
        arrangement="snap",
        node=dict(pad=24, thickness=18, line=dict(color="rgba(155,170,198,.25)", width=1), label=["URL features", "HTML features", "Page text", "URL model", "HTML model", "Text model", "Fusion model", "Prediction"], color=["#4c8caa", "#766bd1", "#368e91", "#4c8caa", "#766bd1", "#368e91", "#8b7cff", "#57d6a1"]),
        link=dict(source=[0,1,2,3,4,5,6], target=[3,4,5,6,6,6,7], value=[1,1,1,1,1,1,3], color=["rgba(83,216,232,.25)","rgba(139,124,255,.25)","rgba(87,214,161,.22)","rgba(83,216,232,.3)","rgba(139,124,255,.3)","rgba(87,214,161,.3)","rgba(139,124,255,.35)"]),
    ))
    st.markdown("<div class='surface'>", unsafe_allow_html=True)
    st.plotly_chart(plot_layout(architecture, 390), use_container_width=True, config={"displayModeBar": False})
    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("<div class='section-head'><div class='section-title'>Implementation boundary</div><div class='section-meta'>TRANSPARENT STATUS</div></div>", unsafe_allow_html=True)
    status_cols = st.columns(2, gap="medium")
    with status_cols[0]:
        st.markdown("<div class='surface'><div style='color:#57d6a1;font-weight:700;margin-bottom:10px'>● Implemented</div><div style='color:#cbd4e5;font-size:12px;line-height:2'>URL feature branch<br>HTML structural branch<br>Page-text branch<br>Hybrid fusion / stacking<br>Threshold-based classification</div></div>", unsafe_allow_html=True)
    with status_cols[1]:
        st.markdown("<div class='surface'><div style='color:#f6bd60;font-weight:700;margin-bottom:10px'>○ Proposed / pending verification</div><div style='color:#cbd4e5;font-size:12px;line-height:2'>Domain intelligence<br>Graph intelligence<br>Genetic Algorithm feature selection<br>Fuzzy decision layer<br>SHAP explanations</div></div>", unsafe_allow_html=True)

# ============================================================
# 9. FOOTER
# ============================================================
st.markdown("<div class='notice'>CompPhish is a research prototype. Model outputs are probabilistic estimates, not a guarantee of website safety. Dashboard overview figures are synthetic preview data; live scan results are returned by your configured FastAPI model.</div>", unsafe_allow_html=True)
