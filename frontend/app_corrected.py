from __future__ import annotations
import os
import html
import math
from typing import Any
from urllib.parse import urlparse

import requests
import streamlit as st


# ============================================================
# 1. PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Website Security Intelligence",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)


# ============================================================
# 2. BACKEND CONFIGURATION
# ============================================================

# ============================================================
# 2. BACKEND API CONFIGURATION
# ============================================================

DEFAULT_API_URL = "http://127.0.0.1:8000"

try:
    API_BASE_URL = st.secrets.get(
        "API_URL",
        os.getenv("API_URL", DEFAULT_API_URL)
    )
except Exception:
    API_BASE_URL = os.getenv("API_URL", DEFAULT_API_URL)

API_URL = API_BASE_URL.strip().rstrip("/") + "/scan"

REQUEST_TIMEOUT = 90

# ============================================================
# 3. CUSTOM DARK THEME
# ============================================================

st.markdown(
    """
    <style>
    .stApp {
        background: #101116;
        color: #E8EAF2;
    }

    [data-testid="stHeader"] {
        background: #101116;
    }

    .block-container {
        max-width: 860px;
        padding-top: 4rem;
        padding-bottom: 3rem;
    }

    #MainMenu, footer {
        visibility: hidden;
    }

    .hero {
        text-align: center;
        margin: 0 auto 2.5rem auto;
    }

    .hero-title {
        color: #F2F3F8;
        font-size: clamp(1.8rem, 4vw, 2.4rem);
        font-weight: 700;
        letter-spacing: -1.1px;
        line-height: 1.2;
        margin: 0 0 0.9rem 0;
    }

    .hero-subtitle {
        color: #9299AC;
        font-size: 0.95rem;
        line-height: 1.85;
        margin: 0;
    }

    .section-label {
        color: #8D9ABC;
        font-size: 0.7rem;
        font-weight: 750;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin: 2rem 0 0.85rem 0;
    }

    div[data-testid="stForm"] {
        background: #14161D;
        border: 1px solid #303543;
        border-radius: 14px;
        padding: 1rem 1rem 0.55rem 1rem;
    }

    div[data-testid="stTextInput"] input {
        background: #191C25;
        color: #F1F3F8;
        border: 1px solid #303543;
        border-radius: 9px;
        min-height: 3rem;
    }

    div[data-testid="stTextInput"] input:focus {
        border-color: #8295FF;
        box-shadow: 0 0 0 1px #8295FF;
    }

    div[data-testid="stFormSubmitButton"] button {
        width: 100%;
        min-height: 3rem;
        border-radius: 9px;
        border: 1px solid #8295FF;
        background: #8295FF;
        color: #101116;
        font-weight: 700;
        transition: 160ms ease;
    }

    div[data-testid="stFormSubmitButton"] button:hover {
        background: #9AA8FF;
        border-color: #9AA8FF;
        color: #101116;
    }

    .result-card {
        background: #191C25;
        border: 1px solid #303543;
        border-radius: 15px;
        padding: 1.5rem;
        margin-top: 0.4rem;
    }

    .result-label {
        color: #9299AC;
        font-size: 0.72rem;
        font-weight: 750;
        letter-spacing: 1.6px;
        text-transform: uppercase;
    }

    .risk-value {
        font-size: clamp(2.6rem, 7vw, 3.5rem);
        font-weight: 750;
        letter-spacing: -2px;
        line-height: 1.2;
        margin: 0.5rem 0;
    }

    .result-note {
        color: #9299AC;
        font-size: 0.86rem;
    }

    .status-badge {
        display: inline-block;
        padding: 0.48rem 0.8rem;
        margin-top: 1rem;
        border-radius: 7px;
        font-size: 0.76rem;
        font-weight: 800;
        letter-spacing: 1px;
    }

    .status-phishing {
        color: #FF929A;
        background: #40232B;
        border: 1px solid #713943;
    }

    .status-legitimate {
        color: #78DDB5;
        background: #18382F;
        border: 1px solid #28624D;
    }

    .branch-card {
        background: #191C25;
        border: 1px solid #303543;
        border-radius: 12px;
        padding: 1.1rem 0.65rem;
        text-align: center;
        min-height: 108px;
    }

    .branch-name {
        color: #9299AC;
        font-size: 0.68rem;
        font-weight: 750;
        letter-spacing: 0.8px;
        line-height: 1.5;
        min-height: 2.1rem;
    }

    .branch-value {
        color: #E8EAF2;
        font-size: 1.4rem;
        font-weight: 700;
        margin-top: 0.4rem;
    }

    .info-card {
        background: #191C25;
        border: 1px solid #303543;
        border-radius: 12px;
        padding: 1.1rem 1.25rem;
    }

    .info-row {
        padding: 0.7rem 0;
        border-bottom: 1px solid #2A2E39;
    }

    .info-row:last-child {
        border-bottom: none;
    }

    .info-label {
        display: block;
        color: #9299AC;
        font-size: 0.75rem;
        margin-bottom: 0.35rem;
    }

    .info-value {
        display: block;
        color: #E8EAF2;
        font-size: 0.86rem;
        overflow-wrap: anywhere;
    }

    .footer-note {
        color: #697184;
        font-size: 0.74rem;
        line-height: 1.7;
        text-align: center;
        margin-top: 3rem;
    }

    [data-testid="stExpander"] {
        background: #191C25;
        border: 1px solid #303543;
        border-radius: 10px;
    }

    @media (max-width: 640px) {
        .block-container {
            padding-top: 2.5rem;
        }

        .hero-subtitle {
            font-size: 0.88rem;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# 4. HELPER FUNCTIONS
# ============================================================

def normalise_url(value: str) -> str:
    """Add https:// when the user enters a hostname without a scheme."""
    value = value.strip()

    if not value:
        raise ValueError("Please enter a website URL.")

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS website URLs are supported.")

    if not parsed.netloc or "." not in parsed.netloc:
        raise ValueError("Please enter a valid website address.")

    return value


def validate_probability(value: Any, field_name: str) -> float:
    """Convert and validate a probability in the range 0 to 1."""
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {field_name} received from the API.") from exc

    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(f"{field_name} must be between 0 and 1.")

    return number


def scan_website(url: str) -> dict[str, Any]:
    """Send the URL to the FastAPI /scan endpoint."""
    try:
        response = requests.post(
            API_URL,
            json={"url": url},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

    except requests.exceptions.Timeout as exc:
        raise RuntimeError(
            "The scan timed out. Please try again."
        ) from exc

    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            "Cannot connect to the backend. Make sure FastAPI is running "
            "at http://127.0.0.1:8000."
        ) from exc

    except requests.exceptions.HTTPError as exc:
        try:
            detail = response.json()
        except ValueError:
            detail = response.text[:500]
        raise RuntimeError(f"Backend returned an error: {detail}") from exc

    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Request failed: {exc}") from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError("The backend did not return valid JSON.") from exc

    if not isinstance(data, dict):
        raise RuntimeError("Unexpected API response format.")

    required_fields = {
        "prediction",
        "hybrid_probability",
        "risk_score",
        "threshold",
        "branch_probabilities",
    }
    missing = required_fields.difference(data.keys())

    if missing:
        raise RuntimeError(
            "The API response is missing: " + ", ".join(sorted(missing))
        )

    if not isinstance(data["branch_probabilities"], dict):
        raise RuntimeError("The branch_probabilities field is not a JSON object.")

    return data


# ============================================================
# 5. HEADER
# ============================================================

st.markdown(
    """
    <div class="hero">
        <h1 class="hero-title">Website Security Intelligence</h1>
        <p class="hero-subtitle">
            Analyse websites through multiple intelligence layers.<br>
            Identify phishing threats using hybrid machine learning.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# 6. URL INPUT AND SCAN
# ============================================================

with st.form("website_scan_form", clear_on_submit=False):
    website_url = st.text_input(
        "Website URL",
        placeholder="Enter website URL  ·  https://example.com",
        label_visibility="collapsed",
    )
    scan_button = st.form_submit_button("Analyse Website  →")


if scan_button:
    try:
        submitted_url = normalise_url(website_url)

        with st.spinner("Analysing website intelligence..."):
            result = scan_website(submitted_url)

        st.session_state["scan_result"] = result
        st.session_state["submitted_url"] = submitted_url
        st.session_state.pop("scan_error", None)

    except (ValueError, RuntimeError) as exc:
        st.session_state.pop("scan_result", None)
        st.session_state["scan_error"] = str(exc)


if st.session_state.get("scan_error"):
    st.error(st.session_state["scan_error"])


# ============================================================
# 7. RESULTS
# ============================================================

if "scan_result" in st.session_state:
    result = st.session_state["scan_result"]

    try:
        prediction = str(result["prediction"]).strip().upper()

        if prediction not in {"PHISHING", "LEGITIMATE"}:
            raise ValueError(f"Unknown prediction label: {prediction}")

        hybrid_probability = validate_probability(
            result["hybrid_probability"], "Hybrid probability"
        )
        threshold = validate_probability(
            result["threshold"], "Decision threshold"
        )

        risk_score = float(result["risk_score"])
        if not math.isfinite(risk_score) or not 0.0 <= risk_score <= 100.0:
            raise ValueError("Risk score must be between 0 and 100.")

        branch_data = result["branch_probabilities"]
        branch_probabilities = {
            "url": validate_probability(branch_data.get("url"), "URL probability"),
            "html": validate_probability(branch_data.get("html"), "HTML probability"),
            "text": validate_probability(branch_data.get("text"), "Text probability"),
        }

    except (TypeError, ValueError) as exc:
        st.error(f"Could not display the API result: {exc}")
        st.stop()

    is_phishing = prediction == "PHISHING"
    risk_color = "#FF929A" if is_phishing else "#78DDB5"
    status_class = "status-phishing" if is_phishing else "status-legitimate"
    status_text = "PHISHING DETECTED" if is_phishing else "LEGITIMATE"

    st.markdown(
        '<div class="section-label">Analysis Result</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <div class="result-card">
            <div class="result-label">Phishing Probability</div>
            <div class="risk-value" style="color:{risk_color};">
                {hybrid_probability * 100:.2f}%
            </div>
            <div class="result-note">Hybrid model risk assessment</div>
            <span class="status-badge {status_class}">{status_text}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.progress(risk_score / 100.0)
    st.caption(
        f"Risk score: {risk_score:.2f}%"
        f"  ·  Decision threshold: {threshold * 100:.0f}%"
    )

    # --------------------------------------------------------
    # Branch probabilities
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-label">Intelligence Breakdown</div>',
        unsafe_allow_html=True,
    )

    branch_display = [
        ("URL INTELLIGENCE", branch_probabilities["url"]),
        ("HTML STRUCTURE", branch_probabilities["html"]),
        ("PAGE TEXT", branch_probabilities["text"]),
    ]

    columns = st.columns(3)

    for column, (display_name, probability) in zip(columns, branch_display):
        with column:
            st.markdown(
                f"""
                <div class="branch-card">
                    <div class="branch-name">{display_name}</div>
                    <div class="branch-value">{probability * 100:.2f}%</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # --------------------------------------------------------
    # Scan information
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-label">Scan Information</div>',
        unsafe_allow_html=True,
    )

    submitted = html.escape(
        str(result.get("submitted_url", st.session_state.get("submitted_url", "")))
    )
    final_url = html.escape(
        str(result.get("final_url", result.get("url", "Not available")))
    )
    content_type = html.escape(
        str(result.get("content_type", "Not available"))
    )
    html_size = html.escape(str(result.get("html_size", "Not available")))

    st.markdown(
        f"""
        <div class="info-card">
            <div class="info-row">
                <span class="info-label">Submitted URL</span>
                <span class="info-value">{submitted}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Final URL</span>
                <span class="info-value">{final_url}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Content Type</span>
                <span class="info-value">{content_type}</span>
            </div>
            <div class="info-row">
                <span class="info-label">HTML Retrieved</span>
                <span class="info-value">{html_size} bytes</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # --------------------------------------------------------
    # Technical details
    # --------------------------------------------------------

    with st.expander("View technical details"):
        st.write("**Model:**", result.get("model", "Not available"))
        st.write("**Hybrid probability:**", f"{hybrid_probability:.6f}")
        st.write("**Decision threshold:**", f"{threshold:.4f}")
        st.write("**Prediction:**", prediction)

    st.markdown(
        """
        <div class="footer-note">
            Predictions are machine-learning estimates and do not guarantee
            that a website is safe or malicious. Do not enter sensitive
            information on websites you do not trust.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# 8. FOOTER
# ============================================================

if "scan_result" not in st.session_state:
    st.markdown(
        """
        <div class="footer-note">
            URL intelligence · HTML structure · Page text
        </div>
        """,
        unsafe_allow_html=True,
    )
