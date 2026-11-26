"""
CompPhish Hybrid Prediction Service

Pipeline:
1. Extract URL features.
2. Extract HTML structural features.
3. Extract visible page text.
4. Generate three branch probabilities.
5. Combine probabilities using the trained fusion model.
6. Apply the saved decision threshold.
"""

from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import joblib
import numpy as np
import pandas as pd

from backend.explain import (
    explain_fusion,
    explain_text_branch,
    explain_tree_branch,
)
from backend.feature_extraction import (
    extract_url_features,
    extract_html_features,
    extract_visible_text,
)


# --------------------------------------------------
# 1. Model configuration
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "compphish_hybrid_model.joblib"
)


# --------------------------------------------------
# 2. Load the trained model
# --------------------------------------------------

def load_hybrid_model():
    """Load the saved CompPhish hybrid model."""

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Hybrid model not found: {MODEL_PATH}"
        )

    model = joblib.load(MODEL_PATH)

    required_keys = [
        "url_model",
        "html_model",
        "text_model",
        "fusion_model",
        "threshold",
        "url_features",
        "html_features",
        "text_feature",
    ]

    missing_keys = [
        key for key in required_keys
        if key not in model
    ]

    if missing_keys:
        raise ValueError(
            f"Model bundle is missing keys: {missing_keys}"
        )

    return model


# Load once when this module is imported.
MODEL = load_hybrid_model()


# --------------------------------------------------
# 2b. URL normalisation and decision bands
# --------------------------------------------------

# Tracking / affiliate parameters carry no information about whether a site
# is phishing, but their punctuation, digits and length shift the URL-branch
# score a lot. They are removed before the URL features are computed.
TRACKING_PARAMS = {
    "tag", "ref", "ref_src", "referrer", "source", "src", "campaign", "cid",
    "click", "clickid", "click_id", "affid", "aff_id", "aff", "sub", "sub1",
    "sub2", "sub3", "gclid", "fbclid", "msclkid", "dclid", "yclid", "mc_cid",
    "mc_eid", "igshid", "sessionid", "session_id", "sid", "trk", "trkid",
}
TRACKING_PREFIXES = ("utm_", "pk_", "mtm_", "hsa_", "vero_")

# Decision bands. Below LOW_THRESHOLD -> legitimate, at or above
# HIGH_THRESHOLD -> phishing, in between -> needs review (no hard verdict).
LOW_THRESHOLD = 0.40
HIGH_THRESHOLD = 0.85


def clean_url_for_scoring(url: str) -> str:
    """Drop tracking parameters and the fragment; keep everything else."""
    parts = urlsplit(url.strip())
    kept = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in TRACKING_PARAMS
        and not k.lower().startswith(TRACKING_PREFIXES)
    ]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(kept), "")
    )


def host_root_url(url: str) -> str:
    """scheme://host/ only - what the domain alone looks like."""
    parts = urlsplit(url.strip())
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


def _url_frame(url: str) -> pd.DataFrame:
    features = extract_url_features(url, MODEL["url_features"])
    return pd.DataFrame([features], columns=MODEL["url_features"])


def _url_branch_probability(url: str) -> float:
    return float(MODEL["url_model"].predict_proba(_url_frame(url))[0, 1])


# --------------------------------------------------
# 3. Prediction function
# --------------------------------------------------

def predict_website(url: str, html: str) -> dict:
    """
    Predict whether a website is phishing or legitimate.

    Parameters
    ----------
    url : str
        Website URL.

    html : str
        HTML source of the website.

    Returns
    -------
    dict
        Branch probabilities, fusion probability,
        risk score and final classification.
    """

    if not isinstance(url, str) or not url.strip():
        raise ValueError("A valid URL is required.")

    if not isinstance(html, str) or not html.strip():
        raise ValueError("Website HTML is required.")

    # ----------------------------------------------
    # A. URL branch
    # ----------------------------------------------
    # The URL model leans heavily on path/query punctuation, so one raw
    # URL can swing the score on the same site. Score the cleaned full URL
    # (tracking parameters removed) and the bare host, then average.

    cleaned_url = clean_url_for_scoring(url)
    url_full_probability = _url_branch_probability(cleaned_url)
    url_host_probability = _url_branch_probability(host_root_url(url))

    # ----------------------------------------------
    # B. HTML feature extraction
    # ----------------------------------------------

    html_features = extract_html_features(
        html,
        MODEL["html_features"]
    )

    html_input = pd.DataFrame(
        [html_features],
        columns=MODEL["html_features"]
    )

    # ----------------------------------------------
    # C. Visible-text extraction
    # ----------------------------------------------

    page_text = extract_visible_text(html)

    text_input = pd.Series(
        [page_text],
        name=MODEL["text_feature"]
    )

    # ----------------------------------------------
    # D. Individual branch predictions
    # ----------------------------------------------

    url_probability = (
        url_full_probability + url_host_probability
    ) / 2.0

    html_probability = float(
        MODEL["html_model"].predict_proba(
            html_input
        )[0, 1]
    )

    text_probability = float(
        MODEL["text_model"].predict_proba(
            text_input
        )[0, 1]
    )

    # ----------------------------------------------
    # E. Hybrid fusion
    # ----------------------------------------------

    # Training-time order:
    # URL probability, HTML probability, Text probability.

    fusion_input = np.array([
        [
            url_probability,
            html_probability,
            text_probability
        ]
    ])

    expected_features = getattr(
        MODEL["fusion_model"],
        "n_features_in_",
        None
    )

    if (
        expected_features is not None
        and fusion_input.shape[1] != expected_features
    ):
        raise ValueError(
            "Fusion model input dimension mismatch."
        )

    hybrid_probability = float(
        MODEL["fusion_model"].predict_proba(
            fusion_input
        )[0, 1]
    )

    # ----------------------------------------------
    # F. Final classification
    # ----------------------------------------------

    if hybrid_probability >= HIGH_THRESHOLD:
        prediction = "PHISHING"
    elif hybrid_probability < LOW_THRESHOLD:
        prediction = "LEGITIMATE"
    else:
        prediction = "NEEDS_REVIEW"

    # Explanation of what the model did (never allowed to break a prediction).
    try:
        explanation = {
            "fusion": explain_fusion(
                MODEL["fusion_model"],
                {"url": url_probability, "html": html_probability, "text": text_probability},
            ),
            "url": explain_tree_branch(
                MODEL["url_model"],
                [_url_frame(cleaned_url), _url_frame(host_root_url(url))],
            ),
            "html": explain_tree_branch(MODEL["html_model"], [html_input]),
            "text": explain_text_branch(MODEL["text_model"], page_text),
        }
    except Exception:
        explanation = None

    # Kept for reference: the bundle's original single cut-off.
    legacy_threshold = float(MODEL["threshold"])

    # ----------------------------------------------
    # G. Return results
    # ----------------------------------------------

    return {
        "url": url,

        "branch_probabilities": {
            "url": round(url_probability, 6),
            "html": round(html_probability, 6),
            "text": round(text_probability, 6),
        },

        "hybrid_probability": round(
            hybrid_probability, 6
        ),

        "risk_score": round(
            hybrid_probability * 100, 2
        ),

        "threshold": HIGH_THRESHOLD,

        "bands": {
            "legitimate_below": LOW_THRESHOLD,
            "phishing_at_or_above": HIGH_THRESHOLD,
            "legacy_single_threshold": legacy_threshold,
        },

        "url_detail": {
            "scored_url": cleaned_url,
            "full_url_probability": round(url_full_probability, 6),
            "host_only_probability": round(url_host_probability, 6),
        },

        "model_explanation": explanation,

        "prediction": prediction,
    }