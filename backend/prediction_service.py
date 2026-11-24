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

import joblib
import numpy as np
import pandas as pd

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
    # A. URL feature extraction
    # ----------------------------------------------

    url_features = extract_url_features(
        url,
        MODEL["url_features"]
    )

    url_input = pd.DataFrame(
        [url_features],
        columns=MODEL["url_features"]
    )

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

    url_probability = float(
        MODEL["url_model"].predict_proba(
            url_input
        )[0, 1]
    )

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

    threshold = float(MODEL["threshold"])

    prediction = (
        "PHISHING"
        if hybrid_probability >= threshold
        else "LEGITIMATE"
    )

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

        "threshold": threshold,

        "prediction": prediction,
    }