"""Facts about the loaded model for the dashboard, read from the bundle itself.

Nothing here is hard-coded about accuracy: it reports what the model file contains
(feature names, fusion weights, tree feature importances, strongest text terms).
"""

from __future__ import annotations

import math
from typing import Any

TOP_FEATURES = 10
TOP_TERMS = 8


def _num(x: Any, digits: int = 4) -> float | None:
    try:
        v = float(x)
    except (TypeError, ValueError):
        return None
    return round(v, digits) if math.isfinite(v) else None


def tree_importances(model: Any, names: list[str], top: int = TOP_FEATURES) -> list[dict]:
    imp = getattr(model, "feature_importances_", None)
    if imp is None or len(imp) != len(names):
        return []
    pairs = sorted(zip(names, imp), key=lambda p: p[1], reverse=True)[:top]
    return [{"feature": n, "importance": _num(v, 5)} for n, v in pairs]


def fusion_weights(model: Any) -> dict | None:
    coef = getattr(model, "coef_", None)
    if coef is None:
        return None
    row = list(coef[0])
    if len(row) != 3:
        return None
    return {
        "url": _num(row[0]), "html": _num(row[1]), "text": _num(row[2]),
        "intercept": _num(getattr(model, "intercept_", [0])[0]),
    }


def text_terms(pipeline: Any, top: int = TOP_TERMS) -> dict | None:
    """Words that push the text branch most toward phishing / legitimate."""
    try:
        vec, clf = pipeline.named_steps["tfidf"], pipeline.named_steps["classifier"]
        names = vec.get_feature_names_out()
        w = clf.coef_[0]
    except Exception:
        return None
    if len(names) != len(w):
        return None
    order = sorted(range(len(w)), key=lambda i: w[i])
    return {
        "phishing": [{"term": str(names[i]), "weight": _num(w[i], 3)} for i in reversed(order[-top:])],
        "legitimate": [{"term": str(names[i]), "weight": _num(w[i], 3)} for i in order[:top]],
    }


def build_model_info(bundle: dict, low: float, high: float) -> dict:
    url_names = list(bundle.get("url_features") or [])
    html_names = list(bundle.get("html_features") or [])
    meta = bundle.get("trained_with") if isinstance(bundle.get("trained_with"), dict) else {}
    return {
        "model_name": str(bundle.get("model_name") or "CompPhish hybrid model"),
        "bands": {"legitimate_below": low, "phishing_at_or_above": high},
        "branches": {
            "url": {"features": len(url_names), "model": type(bundle["url_model"]).__name__},
            "html": {"features": len(html_names), "model": type(bundle["html_model"]).__name__},
            "text": {"model": "TF-IDF + logistic regression"},
        },
        "fusion": fusion_weights(bundle["fusion_model"]),
        "url_importance": tree_importances(bundle["url_model"], url_names),
        "html_importance": tree_importances(bundle["html_model"], html_names, top=len(html_names)),
        "text_terms": text_terms(bundle["text_model"]),
        "retrained_domain_disjoint": bool(meta),
        "trained_at": str(meta.get("trained_at", ""))[:10] if meta else "",
    }
