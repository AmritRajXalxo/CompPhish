"""
Score explanation for the deployed hybrid model (no extra dependencies).

The result is an exact additive breakdown:

  * Fusion (logistic regression on the three branch probabilities):
        logit = intercept + w_url*p_url + w_html*p_html + w_text*p_text
    so each branch's push on the final score is exactly w * p.
  * Tree branches (URL, HTML ExtraTrees): tree-path contributions. For every
    tree, the change in the leaf-probability along the decision path is credited
    to the feature used at each split; averaged over trees,
        P(phishing) = bias + sum(feature contributions)     (checked in tests)
    This is the Saabas "tree interpreter" method. It is NOT SHAP: attributions can
    differ from Shapley values when features interact.
  * Text branch (TF-IDF + logistic regression): coefficient x TF-IDF weight per
    term, in log-odds.

These explain what the MODEL did. They do not show whether the site is phishing.
"""

from __future__ import annotations

from typing import Any

import numpy as np


def _node_prob(tree, node: int, cls: int) -> float:
    v = tree.value[node][0]
    s = float(v.sum())
    return float(v[cls]) / s if s > 0 else 0.0


def tree_contributions(model, x: np.ndarray, cls: int = 1) -> tuple[float, np.ndarray]:
    """(bias, per-feature contributions) so that bias + sum == model.predict_proba(x)[0, cls]."""
    x32 = np.asarray(x, dtype=np.float32).reshape(1, -1)
    n_feat = x32.shape[1]
    contrib = np.zeros(n_feat, dtype=np.float64)
    bias = 0.0
    estimators = model.estimators_
    for est in estimators:
        t = est.tree_
        path = est.decision_path(x32).indices          # node ids, root -> leaf (child ids > parent ids)
        bias += _node_prob(t, int(path[0]), cls)
        for parent, child in zip(path[:-1], path[1:]):
            f = int(t.feature[parent])
            contrib[f] += _node_prob(t, int(child), cls) - _node_prob(t, int(parent), cls)
    n = float(len(estimators))
    return bias / n, contrib / n


def _top(names, values, contribs, k: int) -> list[dict]:
    order = np.argsort(-np.abs(contribs))[:k]
    return [
        {"feature": str(names[i]), "value": _num(values[i]), "contribution": round(float(contribs[i]), 4)}
        for i in order if abs(contribs[i]) > 1e-4
    ]


def _num(v: Any):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return int(f) if f == int(f) and abs(f) < 1e12 else round(f, 3)


def explain_tree_branch(model, frames: list, k: int = 6) -> dict | None:
    """Average the explanation over one or more input frames (e.g. cleaned URL and host-only URL)."""
    if not hasattr(model, "estimators_") or not frames:
        return None
    names = list(frames[0].columns)
    biases, contribs = [], []
    for fr in frames:
        b, c = tree_contributions(model, fr.iloc[0].to_numpy(dtype=float))
        biases.append(b)
        contribs.append(c)
    bias = float(np.mean(biases))
    contrib = np.mean(contribs, axis=0)
    first = frames[0].iloc[0].to_numpy(dtype=float)
    return {"baseline": round(bias, 4), "top_features": _top(names, first, contrib, k), "total": round(bias + float(contrib.sum()), 4)}


def explain_text_branch(pipeline, text: str, k: int = 6) -> dict | None:
    """Top terms by coefficient x TF-IDF weight (log-odds)."""
    try:
        steps = list(pipeline.named_steps.values())
        vec = next(s for s in steps if hasattr(s, "vocabulary_"))
        clf = steps[-1]
        coef = np.asarray(clf.coef_).ravel()
        X = vec.transform([text])
        names = vec.get_feature_names_out()
        idx = X.indices
        vals = X.data * coef[idx]
        order = np.argsort(-np.abs(vals))[:k]
        return {
            "intercept_logodds": round(float(np.asarray(clf.intercept_).ravel()[0]), 4),
            "top_terms": [{"term": str(names[idx[i]]), "contribution": round(float(vals[i]), 4)} for i in order if abs(vals[i]) > 1e-4],
        }
    except Exception:
        return None


def explain_fusion(fusion, probs: dict) -> dict | None:
    """Exact logit decomposition for a logistic regression on [url, html, text] probabilities."""
    try:
        coef = np.asarray(fusion.coef_).ravel()
        order = ["url", "html", "text"]
        parts = {k: float(coef[i]) * float(probs[k]) for i, k in enumerate(order)}
        intercept = float(np.asarray(fusion.intercept_).ravel()[0])
        logit = intercept + sum(parts.values())
        return {
            "intercept": round(intercept, 3),
            "branches": {k: {"probability": round(float(probs[k]), 4), "weight": round(float(coef[i]), 3), "push": round(parts[k], 3)}
                         for i, k in enumerate(order)},
            "logit": round(logit, 3),
            "probability": round(float(1.0 / (1.0 + np.exp(-logit))), 4),
        }
    except Exception:
        return None
