#!/usr/bin/env python
"""
Retrain the CompPhish hybrid model with domain-disjoint evaluation.

Why this exists
---------------
Splitting rows at random lets the same website appear in train and test, so the
model can score well by memorising domains. This script splits by registered
domain, so every test domain is unseen, then fits the same architecture the app
already loads (URL ExtraTrees + HTML ExtraTrees + TF-IDF/LR text + fusion LR)
with these changes:

  * domain-disjoint train / validation / test split (overlap is checked and the
    script stops if it is not zero);
  * shallower trees (--max-depth, --min-leaf) so they cannot memorise rows;
  * URL augmentation: each training URL is also seen with tracking parameters
    removed and as a bare host, matching how the app scores URLs, so one site
    no longer gets very different scores for small URL changes;
  * fusion trained on out-of-fold, domain-grouped branch probabilities (the old
    way of fitting it on in-sample probabilities makes the fusion over-trust
    whichever branch memorised the most);
  * optional hard negatives (--extra) with extra weight;
  * decision bands (legitimate below / phishing at or above) chosen on the
    validation split from a target false-positive rate, not hard-coded;
  * an honest report: Wilson 95% confidence intervals, calibration, and URL
    stability under tracking parameters.

Input table (parquet or CSV), one row per page:
    url                  required
    label                required, 1 = phishing, 0 = legitimate
    tag_count, form_count, input_count, password_fields, script_count,
    anchor_count         the 6 HTML features, OR an `html` column to derive them
    text_clean           visible text, OR an `html` column to derive it

Usage (Colab or your computer, from the repo root):

    python scripts/retrain_model.py --data train.parquet
    python scripts/retrain_model.py --data train.parquet --extra hard_negatives.csv

The new model is written to models/compphish_hybrid_model_v2.joblib. It does NOT
replace the live model. Compare it with the old one using scripts/evaluate_live.py
before copying it over compphish_hybrid_model.joblib.

Train with the scikit-learn version pinned in requirements.txt, or the app will
load the file with a version-mismatch warning.
"""

from __future__ import annotations

import argparse
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.feature_extraction import (  # noqa: E402
    HTML_FEATURES,
    URL_FEATURES,
    extract_html_and_text,
    extract_url_features,
)
from backend.prediction_service import clean_url_for_scoring, host_root_url  # noqa: E402
from backend.trust_signals import registered_domain  # noqa: E402

DEFAULT_LOW, DEFAULT_HIGH = 0.40, 0.85
TRACKING_SAMPLE = "utm_source=mail&utm_medium=email&utm_campaign=x&fbclid=abc123"


# --------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------

def domain_of(url: str) -> str:
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        host = ""
    return registered_domain(host) if host else ""


def read_table(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    if path.suffix.lower() in {".parquet", ".pq"}:
        return pd.read_parquet(path)
    return pd.read_csv(path)


def prepare(df: pd.DataFrame, url_col: str, label_col: str, text_col: str,
            html_col: str | None) -> pd.DataFrame:
    """Return a frame with url, label, domain, the 6 HTML features and text_clean."""
    if url_col not in df or label_col not in df:
        raise SystemExit(f"Data needs columns '{url_col}' and '{label_col}'.")
    out = pd.DataFrame({"url": df[url_col].astype(str), "label": df[label_col].astype(int)})
    if not set(out["label"].unique()) <= {0, 1}:
        raise SystemExit("Labels must be 0 (legitimate) or 1 (phishing).")

    have_html_feats = all(c in df for c in HTML_FEATURES)
    have_text = text_col in df
    if have_html_feats:
        for c in HTML_FEATURES:
            out[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    if have_text:
        out["text_clean"] = df[text_col].fillna("").astype(str)
    if not (have_html_feats and have_text):
        if not html_col or html_col not in df:
            raise SystemExit(
                f"Need either the 6 HTML feature columns + '{text_col}', or an '{html_col or 'html'}' column."
            )
        feats, texts = [], []
        for h in df[html_col].fillna("").astype(str):
            f, t = extract_html_and_text(h)
            feats.append(f)
            texts.append(t)
        derived = pd.DataFrame(feats, index=out.index)
        for c in HTML_FEATURES:
            if c not in out:
                out[c] = derived[c]
        if "text_clean" not in out:
            out["text_clean"] = texts

    out["domain"] = out["url"].map(domain_of)
    out = out[out["domain"] != ""].reset_index(drop=True)
    return out


def url_matrix(urls) -> pd.DataFrame:
    rows = [extract_url_features(u, URL_FEATURES) for u in urls]
    return pd.DataFrame(rows, columns=URL_FEATURES)


def augment_urls(frame: pd.DataFrame) -> pd.DataFrame:
    """Each URL as given (cleaned), and as a bare host. Same label, same group."""
    cleaned = frame["url"].map(clean_url_for_scoring)
    host = frame["url"].map(host_root_url)
    parts = []
    for u in (cleaned, host):
        p = frame[["label", "domain", "weight"]].copy()
        p["url"] = u.values
        parts.append(p)
    return pd.concat(parts, ignore_index=True).drop_duplicates(subset=["url", "label"])


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------

def make_tree(args) -> ExtraTreesClassifier:
    return ExtraTreesClassifier(
        n_estimators=args.n_estimators, max_depth=args.max_depth,
        min_samples_leaf=args.min_leaf, class_weight="balanced",
        n_jobs=-1, random_state=args.seed,
    )


def make_text() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=50000, ngram_range=(1, 2), min_df=2, max_df=0.98,
            sublinear_tf=True, strip_accents="unicode", token_pattern=r"(?u)\b\w+\b")),
        ("classifier", LogisticRegression(
            C=2.0, class_weight="balanced", max_iter=1000, solver="liblinear")),
    ])


class Branches:
    """The three base models plus how the app turns their inputs into probabilities."""

    def __init__(self, args):
        self.args = args
        self.url = self.html = self.text = None

    def fit(self, tr: pd.DataFrame):
        aug = augment_urls(tr)
        self.url = make_tree(self.args).fit(
            url_matrix(aug["url"]), aug["label"], sample_weight=aug["weight"].values)
        self.html = make_tree(self.args).fit(
            tr[HTML_FEATURES], tr["label"], sample_weight=tr["weight"].values)
        self.text = make_text().fit(
            tr["text_clean"], tr["label"], classifier__sample_weight=tr["weight"].values)
        return self

    def url_prob(self, urls) -> np.ndarray:
        """Average of cleaned-full and host-only scores, exactly as the app does."""
        urls = list(urls)
        full = self.url.predict_proba(url_matrix([clean_url_for_scoring(u) for u in urls]))[:, 1]
        host = self.url.predict_proba(url_matrix([host_root_url(u) for u in urls]))[:, 1]
        return (full + host) / 2.0

    def stack(self, df: pd.DataFrame) -> np.ndarray:
        return np.column_stack([
            self.url_prob(df["url"]),
            self.html.predict_proba(df[HTML_FEATURES])[:, 1],
            self.text.predict_proba(df["text_clean"])[:, 1],
        ])


def out_of_fold(tr: pd.DataFrame, args) -> np.ndarray:
    """Branch probabilities for each training row from models that never saw its domain."""
    k = min(args.folds, tr["domain"].nunique())
    if k < 2:
        raise SystemExit("Need at least 2 distinct domains for cross-validation.")
    oof = np.zeros((len(tr), 3))
    for fit_idx, hold_idx in GroupKFold(n_splits=k).split(tr, tr["label"], tr["domain"]):
        b = Branches(args).fit(tr.iloc[fit_idx])
        oof[hold_idx] = b.stack(tr.iloc[hold_idx])
    return oof


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def pct(k: int, n: int) -> str:
    if n == 0:
        return "n/a (0 rows)"
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {100 * k / n:.1f}% (95% CI {100 * lo:.1f}-{100 * hi:.1f}%)"


def ece(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges) - 1, 0, bins - 1)
    total = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            total += m.mean() * abs(y[m].mean() - p[m].mean())
    return float(total)


def choose_bands(y: np.ndarray, p: np.ndarray, target_fpr: float, target_miss: float):
    """high: at most target_fpr of legitimate rows reach it. low: at most
    target_miss of phishing rows fall below it. Falls back to the defaults when
    the validation split cannot support a sensible pair."""
    legit, phish = p[y == 0], p[y == 1]
    if len(legit) < 30 or len(phish) < 30:
        return DEFAULT_LOW, DEFAULT_HIGH, "defaults (validation split too small)"
    high = float(np.quantile(legit, 1 - target_fpr))
    low = float(np.quantile(phish, target_miss))
    high = min(max(high, 0.5), 0.99)
    low = min(max(low, 0.01), 0.5)
    if low >= high:
        return DEFAULT_LOW, DEFAULT_HIGH, "defaults (bands overlapped)"
    return round(low, 3), round(high, 3), "chosen on validation split"


def evaluate(y, probs, low, high) -> dict:
    y = np.asarray(y)
    n_leg, n_phi = int((y == 0).sum()), int((y == 1).sum())
    res = {
        "n_legit": n_leg, "n_phish": n_phi,
        "auc": float(roc_auc_score(y, probs)) if n_leg and n_phi else float("nan"),
        "ap": float(average_precision_score(y, probs)) if n_leg and n_phi else float("nan"),
        "brier": float(brier_score_loss(y, probs)),
        "ece": ece(y, probs),
        "legit_flagged_phishing": int(((probs >= high) & (y == 0)).sum()),
        "legit_needs_review": int(((probs >= low) & (probs < high) & (y == 0)).sum()),
        "phish_caught": int(((probs >= high) & (y == 1)).sum()),
        "phish_needs_review": int(((probs >= low) & (probs < high) & (y == 1)).sum()),
        "phish_called_legit": int(((probs < low) & (y == 1)).sum()),
    }
    return res


def url_stability(branches: Branches, urls: list[str]) -> dict:
    """How far the URL-branch score moves when only tracking parameters are added."""
    changed = []
    for u in urls:
        sep = "&" if "?" in u else "?"
        changed.append(u + sep + TRACKING_SAMPLE)
    a, b = branches.url_prob(urls), branches.url_prob(changed)
    d = np.abs(a - b)
    return {"mean": float(d.mean()), "p95": float(np.quantile(d, 0.95)), "max": float(d.max())}


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def build_report(ctx: dict) -> str:
    t = ctx["test"]
    L = []
    L.append("# CompPhish retraining report\n")
    L.append(f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}. "
             f"scikit-learn {sklearn.__version__}.\n")
    L.append("## Read this first\n")
    L.append("- Test domains were never seen in training (overlap checked = 0). This is still the "
             "**same dataset's** distribution. A model that generalises should also score well on "
             "`scripts/evaluate_live.py` against fresh pages; if it does not, the offline numbers "
             "here are too optimistic.")
    L.append("- Bands and calibration were chosen on a separate validation split, not on the test split.")
    L.append("- Nothing here was tuned on named websites.\n")
    L.append("## Data\n")
    L.append("| Split | Rows | Domains | Phishing | Legitimate |\n|---|---|---|---|---|")
    for name in ("train", "validation", "test"):
        s = ctx["splits"][name]
        L.append(f"| {name} | {s['rows']} | {s['domains']} | {s['phish']} | {s['legit']} |")
    L.append(f"\nDomain overlap train/validation/test: **{ctx['overlap']}** (must be 0).\n")
    L.append("## Settings\n")
    a = ctx["args"]
    L.append(f"- Trees: n_estimators={a.n_estimators}, max_depth={a.max_depth}, min_samples_leaf={a.min_leaf}")
    L.append(f"- Fusion trained on {a.folds}-fold domain-grouped out-of-fold probabilities")
    L.append(f"- Hard negatives: {ctx['extra_rows']} rows (weight x{a.extra_weight})")
    L.append(f"- Bands: legitimate below **{ctx['low']}**, phishing at or above **{ctx['high']}** "
             f"({ctx['band_note']}; target FPR {a.target_fpr:.1%}, target miss {a.target_miss:.1%})\n")
    L.append("## Test results (unseen domains)\n")
    L.append("| Model | ROC-AUC | Avg precision | Brier | ECE |\n|---|---|---|---|---|")
    for name, r in ctx["branch_scores"].items():
        L.append(f"| {name} | {r['auc']:.4f} | {r['ap']:.4f} | {r['brier']:.4f} | {r['ece']:.4f} |")
    L.append("\n### Final decision (fused score and bands)\n")
    nl, np_ = t["n_legit"], t["n_phish"]
    L.append(f"- Legitimate flagged PHISHING: {pct(t['legit_flagged_phishing'], nl)}")
    L.append(f"- Legitimate sent to NEEDS_REVIEW: {pct(t['legit_needs_review'], nl)}")
    L.append(f"- Phishing caught (PHISHING): {pct(t['phish_caught'], np_)}")
    L.append(f"- Phishing sent to NEEDS_REVIEW: {pct(t['phish_needs_review'], np_)}")
    L.append(f"- Phishing called LEGITIMATE (missed): {pct(t['phish_called_legit'], np_)}\n")
    s = ctx["stability"]
    L.append("## URL stability\n")
    L.append("Change in the URL-branch score when only tracking parameters "
             "(utm_*, fbclid) are appended to the test URLs:\n")
    L.append(f"- mean {s['mean']:.4f}, 95th percentile {s['p95']:.4f}, max {s['max']:.4f}\n")
    L.append("## Next steps\n")
    L.append("1. Run `python scripts/evaluate_live.py ... --train-domains <your train domains>` "
             "with this model in place and compare with the old one.")
    L.append("2. Only if live results are better (especially legitimate-flagged-phishing on complex "
             "sites), copy the v2 file over `models/compphish_hybrid_model.joblib` and redeploy.")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def split_by_domain(df: pd.DataFrame, test_size: float, val_size: float, seed: int):
    g = df["domain"]
    outer = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    rest_idx, test_idx = next(outer.split(df, df["label"], g))
    rest = df.iloc[rest_idx]
    inner = GroupShuffleSplit(n_splits=1, test_size=val_size / (1 - test_size), random_state=seed)
    tr_i, val_i = next(inner.split(rest, rest["label"], rest["domain"]))
    return rest.iloc[tr_i].copy(), rest.iloc[val_i].copy(), df.iloc[test_idx].copy()


def describe(df: pd.DataFrame) -> dict:
    return {"rows": len(df), "domains": df["domain"].nunique(),
            "phish": int((df["label"] == 1).sum()), "legit": int((df["label"] == 0).sum())}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True)
    ap.add_argument("--extra", help="hard-negative / extra rows, same columns as --data (train only)")
    ap.add_argument("--extra-weight", type=float, default=3.0)
    ap.add_argument("--url-col", default="url")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--text-col", default="text_clean")
    ap.add_argument("--html-col", default="html")
    ap.add_argument("--max-rows", type=int, default=0, help="subsample for a quick trial (0 = all)")
    ap.add_argument("--n-estimators", type=int, default=250)
    ap.add_argument("--max-depth", type=int, default=14)
    ap.add_argument("--min-leaf", type=int, default=5)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--test-size", type=float, default=0.20)
    ap.add_argument("--val-size", type=float, default=0.15)
    ap.add_argument("--target-fpr", type=float, default=0.01,
                    help="share of legitimate validation rows allowed to reach the PHISHING band")
    ap.add_argument("--target-miss", type=float, default=0.02,
                    help="share of phishing validation rows allowed below the LEGITIMATE band")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(ROOT / "models" / "compphish_hybrid_model_v2.joblib"))
    ap.add_argument("--report", default=str(ROOT / "retrain_out" / "report.md"))
    args = ap.parse_args(argv)

    pin = None
    req = ROOT / "requirements.txt"
    if req.exists():
        for line in req.read_text().splitlines():
            if line.lower().startswith("scikit-learn"):
                pin = line.split("==")[-1].strip() if "==" in line else None
    if pin and pin != sklearn.__version__:
        print(f"WARNING: requirements.txt pins scikit-learn {pin} but this is {sklearn.__version__}. "
              "The saved model will load with a version warning in the app.", file=sys.stderr)

    raw = read_table(args.data)
    if args.max_rows and len(raw) > args.max_rows:
        raw = raw.sample(args.max_rows, random_state=args.seed)
    df = prepare(raw, args.url_col, args.label_col, args.text_col, args.html_col)
    df["weight"] = 1.0

    tr, val, te = split_by_domain(df, args.test_size, args.val_size, args.seed)

    overlap = (set(tr["domain"]) & set(val["domain"])) | (set(tr["domain"]) & set(te["domain"])) \
        | (set(val["domain"]) & set(te["domain"]))
    if overlap:
        raise SystemExit(f"Domain leakage between splits: {sorted(overlap)[:5]} ...")

    extra_rows = 0
    if args.extra:
        ex = prepare(read_table(args.extra), args.url_col, args.label_col, args.text_col, args.html_col)
        # never let an extra row's domain leak into validation or test
        held = set(val["domain"]) | set(te["domain"])
        ex = ex[~ex["domain"].isin(held)].copy()
        ex["weight"] = args.extra_weight
        extra_rows = len(ex)
        tr = pd.concat([tr, ex], ignore_index=True)

    splits = {"train": describe(tr), "validation": describe(val), "test": describe(te)}
    for name, s in splits.items():
        if s["phish"] == 0 or s["legit"] == 0:
            raise SystemExit(f"The {name} split has only one class; use more data or a different --seed.")

    print("Out-of-fold branch probabilities for the fusion model ...")
    oof = out_of_fold(tr, args)
    fusion = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=args.seed)
    fusion.fit(oof, tr["label"], sample_weight=tr["weight"].values)

    print("Fitting final branch models ...")
    branches = Branches(args).fit(tr)

    val_stack, te_stack = branches.stack(val), branches.stack(te)
    val_p = fusion.predict_proba(val_stack)[:, 1]
    te_p = fusion.predict_proba(te_stack)[:, 1]
    low, high, band_note = choose_bands(val["label"].values, val_p, args.target_fpr, args.target_miss)

    y = te["label"].values
    branch_scores = {
        "URL branch": evaluate(y, te_stack[:, 0], low, high),
        "HTML branch": evaluate(y, te_stack[:, 1], low, high),
        "Text branch": evaluate(y, te_stack[:, 2], low, high),
        "Fused": evaluate(y, te_p, low, high),
    }
    stability = url_stability(branches, list(te["url"])[:2000])

    bundle = {
        "url_model": branches.url,
        "html_model": branches.html,
        "text_model": branches.text,
        "fusion_model": fusion,
        "threshold": high,
        "bands": {"legitimate_below": low, "phishing_at_or_above": high},
        "url_features": list(URL_FEATURES),
        "html_features": list(HTML_FEATURES),
        "text_feature": "text_clean",
        "model_name": "CompPhish Hybrid Multi-Modal Model (domain-disjoint retrain)",
        "random_state": args.seed,
        "trained_with": {
            "sklearn": sklearn.__version__, "trained_at": datetime.now(timezone.utc).isoformat(),
            "splits": splits, "max_depth": args.max_depth, "min_samples_leaf": args.min_leaf,
        },
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out)

    report = build_report({
        "args": args, "splits": splits, "overlap": len(overlap), "extra_rows": extra_rows,
        "low": low, "high": high, "band_note": band_note,
        "branch_scores": branch_scores, "test": branch_scores["Fused"], "stability": stability,
    })
    rp = Path(args.report)
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text(report, encoding="utf-8")
    print(report)
    print(f"Model written to {out}\nReport written to {rp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
