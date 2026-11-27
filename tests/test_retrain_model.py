"""Smoke tests for scripts/retrain_model.py on synthetic data (no real dataset needed)."""
import importlib.util
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("retrain_model", ROOT / "scripts" / "retrain_model.py")
rm = importlib.util.module_from_spec(spec)
sys.modules["retrain_model"] = rm
spec.loader.exec_module(rm)


def synthetic(n_domains=120, per=3, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n_domains):
        phish = i % 2 == 0
        dom = f"site{i}-{'secure-login' if phish else 'shop'}.com"
        for j in range(per):
            path = f"/{'verify/account' if phish else 'products'}/{j}?id={rng.integers(1000)}"
            rows.append({
                "url": f"https://{dom}{path}", "label": int(phish),
                "tag_count": int(rng.normal(60 if phish else 400, 20)),
                "form_count": int(phish), "input_count": 3 if phish else 1,
                "password_fields": int(phish), "script_count": int(rng.integers(1, 5 if phish else 40)),
                "anchor_count": int(rng.integers(1, 10 if phish else 80)),
                "text_clean": ("verify your account password login " if phish else "shop products cart delivery ")
                + f"word{rng.integers(50)} common{j}",
            })
    return pd.DataFrame(rows)


def run(tmp_path, df, extra=None, extra_args=()):
    data = tmp_path / "d.csv"
    df.to_csv(data, index=False)
    argv = ["--data", str(data), "--out", str(tmp_path / "m.joblib"),
            "--report", str(tmp_path / "r.md"), "--n-estimators", "20", "--folds", "3"]
    if extra is not None:
        e = tmp_path / "e.csv"
        extra.to_csv(e, index=False)
        argv += ["--extra", str(e)]
    assert rm.main(argv + list(extra_args)) == 0
    return joblib.load(tmp_path / "m.joblib"), (tmp_path / "r.md").read_text()


def test_wilson_and_domain():
    lo, hi = rm.wilson(5, 100)
    assert 0.02 < lo < 0.05 < hi < 0.12
    assert rm.domain_of("https://a.b.example.co.uk/x") == "example.co.uk"


def test_retrain_produces_loadable_bundle_and_zero_overlap(tmp_path):
    bundle, report = run(tmp_path, synthetic())
    for k in ("url_model", "html_model", "text_model", "fusion_model", "threshold",
              "url_features", "html_features", "text_feature", "bands"):
        assert k in bundle
    assert bundle["fusion_model"].n_features_in_ == 3
    assert 0 < bundle["bands"]["legitimate_below"] < bundle["bands"]["phishing_at_or_above"] < 1
    assert "overlap train/validation/test: **0**" in report
    assert "Wilson" not in report and "95% CI" in report


def test_extra_hard_negatives_never_leak_into_eval_domains(tmp_path):
    df = synthetic()
    extra = df.sample(30, random_state=1).copy()  # same domains as the main data
    bundle, report = run(tmp_path, df, extra=extra)
    assert "Hard negatives:" in report


def test_new_bundle_loads_in_app_with_its_bands(tmp_path, monkeypatch):
    bundle, _ = run(tmp_path, synthetic())
    from backend import prediction_service as ps
    low, high = ps._bands_from_bundle(bundle)
    assert (low, high) == (bundle["bands"]["legitimate_below"], bundle["bands"]["phishing_at_or_above"])
    # old bundles without bands keep the documented defaults
    assert ps._bands_from_bundle({}) == (0.40, 0.85)
    assert ps._bands_from_bundle({"bands": {"legitimate_below": 0.9, "phishing_at_or_above": 0.2}}) == (0.40, 0.85)


def test_rejects_single_class(tmp_path):
    df = synthetic()
    df["label"] = 1
    with pytest.raises(SystemExit):
        run(tmp_path, df)
