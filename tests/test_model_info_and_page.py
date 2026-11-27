import sys
from pathlib import Path

from frontend import model_page as mp

ROOT = Path(__file__).resolve().parents[1]


def real_info():
    import sklearn._loss._loss as L
    sys.modules.setdefault("_loss", L)
    from backend import prediction_service as ps
    from backend.model_info import build_model_info
    return build_model_info(ps.MODEL, ps.LOW_THRESHOLD, ps.HIGH_THRESHOLD)


def test_model_info_from_real_bundle():
    i = real_info()
    assert i["branches"]["url"]["features"] == 28 and i["branches"]["html"]["features"] == 6
    assert set(i["fusion"]) == {"url", "html", "text", "intercept"}
    assert len(i["url_importance"]) == 10 and len(i["html_importance"]) == 6
    assert abs(sum(x["importance"] for x in i["html_importance"]) - 1) < 0.01
    assert i["text_terms"]["phishing"] and i["text_terms"]["legitimate"]
    assert i["bands"]["legitimate_below"] < i["bands"]["phishing_at_or_above"]


def test_validate_roundtrip_and_malformed():
    v = mp.validate_info(real_info())
    assert v and len(v["weights"]) == 3 and v["url_features"] == 28 and v["url"] and v["terms_phish"]
    for bad in (None, "x", [], 5):
        assert mp.validate_info(bad) is None
    messy = mp.validate_info({"fusion": "bad", "url_importance": [1, {"feature": 3}, {"feature": "a", "importance": "nan?"}],
                              "text_terms": [], "bands": {"legitimate_below": "x"}, "branches": [1]})
    assert messy["weights"] is None and messy["url"] == [] and (messy["low"], messy["high"]) == (0.40, 0.85)


def test_markup_escaped_single_line():
    page = mp.card("T<", mp.bars_html([("<img src=x onerror=1>", 0.5), ("b", 0.1)]), "note<")
    assert "<img" not in page and "&lt;img" in page and "\n" not in page
    for chunk in (*mp.pipeline_cards(), mp.limitations_html(), mp.status_table_html(None, None), mp.bars_html([])):
        assert "\n" not in chunk


def test_bars_relative_and_visible():
    out = mp.bars_html([("a", 1.0), ("b", 0.001)])
    assert "width:100.0%" in out and "width:2.0%" in out


def test_status_is_honest_about_unmeasured_and_unretrained():
    rows = {c: (s, e) for c, s, e in mp.status_rows(None, None)}
    assert rows["Live accuracy measurement"][0] == "Partly" and rows["Domain-disjoint retraining"][0] == "Partly"
    assert rows["SHAP explanations"][0] == "Planned"
    ev = {"generated": "2026-11-28"}
    rows = {c: s for c, s, e in mp.status_rows({"retrained": True, "url_features": 28, "html_features": 6}, ev)}
    assert rows["Live accuracy measurement"] == "Implemented" and rows["Domain-disjoint retraining"] == "Implemented"


def test_notes_follow_data_not_fixed_claims():
    assert "close" in mp.weights_note([("URL", 4.6), ("HTML", 4.5), ("Text", 5.5)])
    assert "Text branch counts most" in mp.weights_note([("URL", 1.0), ("HTML", 1.0), ("Text", 9.0)])
    assert "'x' is the most influential" in mp.top_note([("x", 0.5)], "e")
