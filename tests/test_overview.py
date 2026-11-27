import json
import re
from pathlib import Path

from frontend import overview as ov

ROOT = Path(__file__).resolve().parents[1]


def payload(pred="LEGITIMATE", risk=12.5):
    return {"prediction": pred, "risk_score": risk}


def test_record_scan_orders_caps_and_ignores_bad_data():
    h = []
    for i in range(60):
        h = ov.record_scan(h, payload(risk=i % 100), f"https://s{i}.example", now=1000 + i)
    assert len(h) == ov.MAX_HISTORY and h[0]["url"] == "https://s59.example"
    before = list(h)
    for bad in (None, "x", {"prediction": "WEIRD", "risk_score": 5}, {"prediction": "PHISHING", "risk_score": "nan"},
                {"prediction": "PHISHING", "risk_score": 150}, {"prediction": "PHISHING"}):
        assert ov.record_scan(h, bad, "u") == before


def test_summary_counts_and_empty():
    assert ov.summarise_history([])["avg_risk"] is None
    h = ov.record_scan([], payload("PHISHING", 90), "a")
    h = ov.record_scan(h, payload("LEGITIMATE", 10), "b")
    s = ov.summarise_history(h)
    assert s["total"] == 2 and s["flagged"] == 1 and s["avg_risk"] == 50


def test_cards_show_no_fake_numbers_when_empty():
    cards = "".join(ov.stat_cards(ov.summarise_history([]), None))
    assert "No scans yet" in cards and "Not yet" in cards
    for fake in ("2,481", "384", "99.9"):
        assert fake not in cards


def test_check_api_states():
    class R:
        status_code = 200
        def json(self): return {"model_name": "M", "bands": {"legitimate_below": .3, "phishing_at_or_above": .9}}
    assert ov.check_api("http://x", getter=lambda *a, **k: R())["state"] == "online"
    assert ov.check_api("http://x", getter=lambda *a, **k: R())["bands"]["phishing_at_or_above"] == .9

    class Timeout(Exception): pass
    def boom(*a, **k): raise Timeout()
    assert ov.check_api("http://x", getter=boom)["state"] == "waking"
    def down(*a, **k): raise ConnectionError()
    assert ov.check_api("http://x", getter=down)["state"] == "offline"

    class Bad(R):
        status_code = 503
    assert ov.check_api("http://x", getter=lambda *a, **k: Bad())["state"] == "offline"
    assert "30 seconds" in ov.status_html({"state": "waking"})


def test_eval_summary_validation(tmp_path):
    good = {"generated": "2026-11-28T10:00", "phish_n": 100, "phish_caught": 90, "legit_n": 200, "legit_flagged": 4, "unseen_domains": True}
    p = tmp_path / "e.json"
    p.write_text(json.dumps(good))
    out = ov.load_eval_summary(p)
    assert out and out["generated"] == "2026-11-28"
    for bad in ({**good, "legit_flagged": 999}, {**good, "phish_n": 0}, {"x": 1}, [1], {**good, "legit_n": "abc"}):
        p.write_text(json.dumps(bad))
        assert ov.load_eval_summary(p) is None
    assert ov.load_eval_summary(tmp_path / "missing.json") is None
    p.write_text("not json")
    assert ov.load_eval_summary(p) is None


def test_markup_is_escaped_and_single_line():
    h = ov.record_scan([], payload("PHISHING", 91), "https://e.example/<script>alert(1)</script>", now=0)
    page = ov.recent_scans_html(h, now=120)
    assert "<script>" not in page and "&lt;script&gt;" in page
    model = ov.model_card_html(.4, .85, "<b>x</b>", None)
    assert "<b>x</b>" not in model and "Not yet measured" in model
    for chunk in (page, model, *ov.verdict_legend_cards(), ov.recent_scans_html([])):
        assert "\n" not in chunk


def test_model_card_reports_confidence_interval():
    e = {"generated": "2026-11-28", "phish_n": 100, "phish_caught": 90, "legit_n": 200, "legit_flagged": 4,
         "unseen_domains": False, "high_threshold": .85}
    card = ov.model_card_html(.4, .85, "M", e)
    assert "95% CI" in card and "not checked against the training set" in card


def test_app_has_no_demo_data_or_unbalanced_wrappers():
    src = (ROOT / "frontend" / "app_flagship.py").read_text()
    for word in ("DEMO_METRICS", "ILLUSTRATIVE", "synthetic", "Synthetic", "2,481"):
        assert word not in src, word
    # a wrapper opened in one st.markdown and closed in another renders as an empty box
    assert not re.search(r'st\.markdown\("</div>"', src)
    assert not re.search(r'st\.markdown\("<div class=.(surface|scanner-box).>"\s*,\s*unsafe', src)


def test_compact_result_strip():
    strip = ov.compact_result_html({"prediction": "PHISHING", "risk_score": 91.2, "final_url": "https://x.example/<b>"})
    assert "Phishing" in strip and "91.2% risk" in strip and "<b>" not in strip and "\n" not in strip
    for bad in (None, {}, {"prediction": "PHISHING", "risk_score": 500}, {"prediction": "??", "risk_score": 5}, "x"):
        assert ov.compact_result_html(bad) is None


def test_overview_is_compact_and_scanner_is_full():
    src = (ROOT / "frontend" / "app_flagship.py").read_text()
    assert 'scanner_section("overview", "Check a website", compact=True)' in src
    assert 'scanner_section("scanner")' in src
    assert 'key="page"' in src and "go_to_scanner" in src
