import json
import re
import sys
import types
import importlib.util
from pathlib import Path

from frontend import session_stats as ss

ROOT = Path(__file__).resolve().parents[1]


def res(pred="LEGITIMATE", risk=12.5):
    return {"prediction": pred, "risk_score": risk}


def test_record_orders_caps_and_ignores_bad_data():
    h = []
    for i in range(60):
        h = ss.record_scan(h, res(risk=i % 100), f"https://s{i}.example", now=1000 + i)
    assert len(h) == ss.MAX_HISTORY and h[0]["url"] == "https://s59.example"
    before = list(h)
    for bad in (None, "x", {"prediction": "WEIRD", "risk_score": 5}, {"prediction": "PHISHING", "risk_score": "nan"},
                {"prediction": "PHISHING", "risk_score": 150}, {"prediction": "PHISHING"}):
        assert ss.record_scan(h, bad, "u") == before


def test_summary_and_empty_state_cards_have_no_fake_numbers():
    assert ss.summarise([])["avg_risk"] is None
    empty = " ".join(" ".join(c) for c in ss.cards(ss.summarise([]), None))
    assert "No scans yet" in empty and "Not yet" in empty
    for fake in ("2,481", "384", "99.9", "18.6"):
        assert fake not in empty
    h = ss.record_scan(ss.record_scan([], res("PHISHING", 90), "a"), res("LEGITIMATE", 10), "b")
    s = ss.summarise(h)
    assert s["total"] == 2 and s["flagged"] == 1 and s["avg_risk"] == 50
    vals = [c[1] for c in ss.cards(s, None)]
    assert vals[:3] == ["2", "1", "50.0%"]


def test_eval_summary_validation(tmp_path):
    good = {"generated": "2026-11-28T10:00", "phish_n": 100, "phish_caught": 90, "legit_n": 200, "legit_flagged": 4, "unseen_domains": True}
    p = tmp_path / "e.json"
    p.write_text(json.dumps(good))
    ev = ss.load_eval_summary(p)
    assert ev and ev["generated"] == "2026-11-28"
    card = ss.cards(ss.summarise([]), ev)[3]
    assert card[1] == "2.0%" and "unseen domains" in card[2]
    for bad in ({**good, "legit_flagged": 999}, {**good, "phish_n": 0}, {"x": 1}, [1], {**good, "legit_n": "abc"}):
        p.write_text(json.dumps(bad))
        assert ss.load_eval_summary(p) is None
    assert ss.load_eval_summary(tmp_path / "missing.json") is None
    p.write_text("not json")
    assert ss.load_eval_summary(p) is None


def test_overview_has_no_synthetic_data_and_records_scans():
    src = (ROOT / "frontend" / "app_flagship.py").read_text()
    for word in ("DEMO_METRICS", "ILLUSTRATIVE", "Synthetic", "synthetic", "2,481", "Scans per day (sample)", "Share of<br>sample scans"):
        assert word not in src, word
    assert "ss.record_scan(" in src and "ss.cards(" in src
    assert "padding:0;overflow:hidden" in src  # chart container no longer wider than its column


def test_headline_summary_excludes_named_and_hard_negative_groups():
    spec = importlib.util.spec_from_file_location("evl", ROOT / "scripts" / "evaluate_live.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules["evl"] = m
    spec.loader.exec_module(m)
    rows = ([{"group": "phishing", "label": 1, "deployed_p": 0.9}] * 3 + [{"group": "phishing", "label": 1, "deployed_p": 0.2}]
            + [{"group": "legitimate", "label": 0, "deployed_p": 0.1}] * 5 + [{"group": "legitimate", "label": 0, "deployed_p": 0.9}]
            + [{"group": "hard_negative", "label": 0, "deployed_p": 0.99}] * 4)
    s = m.headline_summary(rows, types.SimpleNamespace(train_domains="x.txt"))
    assert (s["phish_n"], s["phish_caught"], s["legit_n"], s["legit_flagged"], s["unseen_domains"]) == (4, 3, 6, 1, True)
    assert m.headline_summary([], types.SimpleNamespace(train_domains=None)) is None
