from backend import scan_intel as si
from backend import reports_store as rs
from backend.verdict import compose_verdict

URL = "https://shop.example.com/login"


def test_password_form_to_other_domain_is_high():
    html = '<form action="https://evil.top/post"><input type="password"></form>'
    r = si.page_behaviour(html, URL)
    assert r["has_password_form"] and r["max_severity"] == "high"


def test_plain_password_form_is_info_only():
    r = si.page_behaviour('<form action="/login"><input type="password"></form>', URL)
    assert r["has_password_form"] and r["max_severity"] == "info"


def test_hidden_iframe_alone_is_low():
    html = '<iframe src="https://stats.other.net/x" style="display:none"></iframe>'
    assert si.page_behaviour(html, URL)["max_severity"] == "low"


def test_hidden_iframe_with_password_form_is_medium():
    html = '<iframe src="https://stats.other.net/x" width="0"></iframe><form action="/l"><input type="password"></form>'
    assert si.page_behaviour(html, URL)["max_severity"] == "medium"


def test_footprint_counts():
    html = '<script src="https://cdn.a.com/x.js"></script><img src="/i.png"><a href="https://b.com">b</a>'
    r = si.network_footprint(html, URL, resolve_limit=0)
    assert r["resources"] == 2 and r["links"] == 1 and "cdn.a.com" in r["external_domains"]


def test_feed_normalisation():
    assert si._norm("https://A.com/x/?q=1") == "a.com/x"


# ---- verdict composition ----
def _res(pred):
    return {"prediction": pred, "hybrid_probability": 0.6, "redirect_chain": []}


EST = {"established": True, "domain_age_days": 8000, "registered_domain": "kaggle.com", "tls_valid": True}
YOUNG = {"established": False, "domain_age_days": 3, "registered_domain": "x.top", "tls_valid": True}
NOFEED = {"overall": "no_match", "sources": []}
FEED = {"overall": "match", "sources": [{"name": "OpenPhish community feed", "status": "match"}]}
CLEAN = {"status": "ok", "max_severity": None, "has_password_form": False, "findings": []}
BAD = {"status": "ok", "max_severity": "high", "has_password_form": True, "findings": []}
TLS = {"valid": True}


def test_feed_match_forces_phishing():
    assert compose_verdict(_res("LEGITIMATE"), EST, FEED, CLEAN, TLS)["prediction"] == "PHISHING"


def test_established_clean_uncertain_becomes_likely_legit():
    assert compose_verdict(_res("NEEDS_REVIEW"), EST, NOFEED, CLEAN, TLS)["prediction"] == "LIKELY_LEGITIMATE"


def test_password_form_blocks_upgrade():
    pw = dict(CLEAN, has_password_form=True, max_severity="info")
    assert compose_verdict(_res("NEEDS_REVIEW"), EST, NOFEED, pw, TLS)["prediction"] == "NEEDS_REVIEW"


def test_young_domain_never_upgraded():
    assert compose_verdict(_res("NEEDS_REVIEW"), YOUNG, NOFEED, CLEAN, TLS)["prediction"] == "NEEDS_REVIEW"


def test_established_but_severe_behaviour_keeps_phishing():
    assert compose_verdict(_res("PHISHING"), EST, NOFEED, BAD, TLS)["prediction"] == "PHISHING"


def test_established_phishing_downgraded_when_clean():
    assert compose_verdict(_res("PHISHING"), EST, NOFEED, CLEAN, TLS)["prediction"] == "NEEDS_REVIEW"


def test_explanation_and_steps_present():
    out = compose_verdict(_res("NEEDS_REVIEW"), YOUNG, NOFEED, CLEAN, TLS)
    assert len(out["explanation"]) >= 5 and out["next_steps"]


# ---- reports ----
def test_reports_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(rs, "DB_PATH", str(tmp_path / "r.db"))
    rs._hits.clear()
    s = rs.add_report("https://a.com/x?token=SECRET", "scam", "  fake   login ", "1.2.3.4")
    assert s["total"] == 1 and s["scam"] == 1
    assert rs.summary("https://a.com/x")["total"] == 1      # query ignored
    assert "SECRET" not in str(rs.summary("https://a.com/x"))


def test_reports_validation_and_rate_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(rs, "DB_PATH", str(tmp_path / "r.db"))
    rs._hits.clear()
    for bad in ("ftp://a.com", "nonsense"):
        try:
            rs.add_report(bad, "scam", "", "c"); assert False
        except ValueError:
            pass
    for _ in range(rs.RATE_LIMIT):
        rs.add_report("https://a.com/", "safe", "", "c")
    try:
        rs.add_report("https://a.com/", "safe", "", "c"); assert False
    except PermissionError:
        pass
