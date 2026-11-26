from backend import trust_signals as ts


def _result(pred="PHISHING"):
    return {"prediction": pred, "hybrid_probability": 0.88}


def _patch(monkeypatch, age, tls):
    ts._cache.clear()
    monkeypatch.setattr(ts, "_domain_age_days", lambda d: age)
    monkeypatch.setattr(ts, "_tls_valid", lambda h: tls)


def test_registered_domain():
    assert ts.registered_domain("www.malwarebytes.com") == "malwarebytes.com"
    assert ts.registered_domain("a.b.example.co.uk") == "example.co.uk"


def test_shared_hosting_detected():
    assert ts.is_shared_hosting("evil.weebly.com")
    assert ts.is_shared_hosting("x.workers.dev")
    assert not ts.is_shared_hosting("malwarebytes.com")


def test_established_site_downgraded_to_needs_review(monkeypatch):
    _patch(monkeypatch, 8000, True)
    t = ts.assess_trust("https://www.malwarebytes.com/scam-check/link")
    out = ts.apply_trust_adjustment(_result(), t)
    assert out["prediction"] == "NEEDS_REVIEW"
    assert out["model_prediction"] == "PHISHING"
    assert "years old" in out["decision_note"]


def test_new_domain_keeps_phishing(monkeypatch):
    _patch(monkeypatch, 5, True)
    out = ts.apply_trust_adjustment(_result(), ts.assess_trust("https://paypa1-login.top/"))
    assert out["prediction"] == "PHISHING"
    assert "5 days old" in out["decision_note"]


def test_unknown_age_is_not_trusted(monkeypatch):
    _patch(monkeypatch, None, True)
    out = ts.apply_trust_adjustment(_result(), ts.assess_trust("https://example.org/"))
    assert out["prediction"] == "PHISHING"


def test_bad_certificate_is_not_trusted(monkeypatch):
    _patch(monkeypatch, 8000, False)
    out = ts.apply_trust_adjustment(_result(), ts.assess_trust("https://old-but-broken.com/"))
    assert out["prediction"] == "PHISHING"


def test_shared_hosting_never_trusted(monkeypatch):
    _patch(monkeypatch, 9000, True)
    out = ts.apply_trust_adjustment(_result(), ts.assess_trust("https://fake-bank.weebly.com/login"))
    assert out["prediction"] == "PHISHING"


def test_redirect_to_other_domain_not_trusted(monkeypatch):
    _patch(monkeypatch, 9000, True)
    t = ts.assess_trust("https://bit.example.com/x", "https://old-site.com/")
    assert t["redirected_to_other_domain"] and not t["established"]


def test_never_upgrades_to_legitimate(monkeypatch):
    _patch(monkeypatch, 9000, True)
    for pred in ("LEGITIMATE", "NEEDS_REVIEW"):
        out = ts.apply_trust_adjustment(_result(pred), ts.assess_trust("https://old.com/"))
        assert out["prediction"] == pred
