from frontend import ui_components as ui


def test_formatting_helpers():
    assert ui.fmt_seconds(0.85) == "850 ms"
    assert ui.fmt_seconds(2.345) == "2.35 s"
    assert ui.fmt_seconds(None) is None and ui.fmt_seconds("x") is None
    assert ui.fmt_bytes(512) == "512 B"
    assert ui.fmt_bytes(2048) == "2.0 KB"
    assert ui.fmt_bytes(5 * 1024 * 1024) == "5.0 MB"
    assert ui.fmt_age(8000)[0] == "22 years"
    assert ui.fmt_age(200)[0] == "6 months"
    assert ui.fmt_age(1)[0] == "1 day"
    assert ui.fmt_age(None) is None and ui.fmt_age(-5) is None


def test_tls_states():
    assert ui.tls_state({"status": "ok", "valid": True, "days_left": 200})[:2] == ("good", "VALID")
    assert ui.tls_state({"status": "ok", "valid": True, "days_left": 10})[:2] == ("warn", "EXPIRES SOON")
    assert ui.tls_state({"status": "ok", "valid": True, "days_left": -3})[:2] == ("bad", "EXPIRED")
    assert ui.tls_state({"status": "ok", "valid": False})[:2] == ("bad", "INVALID")
    assert ui.tls_state({"status": "unavailable"})[:2] == ("neutral", "UNAVAILABLE")
    assert ui.tls_state(None)[1] == "UNAVAILABLE"


def test_age_tone_and_status_tone():
    assert ui.age_tone(3) == "bad" and ui.age_tone(200) == "warn"
    assert ui.age_tone(5000) == "good" and ui.age_tone(None) == "neutral"
    assert ui.status_tone(200) == "good" and ui.status_tone(404) == "warn"
    assert ui.status_tone(503) == "bad" and ui.status_tone(None) == "neutral"


def test_everything_from_api_is_escaped():
    evil = "<img src=x onerror=alert(1)>"
    out = ui.connection_card({"status": "ok", "valid": True, "days_left": 90, "issuer": evil, "subject": evil, "not_after": evil, "protocol": evil})
    out += ui.domain_card({"registered_domain": evil, "domain_age_days": 400})
    out += ui.threat_card({"overall": "no_match", "sources": [{"name": evil, "status": "no_match"}]})
    out += ui.behaviour_card({"status": "ok", "max_severity": "high", "findings": [{"severity": "high", "text": evil}]})
    out += ui.location_card({"status": "ok", "country": evil, "ip": evil, "asn": evil, "asn_name": evil})
    out += ui.preview_card("https://x.test/a'onerror='alert(1)")
    assert "<img src=x" not in out and "onerror=alert" not in out.replace("&lt;img src=x onerror=alert(1)&gt;", "")
    assert "'onerror='" not in out


def test_missing_values_render_dash_not_invented_data():
    assert "Location unavailable" in ui.location_card(None)
    assert "Location unavailable" in ui.location_card({"status": "unavailable"})
    assert "Unknown" in ui.domain_card({})
    assert "UNAVAILABLE" in ui.connection_card({})
    stats = ui.stats_grid({}, {})
    assert stats.count("ci-na") >= 6


def test_no_match_is_never_called_safe():
    out = ui.threat_card({"overall": "no_match", "sources": [{"name": "OpenPhish", "status": "no_match"}]})
    assert "NO MATCH" in out and "does not mean the site is safe" in out
    assert ">SAFE<" not in out
    listed = ui.threat_card({"overall": "match", "sources": [{"name": "OpenPhish", "status": "match"}]})
    assert "THREAT LISTED" in listed and "ci-bad" in listed
    assert "UNAVAILABLE" in ui.threat_card({"overall": "unavailable", "sources": []})


def test_page_behaviour_colours():
    clean = ui.behaviour_card({"status": "ok", "max_severity": None, "findings": []})
    assert "Nothing significant found" in clean and "ci-t-good" in clean
    sus = ui.behaviour_card({"status": "ok", "max_severity": "medium", "findings": [{"severity": "medium", "text": "Hidden cross-domain iframe"}]})
    assert "SUSPICIOUS" in sus and "ci-t-warn" in sus
    bad = ui.behaviour_card({"status": "ok", "max_severity": "high", "findings": [{"severity": "high", "text": "Password form submits to a different domain (x)."}]})
    assert "MALICIOUS" in bad and "ci-t-bad" in bad
    assert "NOT CHECKED" in ui.behaviour_card({"status": "unavailable"})


def test_domain_card_badges():
    est = ui.domain_card({"domain_age_days": 8000, "established": True, "shared_hosting": False, "registered_domain": "a.com"})
    assert "ESTABLISHED" in est and "ci-m-good" in est
    shared = ui.domain_card({"domain_age_days": 8000, "established": False, "shared_hosting": True})
    assert ">YES<" in shared.replace("</svg></span>", "").replace("'>", ">") or "YES" in shared
    young = ui.domain_card({"domain_age_days": 5, "established": False})
    assert "ci-m-bad" in young and "5 days" in young


def test_markup_has_no_blank_lines_or_indentation():
    # Streamlit's Markdown would render these as code blocks.
    for out in (ui.connection_card({"status": "ok", "valid": True, "days_left": 90}), ui.domain_card({"domain_age_days": 10}),
                ui.threat_card({}), ui.behaviour_card({"status": "ok", "findings": []}), ui.location_card({}), ui.stats_grid({}, {})):
        assert "\n" not in out


def test_shared_hosting_unknown_when_missing():
    assert "UNKNOWN" in ui.domain_card({})
    assert ">NO<" not in ui.domain_card({}).replace("</svg></span>", "")
