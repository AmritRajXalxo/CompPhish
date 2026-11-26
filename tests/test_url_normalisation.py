from backend.prediction_service import (
    clean_url_for_scoring, host_root_url, predict_website,
)

HTML = "<html><body><h1>Rules</h1><a href='/x'>x</a></body></html>"


def test_tracking_params_removed_real_params_kept():
    out = clean_url_for_scoring("https://a.com/p?q=1&utm_source=x&fbclid=Z&tag=d_1_2#f")
    assert out == "https://a.com/p?q=1"


def test_host_root():
    assert host_root_url("https://a.com/x/y?z=1") == "https://a.com/"


def test_tracking_param_does_not_change_result():
    base = "https://888starzgames.in/en/bonus/rules"
    a = predict_website(base, HTML)
    b = predict_website(base + "?tag=d_6381452m_53359c_&utm_campaign=x", HTML)
    assert a["hybrid_probability"] == b["hybrid_probability"]


def test_prediction_label_is_one_of_three():
    r = predict_website("https://example.com/", HTML)
    assert r["prediction"] in {"PHISHING", "LEGITIMATE", "NEEDS_REVIEW"}
