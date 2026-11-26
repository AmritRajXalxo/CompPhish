import importlib.util
import math
import random
from pathlib import Path
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("evaluate_live", Path(__file__).resolve().parents[1] / "scripts" / "evaluate_live.py")
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)


def test_wilson_interval():
    lo, hi = ev.wilson(50, 100)
    assert 0.40 < lo < 0.41 and 0.59 < hi < 0.60
    assert ev.wilson(0, 0)[0] != ev.wilson(0, 0)[0]          # nan for n=0
    lo, hi = ev.wilson(0, 20)
    assert lo == 0 or lo < 1e-9
    assert hi > 0.1                                          # zero errors in 20 still allows ~16%


def test_summarise_counts_and_auc():
    y = [1, 1, 1, 0, 0, 0]
    p = [0.9, 0.8, 0.3, 0.6, 0.2, 0.1]
    s = ev.summarise(y, p, thresholds=[0.5])
    r = s["rows"][0]
    assert (r["tp"], r["fp"], r["n_pos"], r["n_neg"]) == (2, 1, 3, 3)
    assert math.isclose(r["precision"], 2 / 3)
    assert s["roc_auc"] is not None and 0 <= s["roc_auc"] <= 1
    assert ev.summarise([1, 1], [0.9, 0.8])["roc_auc"] is None   # one class only


def test_parse_url_lines():
    txt = "http://a.com/x\nnot a url\nhttps://b.org\n  https://c.net/  \nftp://d.com\n"
    assert ev.parse_url_lines(txt) == ["http://a.com/x", "https://b.org", "https://c.net/"]


def _fake_run(tmp_path, monkeypatch, with_trust=False):
    import sklearn._loss._loss as L, sys
    sys.modules.setdefault("_loss", L)
    args = SimpleNamespace(phish=6, legit=6, seed=1, workers=2, hard_negatives=False, with_trust=with_trust,
                           phish_file=None, legit_file=None, research_app=None, research_models=None)
    html = "<html><head><title>x</title></head><body><h1>Hello</h1><a href='/a'>a</a></body></html>"

    def fetch(url):
        if "dead" in url:
            raise ValueError("Unable to resolve website hostname.")
        return {"final_url": url, "html": html}

    sources = {
        "phish": lambda n, rng, path: ([f"http://login-secure{i}.example-bad.top/verify?id={i}" for i in range(5)] + ["http://dead.example-bad.top/"], ["fake phishing source"]),
        "legit": lambda n, rng, path: ([f"https://www.site{i}.com/" for i in range(6)], ["fake legit source"]),
    }
    if with_trust:
        from backend import trust_signals as ts, scan_intel as si
        monkeypatch.setattr(ts, "_domain_age_days", lambda d: 5000)
        monkeypatch.setattr(ts, "_tls_valid", lambda h: True)
        monkeypatch.setattr(si, "tls_details", lambda h: {"status": "ok", "valid": True})
    return args, ev.run(args, fetch=fetch, sources=sources)


def test_end_to_end_report(tmp_path, monkeypatch):
    args, results = _fake_run(tmp_path, monkeypatch)
    assert len(results) == 12
    dead = [r for r in results if "dead" in r["url"]][0]
    assert dead["fetched"] is False and "Unable to resolve" in dead["error"]
    assert dead["url_only_p"] is not None and dead["deployed_p"] is None     # URL-only still scored
    ok = [r for r in results if r["fetched"]]
    assert all(r["deployed_p"] is not None for r in ok)
    path = ev.write_outputs(results, tmp_path / "out", args, ["note"])
    text = path.read_text()
    for needle in ("Read this first", "URL branch only", "Deployed hybrid model", "Worst legitimate pages", "95% CI"):
        assert needle in text
    assert (tmp_path / "out" / "results.csv").exists()


def test_with_trust_adds_final_verdict_without_threat_feeds(tmp_path, monkeypatch):
    args, results = _fake_run(tmp_path, monkeypatch, with_trust=True)
    got = [r["final_verdict"] for r in results if r["fetched"]]
    assert got and all(v in {"PHISHING", "NEEDS_REVIEW", "LIKELY_LEGITIMATE", "LEGITIMATE"} for v in got)
    text = ev.build_report(results, args, ["note"])
    assert "Final verdict after trust rules (threat feeds OFF)" in text


def test_report_rebuilds_from_csv(tmp_path, monkeypatch):
    args, results = _fake_run(tmp_path, monkeypatch)
    ev.write_outputs(results, tmp_path / "o1", args, ["n"])
    ev.main(["--from-results", str(tmp_path / "o1" / "results.csv"), "--out", str(tmp_path / "o2")])
    assert "Read this first" in (tmp_path / "o2" / "report.md").read_text()
