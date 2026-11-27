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
        "phish": lambda n, rng, path: ([f"http://login-secure{i}.bad-site{i}.top/verify?id={i}" for i in range(5)] + ["http://dead.dead-site.top/"], ["fake phishing source"]),
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


# ---- unseen-domain design rules ----
def test_dedupe_keeps_one_url_per_domain_and_drops_training_domains():
    urls = ["https://a.example.com/x", "https://www.example.com/y", "https://other.org/", "https://seen-in-training.net/z"]
    kept, dup, tr = ev.dedupe_domains(urls, exclude={"seen-in-training.net"})
    assert kept == ["https://a.example.com/x", "https://other.org/"]
    assert (dup, tr) == (1, 1)


def test_domain_list_loader(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("Example.com\n\n  other.org  \n")
    assert ev.load_domain_list(str(f)) == {"example.com", "other.org"}
    assert ev.load_domain_list(None) == set()


def test_page_complexity_uses_fixed_thresholds_not_names():
    small = "<html><body><script></script></body></html>"
    c = ev.page_complexity(small, "https://google.com/")           # famous name changes nothing
    assert c["complex"] is False and c["has_password"] is False
    many = "<html><body>" + "<script src='https://c%d.example/x.js'></script>" % 0 + "".join(f"<script src='https://cdn{i}.net/a.js'></script>" for i in range(12)) + "</body></html>"
    assert ev.page_complexity(many, "https://x.test/")["complex"] is True      # >= 10 external domains
    big = "<html><body>" + "x" * 250_000 + "</body></html>"
    assert ev.page_complexity(big, "https://x.test/")["complex"] is True       # >= 200 KB
    login = "<form><input type='PASSWORD'></form>"
    assert ev.page_complexity(login, "https://x.test/")["has_password"] is True


def _row(label, p, cx, pw=False, group=None):
    return {"group": group or ("phishing" if label else "legitimate"), "label": label, "url": "u", "fetched": True, "error": "",
            "deployed_p": p, "url_p": p, "html_p": p, "text_p": p, "url_only_p": p, "complex": cx, "has_password": pw,
            "final_verdict": "", "research_p": None}


def test_strata_table_hides_tiny_cells_and_warns_about_shortcut():
    rows = [_row(0, 0.9, True) for _ in range(40)] + [_row(0, 0.1, False) for _ in range(40)] + [_row(1, 0.9, False) for _ in range(40)] \
           + [_row(1, 0.9, True) for _ in range(3)]
    text = "\n".join(ev.strata_section(rows))
    assert "complex pages" in text and "simple pages" in text and "login pages" in text
    assert "too few (n=3)" in text                     # complex phishing: 3 pages -> no rate
    assert "Shortcut warning" in text
    assert ev.strata_section([_row(0, 0.1, None)]) == []   # old CSVs without strata columns


def test_report_marks_named_sites_as_sanity_only(tmp_path, monkeypatch):
    args, results = _fake_run(tmp_path, monkeypatch)
    for r in results[:2]:
        r["group"] = "hard_negative"
    text = ev.build_report(results, args, ["n"])
    assert "regression check only" in text and "never be used for" in text


def test_run_records_domains_and_flags_missing_train_domains(tmp_path, monkeypatch):
    args, results = _fake_run(tmp_path, monkeypatch)
    assert all(r["reg_domain"] for r in results)
    assert "complex" in results[0]
    assert "NOT guaranteed" in "\n".join(ev.run.source_notes)


def test_headline_summary_uses_deployed_scores_and_excludes_hard_negatives(tmp_path):
    import importlib.util, sys, types
    spec = importlib.util.spec_from_file_location("evl", Path(__file__).resolve().parents[1] / "scripts" / "evaluate_live.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules["evl"] = m
    spec.loader.exec_module(m)
    rows = ([{"group": "phishing", "label": 1, "deployed_p": 0.9}] * 3 + [{"group": "phishing", "label": 1, "deployed_p": 0.2}]
            + [{"group": "legitimate", "label": 0, "deployed_p": 0.1}] * 5 + [{"group": "legitimate", "label": 0, "deployed_p": 0.9}]
            + [{"group": "hard_negative", "label": 0, "deployed_p": 0.99}] * 4)
    s = m.headline_summary(rows, types.SimpleNamespace(train_domains="x.txt"))
    assert (s["phish_n"], s["phish_caught"], s["legit_n"], s["legit_flagged"], s["unseen_domains"]) == (4, 3, 6, 1, True)
    assert m.headline_summary([], types.SimpleNamespace(train_domains=None)) is None
