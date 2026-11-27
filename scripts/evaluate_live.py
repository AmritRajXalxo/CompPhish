#!/usr/bin/env python
"""
CompPhish live evaluation.

Fetches real phishing and legitimate pages, runs the app's model(s) on them, and
writes an honest report: phishing caught, legitimate sites wrongly flagged (with
95% confidence intervals), and the exact URLs that failed.

Run it where the internet is reachable (your computer or Colab), from the repo root:

    python scripts/evaluate_live.py --phish 300 --legit 300 --hard-negatives

Optional:
    --with-trust                      also report the final verdict after the domain-age /
                                      TLS / page-behaviour rules (threat feeds are switched
                                      OFF here: phishing sampled from OpenPhish would match
                                      itself and inflate the result)
    --research-app DIR --research-models DIR
                                      also score the 44/33/TF-IDF research model (DIR = the
                                      folder with the `compphish` package; models folder
                                      holds research_bundle.joblib)
    --phish-file F / --legit-file F   use your own URL lists (one URL per line)
    --train-domains FILE              file of registered domains used in training (one per line);
                                      those domains are excluded so every evaluated domain is unseen
    --from-results CSV                rebuild the report from a previous results.csv

Design rules (so the numbers measure generalisation, not memorisation):
  * at most ONE URL per registered domain per group, and none from --train-domains;
  * "complex page" and "login page" strata are defined from the page itself with fixed,
    pre-declared thresholds, never from site names;
  * the named-site list (Google-style examples) is a regression/sanity set only. It is
    excluded from every headline table and must never be used for tuning or training.

Read the caveats at the top of the generated report before trusting any number.
"""

from __future__ import annotations

import argparse
import csv
import io
import math
import random
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

OPENPHISH = "https://openphish.com/feed.txt"
PHISHDB = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE/phishing-links-ACTIVE1.txt"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
CITIZENLAB = "https://raw.githubusercontent.com/citizenlab/test-lists/master/lists/global.csv"

# Real, well-known sites that talk about phishing, scams or security. A good
# model must NOT call these phishing. Some may fail to load; that is reported.
HARD_NEGATIVES = [
    "https://www.malwarebytes.com/", "https://www.malwarebytes.com/scam-check/link",
    "https://www.kaggle.com/", "https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls",
    "https://www.phishing.org/", "https://www.cisa.gov/", "https://www.ftc.gov/",
    "https://consumer.ftc.gov/", "https://www.virustotal.com/", "https://krebsonsecurity.com/",
    "https://haveibeenpwned.com/", "https://www.openphish.com/", "https://www.phishtank.com/",
    "https://www.sans.org/", "https://www.owasp.org/", "https://owasp.org/", "https://www.eff.org/",
    "https://www.wikipedia.org/", "https://en.wikipedia.org/wiki/Phishing", "https://www.bbc.com/news",
    "https://www.reuters.com/", "https://www.nytimes.com/", "https://www.theguardian.com/",
    "https://github.com/", "https://stackoverflow.com/", "https://www.mozilla.org/",
    "https://support.google.com/", "https://support.microsoft.com/", "https://www.apple.com/",
    "https://www.paypal.com/", "https://www.chase.com/", "https://www.bankofamerica.com/",
    "https://www.wellsfargo.com/", "https://www.amazon.com/", "https://www.ebay.com/",
    "https://www.mit.edu/", "https://www.stanford.edu/", "https://www.ox.ac.uk/",
    "https://www.nist.gov/", "https://www.nasa.gov/",
]

THRESHOLDS = [0.40, 0.50, 0.54, 0.70, 0.78, 0.85]


# --------------------------------------------------------------------------
# Statistics (pure functions)
# --------------------------------------------------------------------------

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion k/n."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - h) / d), min(1.0, (c + h) / d))


def rate_text(k: int, n: int) -> str:
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{k / n:.1%} ({k}/{n}; 95% CI {lo:.1%}-{hi:.1%})"


def summarise(y: list[int], p: list[float], thresholds=THRESHOLDS) -> dict:
    """Threshold table plus ROC-AUC / PR-AUC when both classes are present."""
    n_pos = sum(1 for v in y if v == 1)
    n_neg = sum(1 for v in y if v == 0)
    rows = []
    for t in thresholds:
        tp = sum(1 for yy, pp in zip(y, p) if yy == 1 and pp >= t)
        fp = sum(1 for yy, pp in zip(y, p) if yy == 0 and pp >= t)
        prec = tp / (tp + fp) if (tp + fp) else float("nan")
        rows.append({"threshold": t, "tp": tp, "fp": fp, "n_pos": n_pos, "n_neg": n_neg, "precision": prec})
    out = {"n_pos": n_pos, "n_neg": n_neg, "rows": rows, "roc_auc": None, "pr_auc": None}
    if n_pos and n_neg:
        try:
            from sklearn.metrics import average_precision_score, roc_auc_score
            out["roc_auc"] = float(roc_auc_score(y, p))
            out["pr_auc"] = float(average_precision_score(y, p))
        except Exception:
            pass
    return out


def table_md(s: dict) -> str:
    lines = ["| Threshold | Phishing caught | Legitimate wrongly flagged | Precision |", "|---|---|---|---|"]
    for r in s["rows"]:
        prec = "n/a" if r["precision"] != r["precision"] else f"{r['precision']:.1%}"
        lines.append(f"| {r['threshold']:.2f} | {rate_text(r['tp'], r['n_pos'])} | {rate_text(r['fp'], r['n_neg'])} | {prec} |")
    auc = ""
    if s["roc_auc"] is not None:
        auc = f"\nROC-AUC {s['roc_auc']:.3f} · PR-AUC {s['pr_auc']:.3f} (n = {s['n_pos']} phishing, {s['n_neg']} legitimate)\n"
    return "\n".join(lines) + "\n" + auc


# --------------------------------------------------------------------------
# Domain hygiene and page strata
# --------------------------------------------------------------------------

# Pre-declared thresholds. Do NOT adjust them after looking at results.
COMPLEX_HTML_BYTES = 200_000
COMPLEX_SCRIPTS = 30
COMPLEX_EXTERNAL_DOMAINS = 10
MIN_STRATUM_N = 30        # below this a stratum is reported as "too few to conclude"


def reg_domain(url: str) -> str:
    from backend.trust_signals import registered_domain
    return registered_domain((urlparse(url).hostname or "").lower())


def load_domain_list(path: str | None) -> set[str]:
    if not path:
        return set()
    return {line.strip().lower() for line in Path(path).read_text(errors="ignore").splitlines() if line.strip()}


def dedupe_domains(urls: list[str], exclude: set[str]) -> tuple[list[str], int, int]:
    """Keep the first URL per registered domain; drop domains in `exclude`. Returns (kept, dropped_dupes, dropped_train)."""
    seen, kept, dup, tr = set(), [], 0, 0
    for u in urls:
        d = reg_domain(u)
        if d in exclude:
            tr += 1
        elif d in seen:
            dup += 1
        else:
            seen.add(d)
            kept.append(u)
    return kept, dup, tr


def page_complexity(html: str, final_url: str) -> dict:
    """Page-intrinsic descriptors used for strata (no site names involved)."""
    out = {"html_bytes": len(html.encode("utf-8", "ignore")), "n_scripts": None, "n_ext_domains": None,
           "has_password": None, "complex": None}
    try:
        from backend.scan_intel import _soup, network_footprint
        soup = _soup(html[:1_500_000])
        out["n_scripts"] = len(soup.find_all("script"))
        out["has_password"] = bool(soup.find("input", attrs={"type": lambda v: v and v.lower() == "password"}))
        net = network_footprint(html, final_url, resolve_limit=0)
        out["n_ext_domains"] = len(net.get("external_domains", [])) if net.get("status") == "ok" else None
        out["complex"] = bool(out["html_bytes"] >= COMPLEX_HTML_BYTES or out["n_scripts"] >= COMPLEX_SCRIPTS
                              or (out["n_ext_domains"] or 0) >= COMPLEX_EXTERNAL_DOMAINS)
    except Exception:
        pass
    return out


# --------------------------------------------------------------------------
# URL sources
# --------------------------------------------------------------------------

def _http_text(url: str, timeout: float = 30.0, binary: bool = False):
    import httpx
    r = httpx.get(url, timeout=timeout, follow_redirects=True, headers={"User-Agent": "CompPhishEval/1.0"})
    r.raise_for_status()
    return r.content if binary else r.text


def parse_url_lines(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("http://", "https://")) and len(line) < 2000:
            out.append(line)
    return out


def load_phishing(n: int, rng: random.Random, path: str | None) -> tuple[list[str], list[str]]:
    notes, pool = [], []
    if path:
        pool = parse_url_lines(Path(path).read_text(errors="ignore"))
        notes.append(f"phishing URLs from file {path}: {len(pool)}")
    else:
        for name, url in (("OpenPhish", OPENPHISH), ("Phishing.Database", PHISHDB)):
            try:
                got = parse_url_lines(_http_text(url))
                notes.append(f"{name}: {len(got)} URLs available")
                pool.extend(rng.sample(got, min(len(got), n)))
            except Exception as exc:
                notes.append(f"{name}: could not download ({type(exc).__name__})")
    pool = sorted(set(pool))
    rng.shuffle(pool)
    return pool[:n], notes


def load_legit(n: int, rng: random.Random, path: str | None, top_n: int = 5000) -> tuple[list[str], list[str]]:
    notes, pool = [], []
    if path:
        pool = parse_url_lines(Path(path).read_text(errors="ignore"))
        notes.append(f"legitimate URLs from file {path}: {len(pool)}")
    else:
        try:
            z = zipfile.ZipFile(io.BytesIO(_http_text(TRANCO, 60, binary=True)))
            rows = z.read(z.namelist()[0]).decode().splitlines()[:top_n]
            domains = [r.split(",", 1)[1] for r in rows if "," in r]
            pool.extend(f"https://{d}/" for d in rng.sample(domains, min(len(domains), n)))
            notes.append(f"Tranco top {top_n}: sampled {min(len(domains), n)} home pages")
        except Exception as exc:
            notes.append(f"Tranco: could not download ({type(exc).__name__})")
        try:
            rows = list(csv.DictReader(io.StringIO(_http_text(CITIZENLAB))))
            got = [r["url"] for r in rows if r.get("url", "").startswith("http")]
            pool.extend(rng.sample(got, min(len(got), n)))
            notes.append(f"CitizenLab list: {len(got)} URLs available (real pages with paths)")
        except Exception as exc:
            notes.append(f"CitizenLab: could not download ({type(exc).__name__})")
    pool = sorted(set(pool))
    rng.shuffle(pool)
    return pool[:n], notes


# --------------------------------------------------------------------------
# Fetch + score
# --------------------------------------------------------------------------

def fetch_all(items: list[tuple[str, str, int]], workers: int, fetch) -> dict[str, dict]:
    """items = (url, group, label). Returns url -> fetch result dict."""
    out: dict[str, dict] = {}

    def one(url):
        t0 = time.time()
        try:
            r = fetch(url)
            return url, {"ok": True, "final_url": r["final_url"], "html": r["html"], "secs": time.time() - t0}
        except Exception as exc:
            return url, {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:120]}", "secs": time.time() - t0}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(one, u) for u, _, _ in items]
        for i, f in enumerate(as_completed(futs), 1):
            url, res = f.result()
            out[url] = res
            if i % 25 == 0 or i == len(futs):
                print(f"  fetched {i}/{len(futs)}", flush=True)
    return out


def score_deployed_url_only(url: str) -> float:
    """URL branch only, with the app's current normalisation (cleaned URL + host, averaged)."""
    from backend.prediction_service import clean_url_for_scoring, host_root_url, _url_branch_probability
    return (_url_branch_probability(clean_url_for_scoring(url)) + _url_branch_probability(host_root_url(url))) / 2


def load_research(app_dir: str, models_dir: str):
    sys.path.insert(0, str(Path(app_dir).resolve()))
    from compphish.core.predictor import ResearchPredictor
    return ResearchPredictor.load(models_dir)


def run(args, fetch=None, sources=None) -> list[dict]:
    rng = random.Random(args.seed)
    if fetch is None:
        from backend.webpage_fetcher import fetch_webpage as fetch
    load_p = (sources or {}).get("phish", load_phishing)
    load_l = (sources or {}).get("legit", load_legit)

    phish, n1 = load_p(args.phish, rng, args.phish_file)
    legit, n2 = load_l(args.legit, rng, args.legit_file)
    exclude = load_domain_list(getattr(args, "train_domains", None))
    phish, d1, t1 = dedupe_domains(phish, exclude)
    legit, d2, t2 = dedupe_domains(legit, exclude)
    n1 = n1 + [f"domain hygiene: phishing dropped {d1} same-domain and {t1} training-domain URLs; "
               f"legitimate dropped {d2} and {t2}" + ("" if exclude else " (no --train-domains file given: unseen-domain status NOT guaranteed)")]
    items = [(u, "phishing", 1) for u in phish] + [(u, "legitimate", 0) for u in legit]
    if args.hard_negatives:
        items += [(u, "hard_negative", 0) for u in HARD_NEGATIVES]
    run.source_notes = n1 + n2
    print(f"Sampled {len(phish)} phishing, {len(legit)} legitimate, "
          f"{len(HARD_NEGATIVES) if args.hard_negatives else 0} hard negatives. Fetching...")
    fetched = fetch_all(items, args.workers, fetch)

    research = None
    if args.research_app and args.research_models:
        research = load_research(args.research_app, args.research_models)
        print("Research model loaded:", research.available_modes())

    from backend.prediction_service import predict_website, HIGH_THRESHOLD, LOW_THRESHOLD  # noqa: F401
    results = []
    for url, group, label in items:
        f = fetched[url]
        row = {"group": group, "label": label, "url": url, "fetched": f["ok"], "error": f.get("error", ""),
               "final_url": f.get("final_url", ""), "url_only_p": None, "deployed_p": None, "url_p": None,
               "html_p": None, "text_p": None, "research_p": None, "research_mode": "", "final_verdict": "",
               "reg_domain": reg_domain(url), "html_bytes": None, "n_scripts": None, "n_ext_domains": None,
               "has_password": None, "complex": None}
        try:
            row["url_only_p"] = round(score_deployed_url_only(url), 6)
        except Exception as exc:
            row["error"] = (row["error"] + f" url-score:{type(exc).__name__}").strip()
        if f["ok"]:
            html = f["html"]
            row.update(page_complexity(html, f["final_url"]))
            try:
                r = predict_website(url, html)
                row.update(deployed_p=r["hybrid_probability"], url_p=r["branch_probabilities"]["url"],
                           html_p=r["branch_probabilities"]["html"], text_p=r["branch_probabilities"]["text"])
                if args.with_trust:
                    row["final_verdict"] = _final_verdict(r, url, f["final_url"], html)
            except Exception as exc:
                row["error"] = (row["error"] + f" deployed:{type(exc).__name__}: {str(exc)[:80]}").strip()
            if research is not None:
                try:
                    rr = research.predict(f["final_url"], html)
                    row["research_mode"] = rr.get("mode") or ""
                    if rr.get("probability") is not None:
                        row["research_p"] = round(rr["probability"], 6)
                except Exception as exc:
                    row["error"] = (row["error"] + f" research:{type(exc).__name__}: {str(exc)[:80]}").strip()
        results.append(row)
    return results


def _final_verdict(result: dict, url: str, final_url: str, html: str) -> str:
    """Final verdict after trust rules. Threat feeds are deliberately OFF (see module docstring)."""
    from urllib.parse import urlparse as _u
    from backend.scan_intel import page_behaviour, tls_details
    from backend.trust_signals import assess_trust
    from backend.verdict import compose_verdict
    host = (_u(final_url).hostname or "").lower()
    feeds = {"overall": "unavailable", "sources": []}
    out = compose_verdict(dict(result, redirect_chain=[]), assess_trust(url, final_url), feeds,
                          page_behaviour(html, final_url), tls_details(host))
    return out["prediction"]


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def write_outputs(results: list[dict], out_dir: Path, args, source_notes: list[str]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    cols = list(results[0].keys()) if results else []
    with open(out_dir / "results.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(results)
    (out_dir / "report.md").write_text(build_report(results, args, source_notes))
    return out_dir / "report.md"


def _g(rows, group):
    return [r for r in rows if r["group"] == group]


def _pairs(rows, key):
    use = [r for r in rows if r.get(key) not in (None, "")]
    return [int(r["label"]) for r in use], [float(r[key]) for r in use]


def _truthy(v) -> bool:
    return str(v) in ("True", "true", "1")


def strata_section(fetched: list[dict]) -> list[str]:
    if not any(r.get("complex") not in (None, "") for r in fetched):
        return []
    scored = [r for r in fetched if r.get("deployed_p") not in (None, "") and r.get("complex") not in (None, "")]
    L = ["## 4b. By page type (defined from the page itself, thresholds fixed in advance)", "",
         f"Complex page = HTML >= {COMPLEX_HTML_BYTES:,} bytes, or >= {COMPLEX_SCRIPTS} scripts, or >= {COMPLEX_EXTERNAL_DOMAINS} external domains. "
         "Login page = contains a password field.", "",
         "| Stratum | Legitimate n | Phishing n | Legitimate wrongly flagged @0.70 | Legitimate wrongly flagged @0.85 | Phishing caught @0.70 | Phishing caught @0.85 |",
         "|---|---|---|---|---|---|---|"]
    strata = [("all fetched pages", lambda r: True), ("complex pages", lambda r: _truthy(r["complex"])),
              ("simple pages", lambda r: not _truthy(r["complex"])), ("login pages", lambda r: _truthy(r.get("has_password")))]
    thin = []
    for name, f in strata:
        rows = [r for r in scored if f(r)]
        neg = [r for r in rows if int(r["label"]) == 0]
        pos = [r for r in rows if int(r["label"]) == 1]
        def cell(group, thr, want_hit):
            if len(group) < MIN_STRATUM_N:
                return f"too few (n={len(group)})"
            k = sum(1 for r in group if float(r["deployed_p"]) >= thr)
            return rate_text(k, len(group))
        L.append(f"| {name} | {len(neg)} | {len(pos)} | {cell(neg, 0.70, True)} | {cell(neg, 0.85, True)} | {cell(pos, 0.70, True)} | {cell(pos, 0.85, True)} |")
        if len(neg) < MIN_STRATUM_N or len(pos) < MIN_STRATUM_N:
            thin.append(name)
    L += ["", f"Cells with fewer than {MIN_STRATUM_N} pages are not reported as rates: a handful of pages cannot support a conclusion."]
    cx = [r for r in scored if _truthy(r["complex"])]
    if cx and sum(1 for r in cx if int(r["label"]) == 1) < MIN_STRATUM_N:
        L += ["", "**Shortcut warning:** almost all complex pages in this sample are legitimate. A model can then score well by learning "
              "\"big page = legitimate\" without learning anything about phishing. To test that, collect complex phishing pages "
              "(compromised sites, phishing kits that clone large sites) and complex legitimate login pages before trusting any complex-page number."]
    return L + [""]


def build_report(results: list[dict], args, source_notes: list[str]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ph, lg, hn = _g(results, "phishing"), _g(results, "legitimate"), _g(results, "hard_negative")
    def fr(rows): return f"{sum(1 for r in rows if str(r['fetched']) == 'True')}/{len(rows)}"
    L = [f"# CompPhish live evaluation ({now})", "",
         "## Read this first", "",
         "- Pages that could not be fetched (dead phishing sites are common) are **excluded** from the page-based tables, "
         "so those tables describe only phishing that was still online. The URL-only table uses every sampled URL.",
         "- Labels come from public lists and are not hand-verified. Some phishing entries may be dead or mislabelled, "
         "and some \"legitimate\" CitizenLab entries may be low quality sites.",
         "- Tranco home pages are easier than real traffic (no long paths, no tracking links). Mixing in CitizenLab "
         "pages helps but does not remove the bias.",
         "- Small samples give wide confidence intervals. Do not quote a rate without its interval.",
         "- This measures the model on the sample, not on all of the web.", "",
         "## Sample", "",
         f"- Seed {args.seed}. " + " ".join(f"{n}." for n in source_notes),
         f"- Fetched: phishing {fr(ph)}, legitimate {fr(lg)}, hard negatives {fr(hn)}.", ""]

    # 1. URL-only, all URLs
    allr = [r for r in results if r["group"] in ("phishing", "legitimate")]
    y, p = _pairs(allr, "url_only_p")
    L += ["## 1. URL branch only (all sampled URLs, no page needed)", "", table_md(summarise(y, p))]

    fetched = [r for r in allr if str(r["fetched"]) == "True"]
    # 2. Deployed hybrid
    y, p = _pairs(fetched, "deployed_p")
    L += ["## 2. Deployed hybrid model (URL + HTML + text, fetched pages only)", "", table_md(summarise(y, p))]
    # 3. Research
    if any(r.get("research_p") not in (None, "") for r in results):
        y, p = _pairs(fetched, "research_p")
        L += ["## 3. Research model (44 URL + 33 HTML + TF-IDF + stacking, fetched pages only)", "",
              f"Pages scored in full mode: {len(y)} of {len(fetched)}.", "", table_md(summarise(y, p))]
    # 4. Final verdict with trust rules
    if any(r.get("final_verdict") for r in results):
        L += ["## 4. Final verdict after trust rules (threat feeds OFF)", ""]
        verdicts = ["PHISHING", "NEEDS_REVIEW", "LIKELY_LEGITIMATE", "LEGITIMATE"]
        L += ["| Group | " + " | ".join(verdicts) + " |", "|---|" + "---|" * len(verdicts)]
        for name, rows in (("phishing", ph), ("legitimate", lg), ("hard negatives", hn)):
            rows = [r for r in rows if r.get("final_verdict")]
            cnt = {v: sum(1 for r in rows if r["final_verdict"] == v) for v in verdicts}
            L.append(f"| {name} (n={len(rows)}) | " + " | ".join(rate_text(cnt[v], len(rows)) for v in verdicts) + " |")
        L.append("")

    # 4b. Strata
    L += strata_section(fetched)

    # 5. Named-site sanity set
    if hn:
        L += ["## 5. Named-site sanity set (regression check only)", "",
              "These are well-known sites. They are **not** part of any headline number above, and must never be used for "
              "tuning thresholds, adding allow-lists or training. A model that is fixed for these names is overfitted, not better.", "",
              "| URL | Fetched | Deployed score | URL | HTML | Text | Final verdict |", "|---|---|---|---|---|---|---|"]
        for r in hn:
            f = lambda v: "" if v in (None, "") else f"{float(v):.2f}"
            L.append(f"| {r['url']} | {'yes' if str(r['fetched']) == 'True' else 'no'} | {f(r['deployed_p'])} | {f(r['url_p'])} | "
                     f"{f(r['html_p'])} | {f(r['text_p'])} | {r.get('final_verdict', '')} |")
        L.append("")

    # 6. Worst cases
    scored = [r for r in fetched if r.get("deployed_p") not in (None, "")]
    fps = sorted([r for r in scored if int(r["label"]) == 0], key=lambda r: -float(r["deployed_p"]))[:15]
    fns = sorted([r for r in scored if int(r["label"]) == 1], key=lambda r: float(r["deployed_p"]))[:15]
    L += ["## 6. Worst legitimate pages (highest phishing score)", "", "| Score | URL | URL / HTML / Text |", "|---|---|---|"]
    for r in fps:
        L.append(f"| {float(r['deployed_p']):.2f} | {r['url']} | {float(r['url_p']):.2f} / {float(r['html_p']):.2f} / {float(r['text_p']):.2f} |")
    L += ["", "## 7. Worst missed phishing pages (lowest phishing score)", "", "| Score | URL | URL / HTML / Text |", "|---|---|---|"]
    for r in fns:
        L.append(f"| {float(r['deployed_p']):.2f} | {r['url']} | {float(r['url_p']):.2f} / {float(r['html_p']):.2f} / {float(r['text_p']):.2f} |")

    errs: dict[str, int] = {}
    for r in results:
        if r["error"]:
            k = r["error"].split(":")[0]
            errs[k] = errs.get(k, 0) + 1
    if errs:
        L += ["", "## 8. Fetch / scoring errors", ""] + [f"- {k}: {v}" for k, v in sorted(errs.items(), key=lambda kv: -kv[1])]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phish", type=int, default=300)
    ap.add_argument("--legit", type=int, default=300)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--hard-negatives", action="store_true")
    ap.add_argument("--with-trust", action="store_true")
    ap.add_argument("--phish-file")
    ap.add_argument("--legit-file")
    ap.add_argument("--train-domains")
    ap.add_argument("--research-app")
    ap.add_argument("--research-models")
    ap.add_argument("--out", default="eval_out")
    ap.add_argument("--from-results")
    args = ap.parse_args(argv)

    if args.from_results:
        with open(args.from_results) as fh:
            results = list(csv.DictReader(fh))
        for r in results:
            r["label"] = int(r["label"])
        path = write_outputs(results, Path(args.out), args, ["rebuilt from results.csv"])
    else:
        results = run(args)
        path = write_outputs(results, Path(args.out), args, getattr(run, "source_notes", []))
    print(f"\nReport written to {path}\nPer-URL results: {path.parent / 'results.csv'}")


if __name__ == "__main__":
    main()
