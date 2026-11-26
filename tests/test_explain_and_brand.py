import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from backend import explain as ex
from backend.brand_check import brand_check
from backend.verdict import compose_verdict


def _toy_trees():
    rng = np.random.RandomState(0)
    X = pd.DataFrame(rng.rand(400, 5), columns=list("abcde"))
    y = ((X["a"] + 0.5 * X["c"] + 0.2 * rng.randn(400)) > 0.8).astype(int)
    m = ExtraTreesClassifier(n_estimators=40, random_state=0, min_samples_leaf=2).fit(X, y)
    return m, X


def test_tree_contributions_are_exact():
    m, X = _toy_trees()
    for i in (0, 7, 123):
        row = X.iloc[[i]]
        bias, c = ex.tree_contributions(m, row.iloc[0].to_numpy(float))
        assert abs(bias + c.sum() - m.predict_proba(row)[0, 1]) < 1e-9


def test_branch_average_over_two_inputs_is_exact():
    m, X = _toy_trees()
    f1, f2 = X.iloc[[1]], X.iloc[[2]]
    e = ex.explain_tree_branch(m, [f1, f2], k=5)
    want = (m.predict_proba(f1)[0, 1] + m.predict_proba(f2)[0, 1]) / 2
    assert abs(e["total"] - want) < 1e-3
    assert e["top_features"] and set(e["top_features"][0]) == {"feature", "value", "contribution"}


def test_fusion_decomposition_matches_model():
    rng = np.random.RandomState(1)
    P = rng.rand(300, 3)
    y = (P.sum(axis=1) + 0.3 * rng.randn(300) > 1.6).astype(int)
    lr = LogisticRegression().fit(P, y)
    probs = {"url": 0.2, "html": 0.7, "text": 0.9}
    out = ex.explain_fusion(lr, probs)
    want = lr.predict_proba(np.array([[0.2, 0.7, 0.9]]))[0, 1]
    assert abs(out["probability"] - want) < 1e-3
    assert abs(out["intercept"] + sum(b["push"] for b in out["branches"].values()) - out["logit"]) < 2e-3


def test_text_terms():
    docs = ["verify your account login now", "secure login account password", "weather news today sports", "recipe cooking dinner tonight"] * 10
    y = [1, 1, 0, 0] * 10
    pipe = Pipeline([("tfidf", TfidfVectorizer()), ("clf", LogisticRegression())]).fit(docs, y)
    out = ex.explain_text_branch(pipe, "please login to verify your account")
    assert out["top_terms"] and out["top_terms"][0]["contribution"] > 0
    assert ex.explain_text_branch(object(), "x") is None


# ---- brand check ----
def test_official_domains_not_flagged():
    for u in ("https://www.paypal.com/signin", "https://accounts.google.com/", "https://login.microsoftonline.com/"):
        r = brand_check(u)
        assert r["findings"] == [] and r.get("official_domain_of")


def test_embedded_and_typosquat_flagged():
    assert brand_check("https://paypal-login.top/verify")["findings"][0]["kind"] == "contains"
    assert brand_check("https://secure.paypal.example-bad.com/")["findings"]
    assert brand_check("https://paypa1.com/")["findings"]            # 1 -> l
    assert brand_check("https://arnazon.com/")["findings"]           # rn -> m
    assert brand_check("https://netfIix.com/")["findings"]           # I -> l via distance 1


def test_unrelated_domains_not_flagged():
    for u in ("https://www.kaggle.com/datasets", "https://example.org/", "https://wikipedia.org/", "https://github.com/"):
        assert brand_check(u)["findings"] == []
    assert brand_check("not a url")["status"] == "unavailable"


# ---- verdict interaction ----
EST = {"established": True, "domain_age_days": 8000, "registered_domain": "x.com", "tls_valid": True}
YOUNG = {"established": False, "domain_age_days": 3, "registered_domain": "x.top", "tls_valid": True}
NOFEED = {"overall": "no_match", "sources": []}
CLEAN = {"status": "ok", "max_severity": None, "has_password_form": False, "findings": []}
HIT = {"status": "ok", "findings": [{"brand": "paypal", "kind": "contains", "text": "The address contains the brand name 'paypal' but the domain is x.top, not paypal.com."}]}


def _res(p):
    return {"prediction": p, "hybrid_probability": 0.3, "redirect_chain": []}


def test_brand_hit_turns_legit_on_young_domain_into_review():
    out = compose_verdict(_res("LEGITIMATE"), YOUNG, NOFEED, CLEAN, {"valid": True}, HIT)
    assert out["prediction"] == "NEEDS_REVIEW" and "imitates" in out["decision_note"]
    assert any(r.startswith("Brand check") for r in out["explanation"])


def test_brand_hit_blocks_likely_legitimate_upgrade():
    out = compose_verdict(_res("NEEDS_REVIEW"), EST, NOFEED, CLEAN, {"valid": True}, HIT)
    assert out["prediction"] == "NEEDS_REVIEW"


def test_no_brand_hit_keeps_existing_behaviour():
    assert compose_verdict(_res("NEEDS_REVIEW"), EST, NOFEED, CLEAN, {"valid": True}, None)["prediction"] == "LIKELY_LEGITIMATE"
    assert compose_verdict(_res("NEEDS_REVIEW"), EST, NOFEED, CLEAN, {"valid": True})["prediction"] == "LIKELY_LEGITIMATE"


def test_shared_hosting_domains_are_not_official():
    assert brand_check("https://paypal-login.web.app/")["findings"]
    assert brand_check("https://paypal.s3.amazonaws.com/")["findings"]
