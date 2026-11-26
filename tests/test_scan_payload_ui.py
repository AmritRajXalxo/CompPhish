"""End-to-end guard: build a /scan-shaped payload exactly like backend/main.py does and
render the dashboard function with a fake Streamlit. Catches key collisions and crashes
that unit tests of single functions miss."""
import ast
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
HTML = "<html><head><title>Watch</title></head><body><h1>Hello</h1><a href='/a'>a</a><script src='https://x.example/a.js'></script></body></html>"


def build_payload(url="https://www.youtube.com/shorts/abc", preview=True):
    import sklearn._loss._loss as L
    sys.modules.setdefault("_loss", L)
    from backend import trust_signals as ts
    from backend.brand_check import brand_check
    from backend.prediction_service import predict_website
    from backend.scan_intel import network_footprint, page_behaviour
    from backend.verdict import compose_verdict

    result = predict_website(url, HTML)
    trust = {"host": "www.youtube.com", "registered_domain": "youtube.com", "domain_age_days": 7000, "tls_valid": True,
             "shared_hosting": False, "redirected_to_other_domain": False, "established": True}
    feeds = {"overall": "no_match", "sources": [{"name": "OpenPhish community feed", "status": "no_match"}]}
    beh = page_behaviour(HTML, url)
    tls = {"status": "ok", "valid": True, "issuer": "Google Trust Services", "subject": "*.youtube.com", "not_after": "2027-02-01", "days_left": 60, "protocol": "TLSv1.3"}
    result["redirect_chain"] = [{"url": url, "status": 200}]
    result = compose_verdict(result, trust, feeds, beh, tls, brand_check(url))
    return {
        "success": True, "submitted_url": url, "final_url": url, "content_type": "text/html", "html_size": len(HTML),
        "tls": tls, "threat_feeds": feeds, "page_behaviour": beh,
        "network_footprint": network_footprint(HTML, url, resolve_limit=0),
        "server_location": {"status": "ok", "ip": "1.2.3.4", "asn": "AS15169", "asn_name": "GOOGLE", "country": "US"},
        "statistics": {"load_seconds": 1.2, "status_code": 200, "html_bytes": len(HTML), "cookies_set": 1},
        "community_reports": {"status": "ok", "total": 0, "scam": 0, "safe": 0, "other": 0, "recent": []},
        "preview_url": "https://image.thum.io/get/width/900/noanimate/" + url if preview else None,
        **result,
    }


def test_payload_keys_do_not_collide():
    p = build_payload()
    assert isinstance(p["explanation"], list) and p["explanation"]          # "What we checked" lines
    assert isinstance(p["model_explanation"], dict)                         # model explanation
    assert p["model_explanation"]["fusion"]["branches"]


class FakeSt(ModuleType):
    def __init__(self):
        super().__init__("streamlit")
        self.out, self.session_state = [], {}

    def markdown(self, body, **kw): self.out.append(body)
    def caption(self, body, **kw): self.out.append(str(body))
    def success(self, body, **kw): self.out.append(str(body))
    def error(self, body, **kw): self.out.append(str(body))
    def selectbox(self, *a, **k): return "scam"
    def text_input(self, *a, **k): return ""
    def form_submit_button(self, *a, **k): return False

    @contextmanager
    def _ctx(self):
        yield

    def columns(self, spec, **kw):
        n = spec if isinstance(spec, int) else len(spec)
        return [self._ctx() for _ in range(n)]

    def form(self, *a, **k): return self._ctx()


def load_renderer(st):
    src = (ROOT / "frontend" / "app_flagship.py").read_text()
    tree = ast.parse(src)
    keep = {"esc", "rows_html", "section", "submit_report", "render_scan_details"}
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in keep]
    from frontend import ui_components as ui
    import html as html_mod
    ns = {"st": st, "ui": ui, "html": html_mod, "requests": None, "API_BASE_URL": "x", "Any": object}
    exec(compile(ast.Module(body=body, type_ignores=[]), "app_flagship_subset", "exec"), ns)
    return ns["render_scan_details"]


@pytest.mark.parametrize("preview", [True, False])
def test_dashboard_renders_real_payload(preview):
    st = FakeSt()
    render = load_renderer(st)
    render(build_payload(preview=preview))
    page = "".join(st.out)
    for needle in ("What we checked", "Connection security", "Domain age", "Threat intelligence", "Page behaviour",
                   "Why this score", "Brand lookalike", "Network footprint", "Community reports"):
        assert needle in page, needle
    assert ("Site preview" in page) == preview
    if preview:
        # same look as PR #6: preview first, then the four evidence cards in order
        start = page.index("Site preview")
        i = [page.index(x, start) for x in ("Site preview", "Connection security", "Domain age", "Threat intelligence", "Page behaviour")]
        assert i == sorted(i)


def test_dashboard_survives_malformed_payload():
    st = FakeSt()
    render = load_renderer(st)
    render({"explanation": {"oops": 1}, "model_explanation": ["bad"], "brand_check": "bad", "tls": [], "trust_signals": "x",
            "threat_feeds": 5, "page_behaviour": None, "statistics": [], "network_footprint": "n", "server_location": 3})
    assert "Why this score" in "".join(st.out)
