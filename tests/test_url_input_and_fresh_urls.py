import importlib.util
import sys
from pathlib import Path

from frontend import url_input as ui

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fresh", ROOT / "scripts" / "fresh_phish_urls.py")
fresh = importlib.util.module_from_spec(spec)
sys.modules["fresh"] = fresh
spec.loader.exec_module(fresh)


def test_refang_variants():
    assert ui.refang("hxxp://trackdtd[.]click/dhl-za") == "http://trackdtd.click/dhl-za"
    assert ui.refang("HXXPS://a(.)b[dot]c/x") == "https://a.b.c/x"
    assert ui.refang("hxxp[:]//a[.]com") == "http://a.com"
    assert ui.refang("  <https://example.com/>  ") == "https://example.com/"
    assert ui.refang("https://example.com/a.b") == "https://example.com/a.b"  # normal URLs unchanged
    assert ui.refang("") == ""


def test_friendly_errors():
    dead = ui.friendly_backend_error(422, {"detail": "Unable to resolve website hostname."})
    assert "no longer exists" in dead and "HTTP" not in dead
    assert "not a web page" in ui.friendly_backend_error(422, {"detail": "The requested resource is not an HTML webpage."})
    assert "Too many scans" in ui.friendly_backend_error(429, "x")
    assert "HTTP 500" in ui.friendly_backend_error(500, {"detail": "boom"})
    assert "no details" in ui.friendly_backend_error(500, None)


def test_app_uses_refang_and_friendly_errors():
    src = (ROOT / "frontend" / "app_flagship.py").read_text()
    assert "ui_url.refang(value)" in src and "ui_url.friendly_backend_error(" in src
    assert "Backend returned HTTP" not in src


def test_usable_filters():
    ok = "http://amzaonprimes.com/billing/login.php"
    assert fresh.usable(ok) == "amzaonprimes.com"
    for bad in ("http://1.2.3.4/x", "http://a.example/?u=bob@mail.com", "http://x.blogspot.com/a",
                "http://a.example/?email=Ym9iQG1haWwuY29t", "http://localhost/x", "http://" + "a" * 170 + ".com",
                "http://[bad/x"):
        assert fresh.usable(bad) is None, bad


def test_pick_live_keeps_only_resolving_distinct_hosts():
    urls = ["http://a.example/1", "http://a.example/2", "http://b.example/", "http://c.example/", "http://d.blogspot.com/"]
    got = fresh.pick_live(urls, 5, seed=1, resolver=lambda h: h != "b.example")
    assert sorted(got) == ["http://a.example/1", "http://c.example/"]
    assert fresh.pick_live(urls, 1, seed=1, resolver=lambda h: True).__len__() == 1
    assert fresh.pick_live(urls, 5, resolver=lambda h: False) == []


def test_defang_roundtrip_with_scanner():
    d = fresh.defang("http://trackdtd.click/dhl-za")
    assert d == "hxxp://trackdtd[.]click/dhl-za" and ui.refang(d) == "http://trackdtd.click/dhl-za"


def test_resolves_rejects_internal_addresses(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))])
    assert fresh.resolves("x.example") is False
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    assert fresh.resolves("x.example") is True
    def boom(*a, **k): raise socket.gaierror()
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert fresh.resolves("x.example") is False
