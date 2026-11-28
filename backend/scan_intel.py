"""
CompPhish scan intelligence: the evidence checks shown next to the model score.

Every function returns plain dicts, never raises, and reports "unavailable" /
None when a check could not be made. Nothing here treats "no data" as "safe".

Checks
  * tls_details      - certificate issuer, validity window, protocol
  * threat_feeds     - OpenPhish community feed (+ URLhaus / Google Safe
                       Browsing when API keys are configured)
  * page_behaviour   - suspicious page behaviour found in the HTML
  * network_footprint- domains, links and resources referenced by the page
  * server_location  - hosting IP, ASN and country (Team Cymru DNS)
"""

from __future__ import annotations

import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from backend.trust_signals import SHARED_HOSTING_SUFFIXES, is_shared_hosting, registered_domain

TIMEOUT = 5.0


# --------------------------------------------------
# TLS details
# --------------------------------------------------

def tls_details(host: str) -> dict:
    out = {"status": "unavailable", "valid": None}
    if not host:
        return out
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                proto = tls.version()
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        subject = dict(x[0] for x in cert.get("subject", ()))
        not_after = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc
        )
        not_before = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc
        )
        out.update(
            status="ok",
            valid=True,
            protocol=proto,
            issuer=issuer.get("organizationName") or issuer.get("commonName"),
            subject=subject.get("commonName"),
            not_before=not_before.date().isoformat(),
            not_after=not_after.date().isoformat(),
            days_left=(not_after - datetime.now(timezone.utc)).days,
        )
    except ssl.SSLCertVerificationError as exc:
        out.update(status="ok", valid=False, error=str(exc.verify_message))
    except Exception as exc:  # network error, no TLS, timeout ...
        out.update(status="unavailable", error=type(exc).__name__)
    return out


# --------------------------------------------------
# Threat feeds
# --------------------------------------------------

_feed_cache: dict = {"at": 0.0, "urls": set(), "hosts": set(), "ok": False}
FEED_TTL = 3600


def _host(url: str) -> str:
    """Lower-case host without a leading www., so www.x.com and x.com are the same site."""
    try:
        host = (urlparse(url.strip()).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def _norm(url: str) -> str:
    try:
        path = urlparse(url.strip()).path.rstrip("/")
    except ValueError:
        path = ""
    return f"{_host(url)}{path}"


def _load_openphish() -> bool:
    now = time.time()
    if _feed_cache["ok"] and now - _feed_cache["at"] < FEED_TTL:
        return True
    try:
        import httpx  # lazy

        r = httpx.get("https://openphish.com/feed.txt", timeout=8.0, follow_redirects=True)
        if r.status_code != 200:
            return _feed_cache["ok"]
        urls, hosts = set(), set()
        for line in r.text.splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls.add(_norm(line))
                hosts.add(_host(line))
        _feed_cache.update(at=now, urls=urls, hosts=hosts, ok=bool(urls))
        return _feed_cache["ok"]
    except Exception:
        return _feed_cache["ok"]


def _openphish_status(urls: list[str]) -> str:
    if not _load_openphish():
        return "unavailable"
    for u in urls:
        host = _host(u)
        if _norm(u) in _feed_cache["urls"]:
            return "match"
        # A listed host counts as a match, except for the platform's own address
        # (listing docs.google.com must not flag every Google document).
        if host in _feed_cache["hosts"] and host not in SHARED_HOSTING_SUFFIXES:
            return "match"
    return "no_match"


def _combine(statuses: list[str]) -> str:
    if "match" in statuses:
        return "match"
    return "no_match" if statuses and all(x == "no_match" for x in statuses) else "unavailable"


def threat_feeds(url: str, extra_urls: tuple[str, ...] = ()) -> dict:
    """status per source: match | no_match | unavailable. no_match is NOT 'safe'.

    `extra_urls` are other addresses of the same page (for example the address the user
    submitted before redirects); a listing for any of them counts."""
    urls = list(dict.fromkeys([url, *extra_urls]))
    sources = [{"name": "OpenPhish community feed", "status": _openphish_status(urls)}]

    key = os.getenv("URLHAUS_AUTH_KEY")
    if key:
        results = []
        for u in urls:
            try:
                import httpx

                r = httpx.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    data={"url": u},
                    headers={"Auth-Key": key},
                    timeout=TIMEOUT,
                )
                q = r.json().get("query_status") if r.status_code == 200 else None
                results.append("match" if q == "ok" else "no_match" if q == "no_results" else "unavailable")
            except Exception:
                results.append("unavailable")
        sources.append({"name": "URLhaus", "status": _combine(results)})

    gsb = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if gsb:
        try:
            import httpx

            body = {
                "client": {"clientId": "compphish", "clientVersion": "1.2"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": u} for u in urls],
                },
            }
            r = httpx.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb}",
                json=body,
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                st = "match" if r.json().get("matches") else "no_match"
            else:
                st = "unavailable"
        except Exception:
            st = "unavailable"
        sources.append({"name": "Google Safe Browsing", "status": st})

    statuses = {s["status"] for s in sources}
    overall = "match" if "match" in statuses else "no_match" if "no_match" in statuses else "unavailable"
    return {"overall": overall, "sources": sources}


# --------------------------------------------------
# Page behaviour
# --------------------------------------------------

def _soup(html: str):
    from bs4 import BeautifulSoup

    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")


def page_behaviour(html: str, final_url: str) -> dict:
    """Findings are (severity, text). Severity: info | low | medium | high."""
    findings: list[dict] = []
    page_host = (urlparse(final_url).hostname or "").lower()
    page_reg = registered_domain(page_host)

    def add(sev, text):
        findings.append({"severity": sev, "text": text})

    try:
        soup = _soup(html[:1_500_000])
    except Exception:
        return {"status": "unavailable", "findings": [], "has_password_form": None, "max_severity": None}

    has_pw = False
    for form in soup.find_all("form"):
        pw = bool(form.find("input", attrs={"type": re.compile("^password$", re.I)}))
        action = (form.get("action") or "").strip()
        target = urlparse(urljoin(final_url, action)) if action else None
        t_host = (target.hostname or "").lower() if target else page_host
        cross = bool(t_host) and registered_domain(t_host) != page_reg
        if pw:
            has_pw = True
            if cross:
                add("high", f"Password form submits to a different domain ({t_host}).")
            elif target is not None and target.scheme == "http":
                add("high", "Password form submits over unencrypted HTTP.")
            else:
                add("info", "Page contains a password form.")
        elif cross:
            add("medium", f"A form submits data to a different domain ({t_host}).")

    for fr in soup.find_all("iframe"):
        src = (fr.get("src") or "").strip()
        if not src:
            continue
        h = (urlparse(urljoin(final_url, src)).hostname or "").lower()
        style = (fr.get("style") or "").replace(" ", "").lower()
        hidden = (
            "display:none" in style or "visibility:hidden" in style
            or fr.get("width") in ("0", "1") or fr.get("height") in ("0", "1")
            or fr.has_attr("hidden")
        )
        if hidden and h and registered_domain(h) != page_reg:
            add("low", "Hidden cross-domain iframe (common for analytics; weak signal on its own).")
            break
    if any(f["text"].startswith("Hidden cross-domain") for f in findings) and has_pw:
        for f in findings:
            if f["text"].startswith("Hidden cross-domain"):
                f["severity"] = "medium"
                f["text"] = "Hidden cross-domain iframe on a page with a password form."

    for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)}):
        add("medium", "Page redirects automatically using a meta refresh.")
        break

    scripts = " ".join(s.get_text() for s in soup.find_all("script"))[:400_000]
    if re.search(r"(window\.|document\.)?location(\.href)?\s*=\s*['\"]https?://", scripts):
        add("low", "Script redirects the browser to another address.")
    if len(re.findall(r"\b(eval|atob|unescape)\s*\(", scripts)) >= 3:
        add("medium", "Script uses heavy obfuscation (eval/atob/unescape).")
    if re.search(r"contextmenu", html[:600_000], re.I) and re.search(r"preventDefault|return\s*false", scripts):
        add("low", "Page tries to block the right-click menu.")

    order = {"info": 0, "low": 1, "medium": 2, "high": 3}
    mx = max((f["severity"] for f in findings), key=order.get, default=None)
    return {
        "status": "ok",
        "findings": findings,
        "has_password_form": has_pw,
        "max_severity": mx,
    }


# --------------------------------------------------
# Network footprint (from the HTML; not a real browser trace)
# --------------------------------------------------

def network_footprint(html: str, final_url: str, resolve_limit: int = 12) -> dict:
    try:
        soup = _soup(html[:1_500_000])
    except Exception:
        return {"status": "unavailable"}
    page_host = (urlparse(final_url).hostname or "").lower()
    domains, resources, links, insecure = set(), 0, 0, 0
    for tag, attr in (("script", "src"), ("img", "src"), ("link", "href"),
                      ("iframe", "src"), ("source", "src"), ("video", "src"), ("audio", "src")):
        for el in soup.find_all(tag):
            v = el.get(attr)
            if not v or v.startswith(("data:", "javascript:", "#")):
                continue
            if tag == "link" and "stylesheet" not in (el.get("rel") or []) and "icon" not in " ".join(el.get("rel") or []):
                continue
            resources += 1
            full = urlparse(urljoin(final_url, v))
            if full.scheme == "http":
                insecure += 1
            h = (full.hostname or "").lower()
            if h:
                domains.add(h)
    for a in soup.find_all("a", href=True):
        v = a["href"]
        if v.startswith(("http://", "https://", "//")):
            links += 1
    domains.add(page_host)
    ips = set()
    for h in sorted(domains)[:resolve_limit]:
        try:
            for ai in socket.getaddrinfo(h, 443, type=socket.SOCK_STREAM):
                ips.add(ai[4][0])
        except Exception:
            pass
    external = sorted(d for d in domains if registered_domain(d) != registered_domain(page_host))
    return {
        "status": "ok",
        "basis": "estimated from page HTML (no browser)",
        "domains": len(domains),
        "external_domains": external[:15],
        "ips": len(ips),
        "links": links,
        "resources": resources,
        "insecure_resources": insecure,
        "https_share": round(100 * (resources - insecure) / resources) if resources else None,
    }


# --------------------------------------------------
# Server location / ASN (Team Cymru DNS)
# --------------------------------------------------

def server_location(host: str) -> dict:
    out = {"status": "unavailable"}
    try:
        import dns.resolver  # dnspython

        ip = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)[0][4][0]
        if ":" in ip:
            return {"status": "unavailable", "ip": ip, "note": "IPv6 ASN lookup not implemented"}
        rev = ".".join(reversed(ip.split(".")))
        res = dns.resolver.Resolver()
        res.lifetime = TIMEOUT
        txt = str(res.resolve(f"{rev}.origin.asn.cymru.com", "TXT")[0]).strip('"')
        asn, prefix, cc, *_ = [x.strip() for x in txt.split("|")]
        name = None
        try:
            t2 = str(res.resolve(f"AS{asn.split()[0]}.asn.cymru.com", "TXT")[0]).strip('"')
            name = t2.split("|")[-1].strip()
        except Exception:
            pass
        out = {"status": "ok", "ip": ip, "asn": f"AS{asn.split()[0]}", "asn_name": name, "country": cc}
    except Exception as exc:
        out = {"status": "unavailable", "error": type(exc).__name__}
    return out
