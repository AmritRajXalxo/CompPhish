"""
CompPhish trust signals (corroboration layer).

The ML model can over-react to page *topic* (for example a security vendor's
page that talks about phishing). Before a hard PHISHING verdict is shown, we
check independent, hard-to-fake evidence about the site:

  * domain age (RDAP registration date)
  * TLS certificate validity (verified against the system trust store)

An established domain (>= ESTABLISHED_DAYS old) with a valid certificate that
is NOT a shared hosting platform cannot receive a hard PHISHING verdict from
the model alone: the result is downgraded to NEEDS_REVIEW with the reason
shown. Trust signals never turn a result into LEGITIMATE and never change a
verdict that is already LEGITIMATE or NEEDS_REVIEW.

Failures (RDAP down, timeouts, ...) mean "unknown", never "trusted".
"""

from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

ESTABLISHED_DAYS = 730          # about 2 years
NETWORK_TIMEOUT = 5.0
CACHE_SECONDS = 3600

# Free / shared hosting and tunnelling platforms: the PLATFORM's domain is old
# and has a valid certificate, but anyone can host a phishing page on it, so
# neither signal says anything about the individual site.
SHARED_HOSTING_SUFFIXES = {
    "weebly.com", "wixsite.com", "wix.com", "blogspot.com", "blogger.com",
    "wordpress.com", "github.io", "gitlab.io", "workers.dev", "pages.dev",
    "netlify.app", "vercel.app", "herokuapp.com", "web.app",
    "firebaseapp.com", "glitch.me", "repl.co", "replit.app", "ngrok.io",
    "ngrok-free.app", "000webhostapp.com", "azurewebsites.net",
    "azurestaticapps.net", "cloudfront.net", "amazonaws.com",
    "googleusercontent.com", "sites.google.com", "forms.gle", "docs.google.com",
    "drive.google.com", "dropbox.com", "onrender.com", "fly.dev",
    "r2.dev", "trycloudflare.com", "ipfs.io", "mybluehost.me", "godaddysites.com",
    "square.site", "myshopify.com", "webflow.io", "framer.app", "carrd.co",
    "emy.ba", "x10.mx", "infinityfreeapp.com", "rf.gd", "epizy.com",
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    # free website builders and page hosts: every customer gets a subdomain
    "flazio.com", "strikingly.com", "mystrikingly.com", "webnode.com", "webnode.page",
    "jimdosite.com", "jimdofree.com", "site123.me", "yolasite.com", "webself.net",
    "weeblysite.com", "wixstudio.io", "bravesites.com", "tumblr.com", "notion.site",
    "typedream.app", "softr.app", "bubbleapps.io", "teachable.com", "sharemyhtml.com",
    "000webhostapp.com", "hpage.com", "sitey.com", "page.link", "my.canva.site",
}

# Common two-level public suffixes (approximation without the full PSL).
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "com.br", "com.cn",
    "co.jp", "co.nz", "co.za", "com.mx", "com.tr", "com.sg", "com.hk",
    "com.ar", "com.pk", "com.ng", "com.my", "co.id", "co.kr",
}

_cache: dict[str, tuple[float, dict]] = {}


def registered_domain(host: str) -> str:
    """Approximate eTLD+1 (last two labels, three for known 2-level suffixes)."""
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_shared_hosting(host: str) -> bool:
    host = host.lower().strip(".")
    return any(host == s or host.endswith("." + s) for s in SHARED_HOSTING_SUFFIXES)


def _domain_age_days(domain: str) -> int | None:
    """Age from RDAP registration event, or None if unknown."""
    try:
        import httpx  # lazy: only needed for the live RDAP lookup

        r = httpx.get(
            f"https://rdap.org/domain/{domain}",
            timeout=NETWORK_TIMEOUT,
            follow_redirects=True,
            headers={"Accept": "application/rdap+json"},
        )
        if r.status_code != 200:
            return None
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                days = (datetime.now(timezone.utc) - created).days
                return days if days >= 0 else None
    except Exception:
        return None
    return None


def _tls_valid(host: str) -> bool | None:
    """True if a certificate verifies for host; False if verification fails;
    None if the check could not be made (network error)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=NETWORK_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLCertVerificationError:
        return False
    except Exception:
        return None


def assess_trust(submitted_url: str, final_url: str | None = None) -> dict:
    """Collect trust signals. Never raises; unknown values are None."""
    host = (urlparse(final_url or submitted_url).hostname or "").lower()
    sub_host = (urlparse(submitted_url).hostname or "").lower()
    out = {
        "host": host,
        "registered_domain": registered_domain(host) if host else None,
        "domain_age_days": None,
        "tls_valid": None,
        "shared_hosting": is_shared_hosting(host) if host else False,
        "redirected_to_other_domain": bool(
            sub_host and host and registered_domain(sub_host) != registered_domain(host)
        ),
        "established": False,
    }
    if not host:
        return out

    now = time.time()
    hit = _cache.get(host)
    if hit and now - hit[0] < CACHE_SECONDS:
        out.update({k: hit[1][k] for k in ("domain_age_days", "tls_valid")})
    else:
        out["domain_age_days"] = _domain_age_days(out["registered_domain"])
        out["tls_valid"] = _tls_valid(host)
        _cache[host] = (now, {k: out[k] for k in ("domain_age_days", "tls_valid")})

    out["established"] = bool(
        out["domain_age_days"] is not None
        and out["domain_age_days"] >= ESTABLISHED_DAYS
        and out["tls_valid"] is True
        and not out["shared_hosting"]
        and not out["redirected_to_other_domain"]
    )
    return out


def apply_trust_adjustment(result: dict, trust: dict) -> dict:
    """Return a copy of result with the corroboration rule applied."""
    out = dict(result)
    out["model_prediction"] = result["prediction"]
    out["trust_signals"] = trust
    out["decision_note"] = None

    if result["prediction"] == "PHISHING" and trust.get("established"):
        out["prediction"] = "NEEDS_REVIEW"
        years = trust["domain_age_days"] / 365
        out["decision_note"] = (
            f"The model scored this page as phishing, but the domain "
            f"{trust['registered_domain']} is about {years:.0f} years old with a "
            f"valid TLS certificate, which does not fit a typical phishing site. "
            f"Downgraded to 'needs review'. Pages that discuss phishing or scams "
            f"can fool the text model."
        )
    elif result["prediction"] == "PHISHING":
        reasons = []
        if trust.get("domain_age_days") is None:
            reasons.append("domain age could not be checked")
        elif trust["domain_age_days"] < ESTABLISHED_DAYS:
            reasons.append(f"domain is only {trust['domain_age_days']} days old")
        if trust.get("tls_valid") is False:
            reasons.append("TLS certificate failed verification")
        if trust.get("shared_hosting"):
            reasons.append("hosted on a shared hosting platform")
        if trust.get("redirected_to_other_domain"):
            reasons.append("redirects to a different domain")
        if reasons:
            out["decision_note"] = "Phishing verdict kept: " + "; ".join(reasons) + "."
    return out
