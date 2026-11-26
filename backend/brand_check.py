"""
Brand-lookalike check (heuristic evidence, not a model).

Flags addresses that imitate a well-known brand without being its real domain:
  * the brand name appears as a whole word inside another domain
    (paypal-login.top, secure.paypal.example.com)
  * the domain is one character away from the brand, or equals it after the usual
    look-alike swaps (paypa1 -> paypal, rn -> m, 0 -> o, 1 -> l)

It can be wrong: "apple-recipes.com" is not phishing. So it is shown as evidence and
never forces a PHISHING verdict by itself. The brand list is a small, hand-written
sample, not a complete registry.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from backend.trust_signals import registered_domain

# brand keyword -> real registered domains owned by that brand.
# Shared hosting / user-content domains (amazonaws.com, web.app, sharepoint.com ...) are
# deliberately NOT listed: anyone can host a page there, so they must not count as "official".
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.in", "gmail.com", "youtube.com", "goo.gl", "googleapis.com", "gstatic.com", "dns.google", "ggpht.com", "googlevideo.com", "ytimg.com", "googletagmanager.com", "google-analytics.com", "withgoogle.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "msn.com", "bing.com", "azure.com", "live.net", "skype.com", "office365.com"},
    "apple": {"apple.com", "icloud.com", "mzstatic.com", "icloud-content.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.ca", "amazon.com.au", "media-amazon.com", "ssl-images-amazon.com", "a2z.com"},
    "facebook": {"facebook.com", "fb.com", "fb.me", "meta.com", "messenger.com", "fbcdn.net", "facebook.net", "fbsbx.com"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    "ebay": {"ebay.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "dhl": {"dhl.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "spotify": {"spotify.com"},
    "twitter": {"twitter.com", "x.com"},
    "telegram": {"telegram.org", "t.me", "telegram.me", "telegram.dog", "telegra.ph"},
}

_SWAPS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s")]
MIN_LEN = 5            # shorter brand words are too common to flag


def _normalise(label: str) -> str:
    out = label.lower()
    for a, b in _SWAPS:
        out = out.replace(a, b)
    return out


def _edit_distance_le1(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    s, l = (a, b) if len(a) < len(b) else (b, a)
    return any(l[:i] + l[i + 1:] == s for i in range(len(l)))


def brand_check(url: str) -> dict:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return {"status": "unavailable", "findings": []}
    rd = registered_domain(host)
    for brand, domains in BRANDS.items():
        if rd in domains:
            return {"status": "ok", "findings": [], "official_domain_of": brand}
    sld = rd.split(".")[0]
    tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    findings = []
    for brand, domains in BRANDS.items():
        if len(brand) < MIN_LEN:
            continue
        real = sorted(domains)[0]
        if brand in tokens:
            findings.append({"brand": brand, "kind": "contains", "text": f"The address contains the brand name '{brand}' but the domain is {rd}, not {real}."})
        elif _edit_distance_le1(sld, brand) or _normalise(sld) == brand or _edit_distance_le1(_normalise(sld), brand):
            findings.append({"brand": brand, "kind": "lookalike", "text": f"'{sld}' looks like '{brand}' ({real}) but is a different domain."})
    return {"status": "ok", "findings": findings[:3]}
