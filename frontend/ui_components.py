"""
Presentation helpers for the CompPhish scan-detail dashboard.

Pure functions: they take the dicts returned by the API and return HTML
strings. No network access, no model logic, no thresholds. Every value that
comes from the API is HTML-escaped. Missing values render as a muted dash and
are never replaced with example data.

All markup is built on a single line (no indentation or blank lines) so
Streamlit's Markdown parser does not turn it into a code block.
"""

from __future__ import annotations

import html
from typing import Any

# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def dash(value: Any) -> str:
    """Escaped value, or a muted dash when it is missing."""
    if value is None or value == "":
        return "<span class='ci-na'>—</span>"
    return esc(value)


def fmt_seconds(value: Any) -> str | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v < 0:
        return None
    return f"{v * 1000:.0f} ms" if v < 1 else f"{v:.2f} s"


def fmt_bytes(value: Any) -> str | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v < 0:
        return None
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024 or unit == "GB":
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024
    return None


def fmt_age(days: Any) -> tuple[str, str] | None:
    """(big text, small text) for a domain age in days."""
    if not isinstance(days, (int, float)) or isinstance(days, bool) or days < 0:
        return None
    d = int(days)
    if d >= 730:
        big = f"{d / 365.25:.0f} years"
    elif d >= 60:
        big = f"{d // 30} months"
    else:
        big = f"{d} day" + ("" if d == 1 else "s")
    return big, f"{d:,} days since registration"


# --------------------------------------------------------------------------
# Icons (inline SVG, decorative)
# --------------------------------------------------------------------------

_ICONS = {
    "lock": "<rect x='3' y='11' width='18' height='11' rx='2'/><path d='M7 11V7a5 5 0 0110 0v4'/>",
    "shield": "<path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/>",
    "calendar": "<rect x='3' y='4' width='18' height='18' rx='2'/><path d='M16 2v4M8 2v4M3 10h18'/>",
    "pin": "<path d='M21 10c0 7-9 13-9 13S3 17 3 10a9 9 0 0118 0z'/><circle cx='12' cy='10' r='3'/>",
    "clock": "<circle cx='12' cy='12' r='10'/><path d='M12 6v6l4 2'/>",
    "file": "<path d='M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z'/><path d='M14 2v6h6'/>",
    "layers": "<path d='M12 2l10 5-10 5L2 7z'/><path d='M2 17l10 5 10-5M2 12l10 5 10-5'/>",
    "pulse": "<path d='M22 12h-4l-3 9L9 3l-3 9H2'/>",
    "alert": "<path d='M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z'/><path d='M12 9v4M12 17h.01'/>",
    "check": "<path d='M22 11.1V12a10 10 0 11-5.9-9.1'/><path d='M22 4L12 14l-3-3'/>",
    "x": "<circle cx='12' cy='12' r='10'/><path d='M15 9l-6 6M9 9l6 6'/>",
    "code": "<path d='M16 18l6-6-6-6M8 6l-6 6 6 6'/>",
    "globe": "<circle cx='12' cy='12' r='10'/><path d='M2 12h20M12 2a15 15 0 010 20M12 2a15 15 0 000 20'/>",
    "redirect": "<path d='M15 14l5-5-5-5'/><path d='M4 20v-7a4 4 0 014-4h12'/>",
    "form": "<rect x='3' y='3' width='18' height='18' rx='2'/><path d='M7 8h10M7 12h10M7 16h6'/>",
    "server": "<rect x='2' y='2' width='20' height='8' rx='2'/><rect x='2' y='14' width='20' height='8' rx='2'/><path d='M6 6h.01M6 18h.01'/>",
    "cookie": "<path d='M21 12a9 9 0 11-9-9 3 3 0 003 3 3 3 0 003 3 3 3 0 003 3z'/><path d='M8.5 8.5h.01M7.5 14.5h.01M12 16h.01M15.5 12h.01'/>",
    "image": "<rect x='3' y='3' width='18' height='18' rx='2'/><circle cx='8.5' cy='8.5' r='1.5'/><path d='M21 15l-5-5L5 21'/>",
    "info": "<circle cx='12' cy='12' r='10'/><path d='M12 16v-4M12 8h.01'/>",
}


def icon(name: str, size: int = 18) -> str:
    body = _ICONS.get(name, _ICONS["info"])
    return (
        f"<span class='ci-ic' aria-hidden='true'><svg viewBox='0 0 24 24' width='{size}' height='{size}' "
        f"fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' "
        f"stroke-linejoin='round'>{body}</svg></span>"
    )


# --------------------------------------------------------------------------
# Building blocks
# --------------------------------------------------------------------------

TONES = ("good", "warn", "bad", "neutral")


def badge(text: str, tone: str, icon_name: str | None = None, tip: str | None = None) -> str:
    tone = tone if tone in TONES else "neutral"
    title = f" title='{esc(tip)}'" if tip else ""
    ic = icon(icon_name, 14) if icon_name else ""
    return f"<span class='ci-badge ci-{tone}'{title}>{ic}{esc(text)}</span>"


def card(title: str, icon_name: str, body: str, tone: str = "neutral", badge_html: str = "", tip: str | None = None) -> str:
    tone = tone if tone in TONES else "neutral"
    title_attr = f" title='{esc(tip)}'" if tip else ""
    return (
        f"<div class='ci-card ci-t-{tone}'><div class='ci-head'>"
        f"<div class='ci-title'{title_attr}>{icon(icon_name)}<span>{esc(title)}</span></div>{badge_html}</div>{body}</div>"
    )


def fact(label: str, value_html: str, tip: str | None = None) -> str:
    title = f" title='{esc(tip)}'" if tip else ""
    return f"<div class='ci-fact'><div class='ci-k'{title}>{esc(label)}</div><div class='ci-v'>{value_html}</div></div>"


def facts(items: list[str]) -> str:
    return f"<div class='ci-facts'>{''.join(items)}</div>"


def note(text: str) -> str:
    return f"<div class='ci-note'>{icon('info', 14)}<span>{esc(text)}</span></div>"


# --------------------------------------------------------------------------
# 1. Connection security
# --------------------------------------------------------------------------

EXPIRY_WARN_DAYS = 30


def tls_state(tls: dict | None) -> tuple[str, str, str]:
    """(tone, label, icon) for a TLS block from the API."""
    tls = tls or {}
    if tls.get("status") != "ok":
        return "neutral", "UNAVAILABLE", "info"
    if tls.get("valid") is False:
        return "bad", "INVALID", "x"
    days = tls.get("days_left")
    if tls.get("valid") is True:
        if isinstance(days, (int, float)) and days < 0:
            return "bad", "EXPIRED", "x"
        if isinstance(days, (int, float)) and days <= EXPIRY_WARN_DAYS:
            return "warn", "EXPIRES SOON", "alert"
        return "good", "VALID", "check"
    return "neutral", "UNAVAILABLE", "info"


def connection_card(tls: dict | None) -> str:
    tls = tls or {}
    tone, label, ic = tls_state(tls)
    b = badge(label, tone, ic)
    if tls.get("status") != "ok":
        body = note("The certificate could not be checked from the scanner, so nothing is claimed about it.")
        return card("Connection security", "lock", body, tone, b)
    if tls.get("valid") is False:
        body = facts([fact("Reason", dash(tls.get("error")))]) + note(
            "The certificate failed verification. Do not enter sensitive information on this site."
        )
        return card("Connection security", "lock", body, tone, b)
    days = tls.get("days_left")
    if isinstance(days, (int, float)):
        when = f"{tls.get('not_after') or '—'} · " + (
            f"expired {abs(int(days))} days ago" if days < 0 else f"in {int(days)} days"
        )
        expiry_html = esc(when)
        if tone == "warn":
            expiry_html = f"<span class='ci-amber'>{esc(when)}</span>"
        elif tone == "bad":
            expiry_html = f"<span class='ci-red'>{esc(when)}</span>"
    else:
        expiry_html = dash(tls.get("not_after"))
    body = facts([
        fact("Issuer", dash(tls.get("issuer")), "The certificate authority that signed the certificate."),
        fact("Domain", dash(tls.get("subject")), "The name the certificate was issued to."),
        fact("Expires", expiry_html),
        fact("Protocol", dash(tls.get("protocol")), "The TLS version negotiated with the server."),
    ])
    if tone == "warn":
        body += note("The certificate expires soon. This is common for short-lived certificates that renew automatically.")
    return card("Connection security", "lock", body, tone, b)


# --------------------------------------------------------------------------
# 2. Domain age
# --------------------------------------------------------------------------

AGE_RED_DAYS = 90        # display colour only; trust rules are untouched
AGE_GREEN_DAYS = 730


def age_tone(days: Any) -> str:
    if not isinstance(days, (int, float)) or isinstance(days, bool) or days < 0:
        return "neutral"
    if days < AGE_RED_DAYS:
        return "bad"
    if days < AGE_GREEN_DAYS:
        return "warn"
    return "good"


def domain_card(trust: dict | None) -> str:
    trust = trust or {}
    days = trust.get("domain_age_days")
    tone = age_tone(days)
    age = fmt_age(days)
    if age:
        metric = (
            f"<div class='ci-metric ci-m-{tone}'><div class='ci-big'>{esc(age[0])}</div>"
            f"<div class='ci-sub'>{esc(age[1])}</div></div>"
        )
    else:
        metric = "<div class='ci-metric ci-m-neutral'><div class='ci-big'>Unknown</div><div class='ci-sub'>The registration date could not be checked</div></div>"
    est = trust.get("established")
    if est:
        est_b = badge("ESTABLISHED", "good", "check", "2+ years old, valid certificate, not shared hosting, no cross-domain redirect.")
    elif days is None:
        est_b = badge("UNKNOWN", "neutral", "info", "Age or certificate could not be checked.")
    else:
        est_b = badge("NOT ESTABLISHED", "warn", "alert", "Needs 2+ years of age, a valid certificate, no shared hosting and no cross-domain redirect.")
    shared = trust.get("shared_hosting")
    if shared is None:
        shared_b = badge("UNKNOWN", "neutral", "info", "Hosting could not be determined.")
    elif shared:
        shared_b = badge("YES", "warn", "alert", "Anyone can host a page on this platform, so its age says little about this page.")
    else:
        shared_b = badge("NO", "good", None, "Not a known shared hosting platform.")
    body = metric + facts([
        fact("Registered domain", dash(trust.get("registered_domain")), "The registrable domain used for the age lookup."),
        fact("Status", est_b),
        fact("Shared hosting", shared_b),
    ])
    return card("Domain age", "calendar", body, tone, "")


# --------------------------------------------------------------------------
# 3. Threat intelligence
# --------------------------------------------------------------------------

_FEED_BADGE = {
    "match": ("LISTED", "bad", "x"),
    "no_match": ("NO MATCH", "good", "check"),
    "unavailable": ("UNAVAILABLE", "warn", "alert"),
}


def threat_card(feeds: dict | None) -> str:
    feeds = feeds or {}
    sources = feeds.get("sources") or []
    overall = feeds.get("overall")
    if overall == "match":
        head = badge("THREAT LISTED", "bad", "x")
        tone = "bad"
    elif overall == "no_match":
        head = badge("NO MATCH", "good", "check")
        tone = "good"
    else:
        head = badge("UNAVAILABLE", "warn", "alert")
        tone = "warn"
    rows = []
    for s in sources:
        label, t, ic = _FEED_BADGE.get(s.get("status"), ("UNKNOWN", "neutral", "info"))
        rows.append(
            f"<div class='ci-row'><span class='ci-rowname'>{esc(s.get('name') or 'Feed')}</span>{badge(label, t, ic)}</div>"
        )
    if not rows:
        rows.append("<div class='ci-row'><span class='ci-rowname'>Threat feeds</span>" + badge("UNAVAILABLE", "warn", "alert") + "</div>")
    foot = note("“No match” only means these feeds have no record of this page. It does not mean the site is safe.")
    return card("Threat intelligence", "shield", "".join(rows) + foot, tone, head)


# --------------------------------------------------------------------------
# 4. Page behaviour
# --------------------------------------------------------------------------

_SEV_TONE = {"high": "bad", "medium": "warn", "low": "warn"}


def _behaviour_icon(text: str) -> str:
    t = (text or "").lower()
    if "password" in t or "form" in t:
        return "form"
    if "iframe" in t:
        return "layers"
    if "redirect" in t or "refresh" in t:
        return "redirect"
    if "script" in t or "obfusc" in t:
        return "code"
    return "alert"


def behaviour_card(beh: dict | None) -> str:
    beh = beh or {}
    if beh.get("status") != "ok":
        return card(
            "Page behaviour", "code",
            note("The page could not be analysed, so nothing is claimed about its behaviour."),
            "neutral", badge("NOT CHECKED", "neutral", "info"),
        )
    findings = beh.get("findings") or []
    sev = beh.get("max_severity")
    if sev == "high":
        tone, head = "bad", badge("MALICIOUS BEHAVIOUR", "bad", "x")
    elif sev in ("medium", "low"):
        tone, head = "warn", badge("SUSPICIOUS", "warn", "alert")
    else:
        tone, head = "good", badge("NOTHING SIGNIFICANT", "good", "check")
    if not findings:
        banner = "<div class='ci-banner ci-b-good'>" + icon("check", 20) + "<div><b>Nothing significant found</b><br><span>No suspicious forms, hidden frames, redirects or obfuscated scripts were detected in the page HTML.</span></div></div>"
        return card("Page behaviour", "code", banner, tone, head)
    items = []
    for f in findings:
        s = f.get("severity") or "info"
        t = _SEV_TONE.get(s, "neutral")
        items.append(
            f"<div class='ci-finding ci-f-{t}'>{icon(_behaviour_icon(f.get('text', '')), 18)}"
            f"<div class='ci-ftext'>{esc(f.get('text'))}</div>{badge(s.upper(), t)}</div>"
        )
    return card("Page behaviour", "code", "".join(items), tone, head)


# --------------------------------------------------------------------------
# 5. Statistics
# --------------------------------------------------------------------------


def status_tone(code: Any) -> str:
    try:
        c = int(code)
    except (TypeError, ValueError):
        return "neutral"
    if 200 <= c < 300:
        return "good"
    if 500 <= c < 600:
        return "bad"
    return "warn"


def metric_tile(label: str, value: str | None, icon_name: str, tone: str = "neutral", sub: str | None = None, tip: str | None = None) -> str:
    tone = tone if tone in TONES else "neutral"
    title = f" title='{esc(tip)}'" if tip else ""
    val = esc(value) if value else "<span class='ci-na'>—</span>"
    subh = f"<div class='ci-tsub'>{esc(sub)}</div>" if sub else ""
    return (
        f"<div class='ci-tile ci-m-{tone}'{title}><div class='ci-tlabel'>{icon(icon_name, 16)}<span>{esc(label)}</span></div>"
        f"<div class='ci-tval'>{val}</div>{subh}</div>"
    )


def stats_grid(stats: dict | None, net: dict | None) -> str:
    stats, net = stats or {}, net or {}
    code = stats.get("status_code")
    share = net.get("https_share")
    share_tone = "neutral" if share is None else ("good" if share == 100 else "warn")
    cookies = stats.get("cookies_set")
    tiles = [
        metric_tile("Page load", fmt_seconds(stats.get("load_seconds")), "clock", "neutral", None, "Time the scanner took to fetch the page."),
        metric_tile("HTTP status", str(code) if code is not None else None, "pulse", status_tone(code), None, "2xx is success, 3xx/4xx needs attention, 5xx is a server error."),
        metric_tile("HTML size", fmt_bytes(stats.get("html_bytes")), "file", "neutral", None, "Size of the page HTML the scanner downloaded."),
        metric_tile("Resources referenced", str(net["resources"]) if net.get("resources") is not None else None, "layers", "neutral", "scripts, images, styles", "Scripts, images, styles and frames referenced by the HTML."),
        metric_tile("HTTPS resources", f"{share}%" if share is not None else None, "lock", share_tone, None, "Share of referenced resources that load over HTTPS."),
        metric_tile("Cookies set", str(cookies) if cookies is not None else None, "cookie", "neutral", None, "Cookies set by the server when the page was fetched."),
    ]
    return f"<div class='ci-grid'>{''.join(tiles)}</div>"


# --------------------------------------------------------------------------
# 6. Server location
# --------------------------------------------------------------------------


def location_card(loc: dict | None) -> str:
    loc = loc or {}
    if loc.get("status") == "ok" and (loc.get("country") or loc.get("ip")):
        cc = loc.get("country")
        head = badge(str(cc), "good", "pin") if cc else badge("IDENTIFIED", "good", "pin")
        asn = loc.get("asn")
        asn_html = dash(f"{asn} · {loc.get('asn_name')}" if asn and loc.get("asn_name") else asn)
        body = facts([
            fact("Country code", dash(cc), "Two-letter country code reported by the network registry."),
            fact("IP address", dash(loc.get("ip"))),
            fact("Network (ASN)", asn_html, "The autonomous system that announces this IP address."),
        ])
        return card("Server location", "pin", body, "good", head)
    body = "<div class='ci-unavail'>" + icon("pin", 22) + "<div><b>Location unavailable</b><br><span>It could not be determined, so nothing is guessed.</span></div></div>"
    return card("Server location", "pin", body, "neutral", badge("UNAVAILABLE", "neutral", "info"))


# --------------------------------------------------------------------------
# Preview frame
# --------------------------------------------------------------------------


def preview_card(url: str | None) -> str:
    if not url:
        return ""
    body = (
        f"<div class='ci-shot'><img src='{esc(url)}' alt='Screenshot preview of the scanned page' "
        f"loading='lazy' referrerpolicy='no-referrer'></div>"
        + note("Screenshot from the third-party service thum.io. A blank or black image usually means the site blocked it.")
    )
    return card("Site preview", "image", body, "neutral", badge("THIRD PARTY", "neutral", "info"))


# --------------------------------------------------------------------------
# Stylesheet
# --------------------------------------------------------------------------

CSS = """
.ci-ic{display:inline-flex;align-items:center;justify-content:center;flex:none}
.ci-card{position:relative;background:linear-gradient(145deg,rgba(24,31,47,.96),rgba(14,19,29,.96));border:1px solid rgba(155,170,198,.16);border-radius:16px;padding:18px 18px 16px;margin-bottom:14px;box-shadow:0 8px 28px rgba(0,0,0,.18);transition:transform .2s ease,border-color .2s ease,box-shadow .2s ease;overflow:hidden}
.ci-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--ci-accent,#8995ad);opacity:.85}
.ci-card:hover{transform:translateY(-2px);border-color:rgba(139,124,255,.38);box-shadow:0 14px 34px rgba(0,0,0,.28)}
.ci-t-good{--ci-accent:#57d6a1}.ci-t-warn{--ci-accent:#f5c451}.ci-t-bad{--ci-accent:#ff6e83}.ci-t-neutral{--ci-accent:#6d9cff}
.ci-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.ci-title{display:flex;align-items:center;gap:9px;color:#e8edf8;font-size:14px;font-weight:700;letter-spacing:-.1px}
.ci-title .ci-ic{color:var(--ci-accent,#8995ad)}
.ci-badge{display:inline-flex;align-items:center;gap:5px;padding:4px 9px;border-radius:999px;font:600 10.5px 'DM Mono',monospace;letter-spacing:.8px;white-space:nowrap;border:1px solid transparent}
.ci-good{color:#75e3b5;background:rgba(87,214,161,.11);border-color:rgba(87,214,161,.3)}
.ci-warn{color:#f5c451;background:rgba(245,196,81,.11);border-color:rgba(245,196,81,.3)}
.ci-bad{color:#ff91a0;background:rgba(255,110,131,.12);border-color:rgba(255,110,131,.32)}
.ci-neutral{color:#a9b4ca;background:rgba(155,170,198,.09);border-color:rgba(155,170,198,.22)}
.ci-amber{color:#f5c451}.ci-red{color:#ff91a0}.ci-na{color:#6b7790}
.ci-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px 16px}
.ci-fact{min-width:0}
.ci-k{color:#8995ad;font:10px 'DM Mono',monospace;letter-spacing:.9px;text-transform:uppercase;margin-bottom:4px;cursor:help}
.ci-v{color:#e8edf8;font-size:13px;font-weight:600;overflow-wrap:anywhere}
.ci-metric{border-radius:12px;padding:14px 16px;margin-bottom:14px;border:1px solid rgba(155,170,198,.14);background:rgba(255,255,255,.025)}
.ci-big{font-size:30px;font-weight:800;letter-spacing:-1px;line-height:1.1}
.ci-sub{color:#8995ad;font-size:11.5px;margin-top:4px}
.ci-m-good .ci-big,.ci-m-good .ci-tval{color:#57d6a1}.ci-m-warn .ci-big,.ci-m-warn .ci-tval{color:#f5c451}.ci-m-bad .ci-big,.ci-m-bad .ci-tval{color:#ff6e83}.ci-m-neutral .ci-big,.ci-m-neutral .ci-tval{color:#edf2fb}
.ci-m-good.ci-metric{background:linear-gradient(135deg,rgba(87,214,161,.10),rgba(87,214,161,.02))}
.ci-m-warn.ci-metric{background:linear-gradient(135deg,rgba(245,196,81,.10),rgba(245,196,81,.02))}
.ci-m-bad.ci-metric{background:linear-gradient(135deg,rgba(255,110,131,.12),rgba(255,110,131,.02))}
.ci-note{display:flex;gap:8px;align-items:flex-start;margin-top:14px;color:#8995ad;font-size:11.5px;line-height:1.55}
.ci-note .ci-ic{margin-top:1px;color:#6d9cff}
.ci-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid rgba(155,170,198,.12)}
.ci-row:last-of-type{border-bottom:0}
.ci-rowname{color:#e8edf8;font-size:13px;font-weight:600;overflow-wrap:anywhere}
.ci-banner{display:flex;gap:12px;align-items:flex-start;border-radius:12px;padding:14px 16px;font-size:12.5px;line-height:1.55;color:#cbd4e5}
.ci-banner b{color:#e8edf8;font-size:13.5px}.ci-banner span{color:#8995ad}
.ci-b-good{background:linear-gradient(135deg,rgba(87,214,161,.12),rgba(87,214,161,.03));border:1px solid rgba(87,214,161,.25)}
.ci-b-good .ci-ic{color:#57d6a1}
.ci-finding{display:flex;gap:11px;align-items:flex-start;border-radius:11px;padding:11px 13px;margin-bottom:8px;border:1px solid rgba(155,170,198,.14);background:rgba(255,255,255,.025)}
.ci-finding .ci-ftext{flex:1;color:#dbe3f2;font-size:12.5px;line-height:1.5;min-width:0;overflow-wrap:anywhere}
.ci-f-warn{border-color:rgba(245,196,81,.28);background:rgba(245,196,81,.06)}.ci-f-warn>.ci-ic{color:#f5c451}
.ci-f-bad{border-color:rgba(255,110,131,.32);background:rgba(255,110,131,.07)}.ci-f-bad>.ci-ic{color:#ff6e83}
.ci-f-neutral>.ci-ic{color:#8995ad}
.ci-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:14px}
.ci-tile{border-radius:14px;padding:14px 15px;border:1px solid rgba(155,170,198,.15);background:linear-gradient(145deg,rgba(24,31,47,.96),rgba(14,19,29,.96));transition:transform .2s ease,border-color .2s ease;cursor:default}
.ci-tile:hover{transform:translateY(-2px);border-color:rgba(139,124,255,.38)}
.ci-tlabel{display:flex;align-items:center;gap:7px;color:#8995ad;font:10px 'DM Mono',monospace;letter-spacing:.9px;text-transform:uppercase}
.ci-tlabel .ci-ic{color:#6d9cff}
.ci-tval{font-size:24px;font-weight:800;letter-spacing:-.5px;margin-top:9px;overflow-wrap:anywhere}
.ci-tsub{color:#6b7790;font-size:11px;margin-top:3px}
.ci-m-good.ci-tile{border-color:rgba(87,214,161,.3);background:linear-gradient(145deg,rgba(87,214,161,.09),rgba(14,19,29,.96))}
.ci-m-warn.ci-tile{border-color:rgba(245,196,81,.3);background:linear-gradient(145deg,rgba(245,196,81,.09),rgba(14,19,29,.96))}
.ci-m-bad.ci-tile{border-color:rgba(255,110,131,.34);background:linear-gradient(145deg,rgba(255,110,131,.10),rgba(14,19,29,.96))}
.ci-unavail{display:flex;gap:12px;align-items:flex-start;color:#8995ad;font-size:12.5px;line-height:1.55}
.ci-unavail b{color:#cbd4e5;font-size:13.5px}
.ci-shot{border-radius:12px;overflow:hidden;border:1px solid rgba(155,170,198,.16);background:#05070b}
.ci-shot img{display:block;width:100%;height:auto}
@media (prefers-reduced-motion:reduce){.ci-card,.ci-tile{transition:none}.ci-card:hover,.ci-tile:hover{transform:none}}
@media (max-width:640px){.ci-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.ci-big{font-size:26px}.ci-card{padding:15px 14px}.ci-facts{grid-template-columns:1fr 1fr}}
"""
