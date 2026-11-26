"""Combine the model verdict with independent evidence into a final verdict,
a plain-language explanation and guided next steps."""

from __future__ import annotations

from backend.trust_signals import ESTABLISHED_DAYS, apply_trust_adjustment

SEVERE = {"high"}
CAUTION = {"medium", "high"}


def compose_verdict(result: dict, trust: dict, feeds: dict, behaviour: dict, tls: dict) -> dict:
    out = apply_trust_adjustment(result, trust)  # sets model_prediction, trust_signals, note
    model_pred = out["model_prediction"]
    max_sev = behaviour.get("max_severity")
    has_pw = bool(behaviour.get("has_password_form"))
    reasons: list[str] = []
    note = out.get("decision_note")

    # 1. Threat feed match beats everything.
    if feeds.get("overall") == "match":
        out["prediction"] = "PHISHING"
        names = ", ".join(s["name"] for s in feeds["sources"] if s["status"] == "match")
        note = f"Listed by a threat feed ({names}). Treat this site as dangerous."
    # 2. Established-domain downgrade must not hide severe page behaviour.
    elif model_pred == "PHISHING" and out["prediction"] == "NEEDS_REVIEW" and max_sev in SEVERE:
        out["prediction"] = "PHISHING"
        note = "The domain is established, but the page behaves suspiciously (see page behaviour), so the phishing verdict is kept."
    # 3. Upgrade an uncertain result for an established, well-behaved site.
    elif (
        model_pred == "NEEDS_REVIEW"
        and trust.get("established")
        and not has_pw
        and max_sev not in CAUTION
    ):
        out["prediction"] = "LIKELY_LEGITIMATE"
        years = trust["domain_age_days"] / 365
        note = (
            f"The model was uncertain, but {trust['registered_domain']} is about "
            f"{years:.0f} years old with a valid certificate, has no password form "
            f"and no suspicious behaviour. Shown as likely legitimate. This is "
            f"not a guarantee."
        )
    # 4. Severe behaviour on a model-legitimate page needs a second look.
    elif model_pred == "LEGITIMATE" and max_sev in SEVERE:
        out["prediction"] = "NEEDS_REVIEW"
        note = "The model found nothing wrong, but the page behaves suspiciously (see page behaviour)."
    out["decision_note"] = note

    # Plain-language explanation (what we checked).
    age = trust.get("domain_age_days")
    if age is None:
        reasons.append("Domain age: could not be checked.")
    elif age >= ESTABLISHED_DAYS:
        reasons.append(f"Domain age: well established (about {age / 365:.0f} years).")
    else:
        reasons.append(f"Domain age: young ({age} days old). New domains are a common phishing sign.")
    if tls.get("valid") is True:
        reasons.append("Connection: valid TLS certificate.")
    elif tls.get("valid") is False:
        reasons.append("Connection: the TLS certificate failed verification.")
    else:
        reasons.append("Connection: certificate could not be checked.")
    st = feeds.get("overall")
    reasons.append(
        {
            "match": "Threat intelligence: listed by a threat feed.",
            "no_match": "Threat intelligence: not found in the feeds checked (this does not prove safety).",
        }.get(st, "Threat intelligence: feeds were unavailable.")
    )
    if behaviour.get("status") == "ok":
        if max_sev in CAUTION:
            reasons.append("Page behaviour: suspicious behaviour found.")
        else:
            reasons.append("Page behaviour: nothing significant found.")
    chain = out.get("redirect_chain") or []
    if len(chain) > 1:
        reasons.append(f"Navigation: {len(chain) - 1} redirect(s) before the final page.")
    else:
        reasons.append("Navigation: direct link, no redirects.")
    out["explanation"] = reasons

    steps = {
        "PHISHING": [
            "Do not enter passwords, card details or personal information.",
            "Close the page. If you already entered details, change that password and any reused ones.",
            "Report the link to the site's owner or your national phishing-report service.",
        ],
        "NEEDS_REVIEW": [
            "Do not enter sensitive information until you are sure of the site.",
            "Type the organisation's address yourself instead of following this link.",
            "Look at the evidence above, especially domain age and page behaviour.",
        ],
        "LIKELY_LEGITIMATE": [
            "This site looks established, but stay careful about what you enter.",
            "Check that the address bar shows exactly the site you expect.",
        ],
        "LEGITIMATE": [
            "No problems found, but always check the address before signing in.",
        ],
    }
    out["next_steps"] = steps.get(out["prediction"], [])
    return out
