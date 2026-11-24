"""
CompPhish inference-time feature extraction.

Feature definitions are ported from the uploaded combined CompPhish/PhreshPhish
notebook:
- URL features: common URL extraction cell (28 features).
- HTML structure/text: HTML extraction cell (six structural features and
  visible text), followed by the training text-cleaning step.

Keep this file aligned with the notebook if training preprocessing changes.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

import numpy as np
from bs4 import BeautifulSoup


URL_FEATURES = [
    "url_len",
    "host_len",
    "path_len",
    "query_len",
    "n_dots",
    "n_hyphens",
    "n_underscores",
    "n_at",
    "n_pct",
    "n_amp",
    "n_eq",
    "n_slashes",
    "n_subdomains",
    "host_digits",
    "host_has_ip",
    "host_entropy",
    "has_https",
    "has_query",
    "has_fragment",
    "has_port",
    "path_depth",
    "suspicious_word_count",
    "has_suspicious_word",
    "is_url_shortener",
    "has_punycode",
    "url_entropy",
    "digit_ratio",
    "special_char_ratio",
]

HTML_FEATURES = [
    "tag_count",
    "form_count",
    "input_count",
    "password_fields",
    "script_count",
    "anchor_count",
]

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "password",
    "banking",
    "confirm",
    "wallet",
    "authentication",
    "paypal",
    "webscr",
    "credential",
    "suspended",
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
]

MAX_HTML_CHARS = 250_000
MAX_TEXT_CHARS = 4_000


class FeatureExtractionNotConfigured(ValueError):
    """Raised when requested model features do not match this extractor."""


def _safe_string(value: Any) -> str:
    """Convert missing values to an empty string without emitting 'nan'."""
    if value is None:
        return ""
    if isinstance(value, (float, np.floating)) and np.isnan(value):
        return ""
    return str(value)


def calculate_entropy(value: str) -> float:
    """Shannon character entropy, matching the training notebook."""
    if not value:
        return 0.0

    counts = Counter(value)
    total = len(value)

    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts.values()
    )


def _validate_feature_names(
    supplied: list[str] | tuple[str, ...] | None,
    expected: list[str],
    modality: str,
) -> list[str]:
    if supplied is None:
        return expected.copy()

    names = list(supplied)
    if names != expected:
        raise FeatureExtractionNotConfigured(
            f"{modality} feature names/order do not match the "
            f"CompPhish extractor. Expected {expected}; received {names}."
        )
    return names


def extract_url_features(
    url: str,
    feature_names: list[str] | tuple[str, ...] | None = None,
) -> dict[str, int | float]:
    """
    Extract the model's 28 URL features.

    Parsing and feature formulas follow the common URL feature extraction
    function in the uploaded combined notebook.
    """
    names = _validate_feature_names(
        feature_names, URL_FEATURES, "URL"
    )

    url = _safe_string(url).strip()

    hostname = ""
    path = ""
    query = ""
    fragment = ""
    scheme = ""
    port = None

    try:
        parse_url = url
        if parse_url and not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://", parse_url
        ):
            parse_url = "http://" + parse_url

        parsed = urlsplit(parse_url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        scheme = parsed.scheme.lower()

        try:
            port = parsed.port
        except ValueError:
            port = None
    except Exception:
        # The training implementation keeps the initialized empty defaults.
        pass

    hostname = hostname.lower()
    host_parts = [part for part in hostname.split(".") if part]

    try:
        ipaddress.ip_address(hostname)
        host_has_ip = 1
    except ValueError:
        host_has_ip = 0

    lower_url = url.lower()
    suspicious_word_count = sum(
        lower_url.count(word) for word in SUSPICIOUS_WORDS
    )

    is_url_shortener = int(
        any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in SHORTENERS
        )
    )

    digit_count = sum(character.isdigit() for character in url)
    special_char_count = sum(
        not character.isalnum() for character in url
    )

    features = {
        "url_len": len(url),
        "host_len": len(hostname),
        "path_len": len(path),
        "query_len": len(query),
        "n_dots": url.count("."),
        "n_hyphens": url.count("-"),
        "n_underscores": url.count("_"),
        "n_at": url.count("@"),
        "n_pct": url.count("%"),
        "n_amp": url.count("&"),
        "n_eq": url.count("="),
        "n_slashes": url.count("/"),
        "n_subdomains": max(len(host_parts) - 2, 0),
        "host_digits": sum(character.isdigit() for character in hostname),
        "host_has_ip": host_has_ip,
        "host_entropy": calculate_entropy(hostname),
        "has_https": int(scheme == "https"),
        "has_query": int(bool(query)),
        "has_fragment": int(bool(fragment)),
        "has_port": int(port is not None),
        "path_depth": len([part for part in path.split("/") if part]),
        "suspicious_word_count": suspicious_word_count,
        "has_suspicious_word": int(suspicious_word_count > 0),
        "is_url_shortener": is_url_shortener,
        "has_punycode": int("xn--" in hostname),
        "url_entropy": calculate_entropy(url),
        "digit_ratio": digit_count / len(url) if url else 0.0,
        "special_char_ratio": (
            special_char_count / len(url) if url else 0.0
        ),
    }

    # Preserve exactly the saved model's feature order.
    return {name: features[name] for name in names}


def _parse_html(html: str) -> BeautifulSoup:
    html = _safe_string(html)[:MAX_HTML_CHARS]
    return BeautifulSoup(html, "lxml")


def extract_html_features(
    html: str,
    feature_names: list[str] | tuple[str, ...] | None = None,
) -> dict[str, int]:
    """
    Extract six structural features.

    Counts are taken before removing scripts/styles, as in the notebook's
    HTML extraction routine.
    """
    names = _validate_feature_names(
        feature_names, HTML_FEATURES, "HTML"
    )

    try:
        soup = _parse_html(html)

        inputs = soup.find_all("input")
        features = {
            "tag_count": len(soup.find_all()),
            "form_count": len(soup.find_all("form")),
            "input_count": len(inputs),
            "password_fields": sum(
                1
                for element in inputs
                if str(element.get("type", "")).lower() == "password"
            ),
            "script_count": len(soup.find_all("script")),
            "anchor_count": len(soup.find_all("a")),
        }
    except Exception:
        # Matches the notebook extraction fallback for unparseable HTML.
        features = {name: 0 for name in HTML_FEATURES}

    return {name: int(features[name]) for name in names}


def extract_visible_text(html: str) -> str:
    """
    Produce text_clean in the same way as the training data preparation:
    parse with lxml, remove non-visible elements, extract visible text,
    normalize whitespace, lowercase, and cap at 4,000 characters.
    """
    try:
        soup = _parse_html(html)

        for element in soup(
            ["script", "style", "noscript", "svg", "template"]
        ):
            element.decompose()

        visible_text = soup.get_text(
            separator=" ",
            strip=True,
        )
        visible_text = re.sub(r"\s+", " ", visible_text).strip()
        visible_text = visible_text[:MAX_TEXT_CHARS]

        # Training-time text_clean transformation from the notebook.
        text_clean = re.sub(
            r"\s+",
            " ",
            visible_text.lower(),
        ).strip()

        return text_clean
    except Exception:
        return ""


def extract_html_and_text(
    html: str,
    html_feature_names: list[str] | tuple[str, ...] | None = None,
) -> tuple[dict[str, int], str]:
    """Convenience function to obtain HTML features and text_clean."""
    html_features = extract_html_features(html, html_feature_names)
    page_text = extract_visible_text(html)
    return html_features, page_text
