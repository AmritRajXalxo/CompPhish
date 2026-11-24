"""
Training-time feature parity adapter.

IMPORTANT:
The exact URL and HTML feature formulas must be copied from the original
training notebook. This module intentionally refuses to invent approximations.
"""


class FeatureExtractionNotConfigured(NotImplementedError):
    pass


def extract_url_features(url: str, feature_names: list[str]) -> dict:
    """
    TODO: Port the exact 28-feature extraction implementation from the
    Google Colab training notebook.

    Return a dictionary containing every name in feature_names, with the
    same numeric types and calculations used during training.
    """
    raise FeatureExtractionNotConfigured(
        "URL feature extraction has not yet been ported from the training notebook. "
        "Do not use approximate feature calculations for model inference."
    )


def extract_html_features(html: str, feature_names: list[str]) -> dict:
    """
    TODO: Port the exact six HTML structural feature calculations from the
    training notebook. Preserve its parsing and counting rules.
    """
    raise FeatureExtractionNotConfigured(
        "HTML feature extraction has not yet been ported from the training notebook."
    )


def extract_visible_text(html: str) -> str:
    """
    Basic visible-text extraction helper. Verify its cleaning/tokenization
    behavior against the training-time text extraction before deployment.
    """
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html or "", "html.parser")

    for node in soup(["script", "style", "noscript", "template"]):
        node.decompose()

    return " ".join(soup.stripped_strings)