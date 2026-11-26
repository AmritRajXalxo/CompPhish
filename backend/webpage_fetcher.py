"""
CompPhish Webpage Fetcher

Retrieves HTML from publicly accessible websites.
Includes basic protections against unsafe URL fetching.
"""

import ipaddress
import socket
import time

import httpx
from urllib.parse import urljoin, urlparse


MAX_HTML_SIZE = 2 * 1024 * 1024  # 2 MB
MAX_REDIRECTS = 5
TIMEOUT = 10.0


def validate_public_url(url: str) -> str:
    """Validate URL and reject private or unsafe destinations."""

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid website URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    if parsed.port not in (None, 80, 443):
        raise ValueError("Only standard HTTP/HTTPS ports are allowed.")

    hostname = parsed.hostname

    try:
        addresses = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        raise ValueError("Unable to resolve website hostname.")

    if not addresses:
        raise ValueError("Website hostname has no valid IP address.")

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])

        if not ip.is_global:
            raise ValueError("Private or non-public IP destinations are blocked.")

    return url


def fetch_webpage(url: str) -> dict:
    """
    Fetch webpage HTML with redirect, timeout and size limits.

    Returns:
        {
            "final_url": "...",
            "html": "...",
            "content_type": "..."
        }
    """

    current_url = url
    chain = []
    started = time.monotonic()

    headers = {
        "User-Agent": "CompPhishResearchScanner/1.0",
        "Accept": "text/html,application/xhtml+xml",
    }

    with httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=False,
        trust_env=False,
    ) as client:

        for redirect_count in range(MAX_REDIRECTS + 1):

            validate_public_url(current_url)

            with client.stream(
                "GET",
                current_url,
                headers=headers,
            ) as response:

                if response.status_code in (301, 302, 303, 307, 308):

                    if redirect_count >= MAX_REDIRECTS:
                        raise ValueError("Too many redirects.")

                    location = response.headers.get("location")

                    if not location:
                        raise ValueError("Redirect location is missing.")

                    chain.append(
                        {"url": current_url, "status": response.status_code}
                    )
                    current_url = urljoin(current_url, location)
                    continue

                response.raise_for_status()

                content_type = response.headers.get(
                    "content-type", ""
                ).lower()

                if not (
                    "text/html" in content_type
                    or "application/xhtml+xml" in content_type
                ):
                    raise ValueError(
                        "The requested resource is not an HTML webpage."
                    )

                content_length = response.headers.get("content-length")

                if content_length:
                    if int(content_length) > MAX_HTML_SIZE:
                        raise ValueError("Webpage is too large.")

                chunks = []
                total_size = 0

                for chunk in response.iter_bytes():
                    total_size += len(chunk)

                    if total_size > MAX_HTML_SIZE:
                        raise ValueError("Webpage exceeds the size limit.")

                    chunks.append(chunk)

                html = b"".join(chunks).decode(
                    response.encoding or "utf-8",
                    errors="replace",
                )

                chain.append(
                    {"url": str(response.url), "status": response.status_code}
                )

                return {
                    "final_url": str(response.url),
                    "html": html,
                    "content_type": content_type,
                    "redirect_chain": chain,
                    "status_code": response.status_code,
                    "load_seconds": round(time.monotonic() - started, 2),
                    "cookie_count": len(
                        response.headers.get_list("set-cookie")
                    ),
                    "server_header": response.headers.get("server"),
                    "security_headers": {
                        name: name in response.headers
                        for name in (
                            "strict-transport-security",
                            "content-security-policy",
                            "x-frame-options",
                            "x-content-type-options",
                        )
                    },
                }

    raise ValueError("Unable to retrieve webpage.")