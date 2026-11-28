#!/usr/bin/env python
"""
Print a few CURRENT phishing URLs (from the OpenPhish public feed) to paste into the scanner.

Many feed entries are dead within hours. This script looks each host up in DNS first and keeps
only hosts that still resolve, so you waste fewer scans on "Unable to resolve website hostname".
It does NOT connect to the phishing sites; it only asks your DNS resolver for the address.

    python scripts/fresh_phish_urls.py              # 10 URLs, defanged (safe to paste in chat)
    python scripts/fresh_phish_urls.py -n 20 --plain  # raw URLs for a file
    python scripts/fresh_phish_urls.py --from-file urls.txt

Defanged output (hxxp, [.]) cannot be clicked by accident. The scanner understands it, so you can
paste it as it is. Never open these addresses in your browser.
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import re
import socket
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

FEED = "https://openphish.com/feed.txt"
FREE_HOSTS = ("github.io", "blogspot.com", "weebly.com", "wixsite.com", "web.app", "pages.dev",
              "workers.dev", "vercel.app", "netlify.app", "glitch.me", "000webhostapp.com")
PERSONAL = re.compile(r"[?&](e?-?mail|user(name)?|u|id)=[^&]*(@|%40|[A-Za-z0-9+/]{16,}={0,2})", re.I)


def defang(url: str) -> str:
    return re.sub(r"^http", "hxxp", url, count=1, flags=re.I).replace(".", "[.]")


def usable(url: str) -> str | None:
    """Host name if the URL is worth testing, else None."""
    if len(url) > 160 or "@" in url or PERSONAL.search(url):
        return None  # long URLs and ones carrying a victim's address or token
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return None
    if not host or "." not in host:
        return None
    try:
        ipaddress.ip_address(host)
        return None  # raw IP addresses
    except ValueError:
        pass
    if any(host == h or host.endswith("." + h) for h in FREE_HOSTS):
        return None
    return host


def resolves(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            return False  # sinkholed or internal: not a real page
    return bool(infos)


def pick_live(urls: list[str], n: int, seed: int | None = None, resolver=resolves, workers: int = 32) -> list[str]:
    """Up to n URLs on distinct hosts whose hostname still resolves."""
    rng = random.Random(seed)
    pool = []
    seen = set()
    for u in dict.fromkeys(urls):
        host = usable(u)
        if host and host not in seen:
            seen.add(host)
            pool.append((u, host))
    rng.shuffle(pool)
    pool = pool[: max(n * 25, 100)]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        alive = list(ex.map(lambda p: resolver(p[1]), pool))
    return [u for (u, _), ok in zip(pool, alive) if ok][:n]


def read_urls(path: str | None) -> list[str]:
    if path:
        text = open(path, encoding="utf-8", errors="ignore").read()
    else:
        req = urllib.request.Request(FEED, headers={"User-Agent": "CompPhishResearch/1.0"})
        text = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "ignore")
    return [l.strip() for l in text.splitlines() if l.strip().lower().startswith(("http://", "https://"))]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", type=int, default=10)
    ap.add_argument("--plain", action="store_true", help="print raw URLs instead of defanged ones")
    ap.add_argument("--from-file", help="read URLs from a file instead of downloading the feed")
    ap.add_argument("--seed", type=int)
    args = ap.parse_args(argv)
    try:
        urls = read_urls(args.from_file)
    except Exception as exc:
        print(f"Could not read the feed ({type(exc).__name__}: {exc}).", file=sys.stderr)
        return 1
    live = pick_live(urls, args.n, args.seed)
    if not live:
        print("No URL with a resolving hostname was found. Try again in a few minutes.", file=sys.stderr)
        return 2
    print(f"# {len(live)} phishing URLs whose hostnames still resolve (from {len(urls)} feed entries).")
    print("# Paste into the scanner. Do not open them in your browser.")
    for u in live:
        print(u if args.plain else defang(u))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
