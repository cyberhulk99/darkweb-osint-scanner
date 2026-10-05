"""
Tor-proxied HTTP scanner.

Requires:
  - Tor running on localhost:9050
  - requests[socks] installed  (pip install requests[socks])
"""

import re
import time
import urllib.parse
from utils import write_log

try:
    import requests
    from requests.exceptions import RequestException
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    raise RuntimeError("requests[socks] is required. Run: pip install requests[socks]")

# ── Tor SOCKS5 proxy ─────────────────────────────────────────────────────────

TOR_PROXY = {
    "http":  "socks5h://127.0.0.1:9050",   # socks5h = DNS via Tor (essential for .onion)
    "https": "socks5h://127.0.0.1:9050",
}

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

REQUEST_TIMEOUT = 30   # seconds
RATE_DELAY      = 2    # seconds between requests (avoid rate-limiting)


def tor_session() -> "requests.Session":
    s = requests.Session()
    s.proxies = TOR_PROXY
    s.headers.update(_HEADERS)
    return s


def check_tor(session: "requests.Session") -> bool:
    """Return True if requests are actually routing through Tor."""
    try:
        r = session.get("https://check.torproject.org/api/ip", timeout=15)
        return r.json().get("IsTor", False)
    except Exception:
        return False


# ── Low-level fetch ──────────────────────────────────────────────────────────

def _fetch(url: str, session: "requests.Session", retries: int = 3) -> str | None:
    for attempt in range(retries):
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            time.sleep(RATE_DELAY)
            return r.text
        except Exception as e:
            write_log(f"Fetch attempt {attempt + 1}/{retries} failed [{url}]: {e}")
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    return None


def _strip_html(html: str) -> str:
    text = re.sub(r'<[^>]+>', ' ', html)
    return re.sub(r'\s+', ' ', text).strip()


# ── Search engines ───────────────────────────────────────────────────────────

def search_ahmia(query: str, session: "requests.Session") -> list[dict]:
    """
    Ahmia indexes .onion sites and has both a clearnet and .onion version.
    Try the .onion version first (richer results); fall back to clearnet.
    """
    encoded = urllib.parse.quote_plus(query)
    urls = [
        f"http://juhanurmihxlp77nkq76byazcldy2hlmojfz3gajpcb2jt6u2e5ygyd.onion/search/?q={encoded}",
        f"https://ahmia.fi/search/?q={encoded}",
    ]
    results = []
    for url in urls:
        html = _fetch(url, session)
        if not html:
            continue
        # Extract .onion result links
        links = re.findall(r'href="(http://[a-z2-7]{16,56}\.onion[^"]*)"', html)
        snippets = re.findall(
            r'<p[^>]*class="[^"]*result[^"]*"[^>]*>(.*?)</p>', html, re.DOTALL
        )
        for i, link in enumerate(links[:20]):
            snippet = _strip_html(snippets[i]) if i < len(snippets) else ""
            results.append({"url": link, "snippet": snippet})
        if results:
            break
    write_log(f"Ahmia: {len(results)} results for '{query}'")
    return results


def search_torch(query: str, session: "requests.Session") -> list[dict]:
    """Torch is one of the oldest .onion search engines."""
    encoded = urllib.parse.quote_plus(query)
    url = (
        f"http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion"
        f"/search?query={encoded}&action=search"
    )
    html = _fetch(url, session)
    results = []
    if html:
        links = re.findall(r'href="(http://[a-z2-7]{16,56}\.onion[^"]*)"', html)
        results = [{"url": l, "snippet": ""} for l in links[:20]]
    write_log(f"Torch: {len(results)} results for '{query}'")
    return results


def search_haystak(query: str, session: "requests.Session") -> list[dict]:
    """Haystak — another .onion search engine."""
    encoded = urllib.parse.quote_plus(query)
    url = (
        f"http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion"
        f"/?q={encoded}"
    )
    html = _fetch(url, session)
    results = []
    if html:
        links = re.findall(r'href="(http://[a-z2-7]{16,56}\.onion[^"]*)"', html)
        results = [{"url": l, "snippet": ""} for l in links[:20]]
    write_log(f"Haystak: {len(results)} results for '{query}'")
    return results


def fetch_result_pages(search_results: list[dict], session: "requests.Session",
                       max_pages: int = 5) -> list[dict]:
    """Fetch the actual text content of result pages for deep analysis."""
    pages = []
    for item in search_results[:max_pages]:
        url = item.get("url", "")
        if not url:
            continue
        html = _fetch(url, session)
        if html:
            pages.append({"url": url, "content": _strip_html(html)})
    return pages


# ── Paste site monitor ───────────────────────────────────────────────────────

_PASTE_SITES = [
    "http://zeropaste3vcbfhq6.onion/",
    "http://depastedihrn3jtw.onion/",
]


def scan_paste_sites(keywords: list[str], session: "requests.Session") -> list[dict]:
    """
    Fetch recent pastes from known dark web paste sites.
    Return only those that contain at least one org keyword.
    """
    hits = []
    for site in _PASTE_SITES:
        html = _fetch(site, session)
        if not html:
            continue
        paste_links = re.findall(r'href="(/[a-zA-Z0-9]{4,})"', html)
        for link in paste_links[:30]:
            paste_url = site.rstrip("/") + link
            content = _fetch(paste_url, session)
            if not content:
                continue
            text = _strip_html(content)
            if any(kw.lower() in text.lower() for kw in keywords):
                hits.append({"url": paste_url, "content": text})
    write_log(f"Paste sites: {len(hits)} keyword hits")
    return hits


# ── Ransomware blog monitor ──────────────────────────────────────────────────

def scan_ransomware_blogs(keywords: list[str], session: "requests.Session",
                          blogs_file: str) -> list[dict]:
    """
    Check ransomware / extortion group leak sites for org mentions.
    Addresses are loaded from blogs_file (one .onion URL per line).
    Populate that file from: https://www.ransomlook.io/ or ransomwatch.telemetry.ltd
    """
    import os
    hits = []
    if not os.path.exists(blogs_file):
        write_log(f"Ransomware blogs file missing: {blogs_file}")
        return hits

    with open(blogs_file) as f:
        sites = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if not sites:
        write_log("Ransomware blogs file is empty — populate it from ransomlook.io")
        return hits

    for site in sites:
        html = _fetch(site, session)
        if not html:
            continue
        text = _strip_html(html)
        if any(kw.lower() in text.lower() for kw in keywords):
            hits.append({"url": site, "content": text[:8000]})

    write_log(f"Ransomware blogs: {len(hits)} hits / {len(sites)} checked")
    return hits
