"""
Tor-proxied HTTP scanner + clearnet threat intel sources.

Requires:
  - Tor running on localhost:9050
  - requests[socks] installed  (pip install requests[socks])

Optional environment variables for enhanced coverage:
  - HIBP_API_KEY    : HaveIBeenPwned API key (haveibeenpwned.com/API/Key)
  - GITHUB_TOKEN    : GitHub PAT with public_repo read scope
"""

import json
import os
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

# Clearnet requests bypass Tor — many clearnet APIs actively block Tor exit nodes.
_CLEARNET_SESSION = None

def _clearnet_session() -> "requests.Session":
    global _CLEARNET_SESSION
    if _CLEARNET_SESSION is None:
        _CLEARNET_SESSION = requests.Session()
        _CLEARNET_SESSION.headers.update(_HEADERS)
    return _CLEARNET_SESSION

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


# ── Dark web paste sites (.onion) ────────────────────────────────────────────

# Current as of late 2024 — rotate when addresses go dead
_ONION_PASTE_SITES = [
    "http://pastenow3gvhmnzg6hm7hzfpjsz3yrgkjktyxq6ngpkn7kzagx2qxid.onion/",
    "http://pastemenu3n5rpxtn7kfbdmvygsxudqjzm4b3zujd3vfbezqhvljbahyd.onion/",
    "http://depastedihrn3jtw.onion/",
]


def scan_paste_sites(keywords: list[str], session: "requests.Session") -> list[dict]:
    """Fetch recent pastes from dark web (.onion) paste sites."""
    hits = []
    for site in _ONION_PASTE_SITES:
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
    write_log(f"Onion paste sites: {len(hits)} keyword hits")
    return hits


# ── Clearnet paste sites ──────────────────────────────────────────────────────

def scan_pastebin_clearnet(keywords: list[str]) -> list[dict]:
    """
    Scrape Pastebin public archive for recent pastes containing org keywords.
    Uses clearnet — Pastebin blocks Tor exit nodes.
    Also checks paste.ee and ghostbin archives.
    """
    cs = _clearnet_session()
    hits = []

    # Pastebin public archive
    try:
        archive_html = cs.get("https://pastebin.com/archive", timeout=15).text
        paste_ids = re.findall(r'href="/([a-zA-Z0-9]{8})"', archive_html)[:50]
        for pid in paste_ids:
            try:
                content = cs.get(f"https://pastebin.com/raw/{pid}", timeout=10).text
                time.sleep(0.3)
                if any(kw.lower() in content.lower() for kw in keywords):
                    hits.append({
                        "url": f"https://pastebin.com/{pid}",
                        "content": content[:8000],
                    })
            except Exception:
                pass
    except Exception as e:
        write_log(f"Pastebin error: {e}")

    # paste.ee public archive
    try:
        archive_html = cs.get("https://paste.ee/recent", timeout=15).text
        paste_ids = re.findall(r'href="/p/([a-zA-Z0-9]+)"', archive_html)[:30]
        for pid in paste_ids:
            try:
                content = cs.get(f"https://paste.ee/r/{pid}", timeout=10).text
                time.sleep(0.3)
                if any(kw.lower() in content.lower() for kw in keywords):
                    hits.append({
                        "url": f"https://paste.ee/p/{pid}",
                        "content": content[:8000],
                    })
            except Exception:
                pass
    except Exception as e:
        write_log(f"paste.ee error: {e}")

    write_log(f"Clearnet pastes: {len(hits)} keyword hits")
    return hits


# ── DarkSearch.io ─────────────────────────────────────────────────────────────

def search_darksearch(query: str) -> list[dict]:
    """
    DarkSearch.io — free clearnet REST API that indexes dark web content.
    No Tor required, no API key needed. Rate limit: ~30 req/min.
    """
    cs = _clearnet_session()
    encoded = urllib.parse.quote_plus(query)
    url = f"https://darksearch.io/api/search?query={encoded}&page=1"
    results = []
    try:
        r = cs.get(url, timeout=15)
        r.raise_for_status()
        for hit in r.json().get("data", []):
            results.append({
                "url": hit.get("link", ""),
                "content": hit.get("description", "") + " " + hit.get("title", ""),
            })
        time.sleep(1)
    except Exception as e:
        write_log(f"DarkSearch error for '{query}': {e}")
    write_log(f"DarkSearch: {len(results)} results for '{query}'")
    return results


# ── HaveIBeenPwned domain search ──────────────────────────────────────────────

def check_hibp(email_domain: str, api_key: str) -> list[dict]:
    """
    Query HIBP for all accounts on this email domain found in known breaches.
    Returns pre-scored CRITICAL findings — these are confirmed, not candidate matches.
    Requires a paid HIBP API key: https://haveibeenpwned.com/API/Key
    Set env var HIBP_API_KEY before running.
    """
    if not api_key or not email_domain:
        return []
    cs = _clearnet_session()
    results = []
    try:
        r = cs.get(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{email_domain}",
            headers={"hibp-api-key": api_key, "user-agent": "WODS-DarkWebOSINT"},
            timeout=20,
        )
        if r.status_code == 200:
            # {email_prefix: [breach_name, ...], ...}
            data = r.json()
            for prefix, breaches in data.items():
                full_email = f"{prefix}@{email_domain}"
                results.append({
                    "url": f"https://haveibeenpwned.com/account/{full_email}",
                    "content": (
                        f"HIBP confirmed breach: {full_email} appears in "
                        f"{len(breaches)} breach(es): {', '.join(breaches[:10])}"
                    ),
                    "source": "hibp",
                    "pre_severity": "critical",
                    "indicator": f"HIBP: account in {len(breaches)} breach(es)",
                })
        elif r.status_code == 404:
            write_log(f"HIBP: {email_domain} not found in any known breaches")
        elif r.status_code == 401:
            write_log("HIBP: invalid API key — check HIBP_API_KEY env var")
        elif r.status_code == 429:
            write_log("HIBP: rate limited — back off")
    except Exception as e:
        write_log(f"HIBP error: {e}")
    write_log(f"HIBP: {len(results)} breached account(s) for {email_domain}")
    return results


# ── GitHub public code search ─────────────────────────────────────────────────

_GITHUB_SENSITIVE = [
    "password", "secret", "api_key", "apikey", "token",
    "private_key", "access_key", "credentials", "passwd",
]


def scan_github_code(keywords: list[str], token: str) -> list[dict]:
    """
    Search GitHub public repos for org keywords near sensitive terms.
    Leaked API keys, DB connection strings, and config files with credentials
    are one of the most common real-world enterprise breach vectors.
    Requires a GitHub classic PAT with no special scopes (public repo search is free).
    Set env var GITHUB_TOKEN before running.
    """
    if not token:
        write_log("GitHub scan skipped — set GITHUB_TOKEN env var to enable")
        return []
    cs = _clearnet_session()
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "WODS-DarkWebOSINT",
    }
    hits = []
    seen_repos = set()

    for kw in keywords[:3]:
        for term in _GITHUB_SENSITIVE[:4]:
            query = urllib.parse.quote_plus(f'"{kw}" {term}')
            url = f"https://api.github.com/search/code?q={query}&per_page=10"
            try:
                r = cs.get(url, headers=headers, timeout=20)
                time.sleep(2.5)  # GitHub: 30 authenticated code search req/min
                if r.status_code == 200:
                    for item in r.json().get("items", []):
                        repo = item["repository"]["full_name"]
                        path = item["path"]
                        uid = f"{repo}/{path}"
                        if uid in seen_repos:
                            continue
                        seen_repos.add(uid)
                        hits.append({
                            "url": item["html_url"],
                            "content": (
                                f"GitHub public repo {repo} contains '{kw}' near "
                                f"'{term}' in file {path}. This may be a leaked "
                                f"credential or internal reference."
                            ),
                            "source": "github",
                            "pre_severity": "high",
                            "indicator": f"GitHub code: '{kw}' + '{term}' in {path}",
                        })
                elif r.status_code == 403:
                    write_log("GitHub: rate limited — pausing 60s")
                    time.sleep(60)
                elif r.status_code == 422:
                    write_log(f"GitHub: query too complex for '{kw}' + '{term}'")
            except Exception as e:
                write_log(f"GitHub search error ({kw} + {term}): {e}")

    write_log(f"GitHub: {len(hits)} potential code exposure(s)")
    return hits


# ── Telegram public channel monitor ──────────────────────────────────────────

# Public Telegram threat intel channels — threat actors announce victims and
# sell access here. All are public and readable via t.me/s/<channel> (no auth).
_TELEGRAM_CHANNELS = [
    "darkwebinformer",      # breach announcements
    "leakbase",             # credential leak announcements
    "databreachesnews",     # breach tracking
    "RansomwareUpdates",    # ransomware victim tracking
    "H4ckManac",            # general threat intel
]


def scan_telegram_channels(keywords: list[str],
                            extra_channels: list[str] | None = None) -> list[dict]:
    """
    Monitor public Telegram threat intel channels for org keyword mentions.
    Uses t.me/s/<channel> (public web preview, no API key or account needed).
    Threat actors have largely moved from dark web forums to Telegram.
    """
    cs = _clearnet_session()
    channels = _TELEGRAM_CHANNELS + (extra_channels or [])
    hits = []

    for channel in channels:
        url = f"https://t.me/s/{channel}"
        try:
            html = cs.get(url, timeout=15).text
            time.sleep(1)
            text = _strip_html(html)
            matching_kws = [kw for kw in keywords if kw.lower() in text.lower()]
            if matching_kws:
                # Extract just the relevant message windows
                snippets = []
                for kw in matching_kws:
                    for m in re.finditer(re.escape(kw), text, re.IGNORECASE):
                        start = max(0, m.start() - 200)
                        end   = min(len(text), m.end() + 200)
                        snippets.append(text[start:end])
                hits.append({
                    "url": url,
                    "content": " ... ".join(snippets[:5]),
                    "source": "telegram",
                })
        except Exception as e:
            write_log(f"Telegram channel @{channel} error: {e}")

    write_log(f"Telegram: {len(hits)} channel(s) with keyword matches")
    return hits


# ── RansomWatch feed (auto-updated victim database) ───────────────────────────

def scan_ransomwatch(keywords: list[str]) -> list[dict]:
    """
    RansomWatch is an open-source project that continuously scrapes all known
    ransomware group leak sites and publishes victims as JSON on GitHub.
    More reliable than manually maintained .onion addresses — auto-updated.
    Source: https://github.com/joshhighet/ransomwatch
    """
    cs = _clearnet_session()
    hits = []
    feed_url = (
        "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    )
    try:
        r = cs.get(feed_url, timeout=30)
        r.raise_for_status()
        posts = r.json()  # [{group_name, post_title, discovered, ...}, ...]
        for post in posts:
            title   = str(post.get("post_title", "")).lower()
            group   = str(post.get("group_name", ""))
            country = str(post.get("country", ""))
            if any(kw.lower() in title for kw in keywords):
                hits.append({
                    "url": f"https://github.com/joshhighet/ransomwatch",
                    "content": (
                        f"RansomWatch victim match: '{post.get('post_title')}' "
                        f"listed by {group} on {post.get('discovered', 'unknown date')}. "
                        f"Country: {country}."
                    ),
                    "source": "ransomwatch",
                    "pre_severity": "critical",
                    "indicator": f"Ransomware victim listing by {group}",
                })
    except Exception as e:
        write_log(f"RansomWatch feed error: {e}")
    write_log(f"RansomWatch: {len(hits)} victim match(es) in feed")
    return hits


# ── Ransomware blog monitor (.onion) ──────────────────────────────────────────

def scan_ransomware_blogs(keywords: list[str], session: "requests.Session",
                          blogs_file: str) -> list[dict]:
    """
    Check ransomware group .onion leak sites directly for org mentions.
    Addresses are loaded from blogs_file (one .onion URL per line).
    Complement to scan_ransomwatch() which uses the auto-updated feed.
    Populate from: https://www.ransomlook.io/
    """
    hits = []
    if not os.path.exists(blogs_file):
        write_log(f"Ransomware blogs file missing: {blogs_file}")
        return hits

    with open(blogs_file) as f:
        sites = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not sites:
        write_log("Ransomware blogs file is empty — populate from ransomlook.io or use scan_ransomwatch()")
        return hits

    for site in sites:
        html = _fetch(site, session)
        if not html:
            continue
        text = _strip_html(html)
        if any(kw.lower() in text.lower() for kw in keywords):
            hits.append({"url": site, "content": text[:8000]})

    write_log(f"Ransomware blogs (.onion): {len(hits)} hits / {len(sites)} checked")
    return hits
