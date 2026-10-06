import time
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import write_log, print_banner
from tor_control import start_tor_service
from result_store import is_new, record
from alert import send_alert
from analyzer import analyze_page, _severity_rank, Finding
from scanner import (
    tor_session, check_tor,
    search_ahmia, search_torch, search_haystak,
    fetch_result_pages,
    scan_paste_sites,
    scan_pastebin_clearnet,
    search_darksearch,
    check_hibp,
    scan_github_code,
    scan_telegram_channels,
    scan_ransomwatch,
    scan_ransomware_blogs,
)

_BASE        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROFILE_PATH = os.path.join(_BASE, "config", "org_profile.toml")
_BLOGS_FILE   = os.path.join(_BASE, "config", "ransomware_blogs.txt")


# ── Profile loading ───────────────────────────────────────────────────────────

def load_profile(path: str = _PROFILE_PATH) -> dict:
    try:
        import tomllib
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (ImportError, AttributeError):
        import toml
        with open(path) as f:
            return toml.load(f)


def _build_org_profile(config: dict) -> dict:
    """Flatten config into the dict the analyzer and scanners expect."""
    org   = config.get("organization", {})
    infra = config.get("infrastructure", {})

    name         = org.get("name", "")
    domains      = org.get("domains", [])
    email_domain = org.get("email_domain", domains[0] if domains else "")
    subsidiaries = org.get("subsidiaries", [])
    executives   = org.get("executives", [])
    extras       = org.get("keywords_extra", [])
    internal     = infra.get("internal_names", [])
    buckets      = infra.get("cloud_buckets", [])

    raw = [name] + domains + subsidiaries + executives + extras + internal + buckets
    keywords = list(dict.fromkeys(k for k in raw if k))  # dedup, preserve order

    return {
        "name":         name,
        "email_domain": email_domain,
        "keywords":     keywords,
    }


# ── Setup check ───────────────────────────────────────────────────────────────

def check_setup(config: dict) -> None:
    """Print a quick setup status report without scanning."""
    org      = _build_org_profile(config)
    hibp_key = os.environ.get("HIBP_API_KEY", "")
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    slack_wh = os.environ.get("SLACK_WEBHOOK_URL", "")

    ok  = "\033[92m✓\033[0m"
    no  = "\033[91m✗\033[0m"
    opt = "\033[93m○\033[0m"

    print("\n── WODS Setup Check ─────────────────────────────────────")
    print(f"  Org name      : {org['name'] or '⚠ NOT SET (fill in org_profile.toml)'}")
    print(f"  Email domain  : {org['email_domain'] or '⚠ NOT SET'}")
    print(f"  Keywords      : {len(org['keywords'])} term(s)")
    print()
    print(f"  {ok if org['name'] else no}  org_profile.toml — name configured")
    print(f"  {ok if org['email_domain'] else no}  org_profile.toml — email_domain configured")
    print()
    print(f"  {ok if hibp_key else opt}  HIBP_API_KEY      {'set' if hibp_key else 'not set (optional — paid key)'}")
    print(f"  {ok if gh_token else opt}  GITHUB_TOKEN      {'set' if gh_token else 'not set (optional — free PAT)'}")
    print(f"  {ok if slack_wh else opt}  SLACK_WEBHOOK_URL {'set' if slack_wh else 'not set (optional)'}")
    print()
    # Test Tor
    session = tor_session()
    tor_ok = check_tor(session)
    print(f"  {ok if tor_ok else no}  Tor routing       {'confirmed via check.torproject.org' if tor_ok else 'NOT routing — start Tor: sudo service tor start'}")
    print()

    # Test clearnet (RansomWatch / DarkSearch)
    try:
        import requests
        r = requests.get("https://darksearch.io/", timeout=8)
        clearnet_ok = r.status_code < 500
    except Exception:
        clearnet_ok = False
    print(f"  {ok if clearnet_ok else no}  Clearnet access   {'OK (DarkSearch, Pastebin, Telegram, RansomWatch)' if clearnet_ok else 'BLOCKED — check network/firewall'}")
    print("─────────────────────────────────────────────────────────\n")


# ── Pre-scored finding helper ─────────────────────────────────────────────────

def _prescore_to_finding(page: dict, org_profile: dict) -> Finding:
    """Convert a pre-confirmed result (HIBP / GitHub / RansomWatch) to a Finding."""
    return Finding(
        source=page.get("source", "unknown"),
        url=page.get("url", ""),
        category="credentials" if page.get("pre_severity") == "critical" else "documents",
        severity=page.get("pre_severity", "high"),
        matched_keyword=org_profile.get("name", ""),
        context=page.get("content", "")[:500],
        indicator=page.get("indicator", page.get("source", "unknown")),
    )


# ── Single monitoring cycle ───────────────────────────────────────────────────

def _run_source(label: str, fn, *args, **kwargs) -> list:
    """Call a source function; return [] and print a warning on any exception."""
    try:
        return fn(*args, **kwargs) or []
    except Exception as e:
        print(f"[!] {label} error: {e}")
        write_log(f"Source error [{label}]: {e}")
        return []


def run_cycle(config: dict = None) -> list:
    if config is None:
        config = load_profile()

    org_profile  = _build_org_profile(config)
    org_name     = org_profile["name"]
    monitoring   = config.get("monitoring", {})
    min_severity = monitoring.get("min_severity", "medium")
    max_pages    = monitoring.get("max_results_per_query", 10)

    hibp_key     = os.environ.get("HIBP_API_KEY", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    extra_tg     = config.get("telegram", {}).get("extra_channels", [])

    write_log(f"Cycle started — org: {org_name}")
    print(f"\n[*] Monitoring cycle for: \033[1m{org_name}\033[0m")
    print(f"[*] Min severity: {min_severity.upper()}  |  "
          f"HIBP: {'✓' if hibp_key else '○'}  "
          f"GitHub: {'✓' if github_token else '○'}  "
          f"Slack: {'✓' if os.environ.get('SLACK_WEBHOOK_URL') else '○'}")

    session = tor_session()

    if check_tor(session):
        print("[+] Tor routing confirmed.")
        write_log("Tor routing confirmed")
    else:
        print("[!] WARNING: Tor check failed — .onion sources will not work.")
        write_log("WARNING: Tor check failed")

    # ── Tier 1: Confirmed breach data (pre-scored) ────────────────────────────
    pre_scored = []

    print("\n[*] ── Tier 1: Confirmed breach sources ──")
    pre_scored += _run_source("HIBP",        check_hibp,       org_profile["email_domain"], hibp_key)
    pre_scored += _run_source("RansomWatch", scan_ransomwatch, org_profile["keywords"])
    pre_scored += _run_source("GitHub",      scan_github_code, org_profile["keywords"], github_token)

    # ── Tier 2: Pages to analyse with context-aware matching ─────────────────
    all_pages = []
    search_keywords = org_profile["keywords"][:5]

    print("\n[*] ── Tier 2: Dark web search engines ──")
    for kw in search_keywords:
        print(f"[*] Ahmia      → {kw}")
        results = _run_source("Ahmia",      search_ahmia,    kw, session)
        pages   = _run_source("Ahmia/fetch",fetch_result_pages, results, session,
                              max_pages=min(max_pages, 5))
        for p in pages:
            p["source"] = "ahmia"
        all_pages.extend(pages)

        print(f"[*] Torch      → {kw}")
        results = _run_source("Torch",      search_torch,    kw, session)
        pages   = _run_source("Torch/fetch",fetch_result_pages, results, session,
                              max_pages=min(max_pages, 3))
        for p in pages:
            p["source"] = "torch"
        all_pages.extend(pages)

        print(f"[*] Haystak    → {kw}")
        results = _run_source("Haystak",    search_haystak,  kw, session)
        pages   = _run_source("Haystak/fetch", fetch_result_pages, results, session,
                              max_pages=min(max_pages, 3))
        for p in pages:
            p["source"] = "haystak"
        all_pages.extend(pages)

        print(f"[*] DarkSearch → {kw}")
        ds = _run_source("DarkSearch", search_darksearch, kw)
        for r in ds[:5]:
            r["source"] = "darksearch"
        all_pages.extend(ds[:5])

    print("\n[*] ── Tier 2: Paste & leak sources ──")
    print("[*] Dark web paste sites (.onion)…")
    pastes_onion = _run_source("PasteOnion", scan_paste_sites,
                               org_profile["keywords"], session)
    for p in pastes_onion:
        p["source"] = "paste_onion"
    all_pages.extend(pastes_onion)

    print("[*] Clearnet paste sites (Pastebin, paste.ee)…")
    pastes_clear = _run_source("PasteClearnet", scan_pastebin_clearnet,
                               org_profile["keywords"])
    for p in pastes_clear:
        p["source"] = "paste_clearnet"
    all_pages.extend(pastes_clear)

    print("\n[*] ── Tier 2: Threat actor channels ──")
    print("[*] Telegram threat intel channels…")
    tg_hits = _run_source("Telegram", scan_telegram_channels,
                          org_profile["keywords"], extra_tg)
    for p in tg_hits:
        p["source"] = "telegram"
    all_pages.extend(tg_hits)

    print("\n[*] ── Tier 2: Ransomware blogs (.onion) ──")
    ransom_hits = _run_source("RansomBlogs", scan_ransomware_blogs,
                              org_profile["keywords"], session, _BLOGS_FILE)
    for p in ransom_hits:
        p["source"] = "ransomware_blogs"
    all_pages.extend(ransom_hits)

    # ── Analyse ───────────────────────────────────────────────────────────────
    print(f"\n[*] Analysing {len(all_pages)} page(s) + "
          f"{len(pre_scored)} pre-confirmed finding(s)…")

    candidate_findings = []
    for page in all_pages:
        try:
            findings = analyze_page(
                page.get("content", ""),
                page.get("url", ""),
                page.get("source", "unknown"),
                org_profile,
            )
            candidate_findings.extend(findings)
        except Exception as e:
            write_log(f"analyze_page error [{page.get('url','?')}]: {e}")

    for page in pre_scored:
        candidate_findings.append(_prescore_to_finding(page, org_profile))

    # ── Deduplicate + filter ──────────────────────────────────────────────────
    new_findings = []
    for f in candidate_findings:
        if _severity_rank(f.severity) < _severity_rank(min_severity):
            continue
        dedup_key = f"{f.url}|{f.indicator}|{f.matched_keyword}"
        if is_new("monitor", dedup_key):
            record("monitor", dedup_key, keyword=f.matched_keyword)
            new_findings.append(f)

    if new_findings:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        new_findings.sort(key=lambda f: sev_order.get(f.severity, 3))
        print(f"\n\033[91m[!] {len(new_findings)} NEW finding(s) detected.\033[0m")
        send_alert(org_name, new_findings)
    else:
        print("[+] No new findings this cycle — clean.")

    write_log(f"Cycle complete — {len(all_pages)} pages, "
              f"{len(pre_scored)} pre-scored, {len(new_findings)} new findings")
    return new_findings


# ── Continuous mode ───────────────────────────────────────────────────────────

def run_continuous(org_name: str = None, interval_hours: float = None,
                   config: dict = None) -> None:
    if config is None:
        config = load_profile()
    if org_name:
        config.setdefault("organization", {})["name"] = org_name

    interval = interval_hours or config.get("monitoring", {}).get("interval_hours", 6.0)

    print_banner()
    start_tor_service()

    org = config.get("organization", {}).get("name", "?")
    write_log(f"Continuous monitoring started — org: {org}, interval: {interval}h")
    print(f"[*] Continuous mode — every {interval}h")

    cycle = 0
    while True:
        cycle += 1
        print(f"\n{'─' * 62}")
        print(f"  Cycle #{cycle}   |   {org}")
        print(f"{'─' * 62}")
        try:
            run_cycle(config)
        except Exception as e:
            print(f"[!] Cycle #{cycle} failed with unexpected error: {e}")
            write_log(f"Cycle #{cycle} crash: {e}")
        print(f"\n[*] Sleeping {interval}h until next cycle…")
        time.sleep(interval * 3600)
