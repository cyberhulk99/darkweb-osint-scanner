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

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROFILE_PATH  = os.path.join(_BASE, "config", "org_profile.toml")
_BLOGS_FILE    = os.path.join(_BASE, "config", "ransomware_blogs.txt")


# ── Profile loading ──────────────────────────────────────────────────────────

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
    """Flatten config into the dict the analyzer expects."""
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

    raw_keywords = [name] + domains + subsidiaries + executives + extras + internal + buckets
    keywords = list(dict.fromkeys(k for k in raw_keywords if k))  # dedup, preserve order

    return {
        "name":         name,
        "email_domain": email_domain,
        "keywords":     keywords,
    }


# ── Single monitoring cycle ──────────────────────────────────────────────────

def _prescore_to_finding(page: dict, org_profile: dict) -> "Finding":
    """Convert a pre-scored page (from HIBP, GitHub, RansomWatch) to a Finding directly."""
    return Finding(
        source=page.get("source", "unknown"),
        url=page.get("url", ""),
        category="credentials" if page.get("pre_severity") == "critical" else "documents",
        severity=page.get("pre_severity", "high"),
        matched_keyword=org_profile.get("name", ""),
        context=page.get("content", "")[:500],
        indicator=page.get("indicator", page.get("source", "unknown")),
    )


def run_cycle(config: dict = None) -> list:
    if config is None:
        config = load_profile()

    org_profile  = _build_org_profile(config)
    org_name     = org_profile["name"]
    monitoring   = config.get("monitoring", {})
    min_severity = monitoring.get("min_severity", "medium")
    max_pages    = monitoring.get("max_results_per_query", 10)

    # Optional API integrations — loaded from environment, never from config file
    hibp_key     = os.environ.get("HIBP_API_KEY", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")

    write_log(f"Cycle started — org: {org_name}")
    print(f"\n[*] Monitoring cycle for: {org_name}")
    print(f"[*] Integrations: HIBP={'✓' if hibp_key else '✗ (set HIBP_API_KEY)'}  "
          f"GitHub={'✓' if github_token else '✗ (set GITHUB_TOKEN)'}")

    session = tor_session()

    if check_tor(session):
        print("[+] Tor routing confirmed.")
        write_log("Tor routing confirmed")
    else:
        print("[!] WARNING: traffic may not be routing through Tor — check the service.")
        write_log("WARNING: Tor check failed")

    # ── Tier 1: Confirmed breach databases (pre-scored, no analysis needed) ──
    # These are not "candidates" — a result here IS a finding.
    pre_scored: list[dict] = []

    print("[*] HaveIBeenPwned domain search…")
    pre_scored.extend(check_hibp(org_profile["email_domain"], hibp_key))

    print("[*] RansomWatch victim feed…")
    pre_scored.extend(scan_ransomwatch(org_profile["keywords"]))

    print("[*] GitHub public code search…")
    pre_scored.extend(scan_github_code(org_profile["keywords"], github_token))

    # ── Tier 2: Pages to analyse (context-aware scoring) ──────────────────────
    all_pages: list[dict] = []
    search_keywords = org_profile["keywords"][:5]

    # Dark web search engines (Tor)
    for kw in search_keywords:
        print(f"[*] Ahmia     → {kw}")
        results = search_ahmia(kw, session)
        pages   = fetch_result_pages(results, session, max_pages=min(max_pages, 5))
        for p in pages:
            p["source"] = "ahmia"
        all_pages.extend(pages)

        print(f"[*] Torch     → {kw}")
        results = search_torch(kw, session)
        pages   = fetch_result_pages(results, session, max_pages=min(max_pages, 3))
        for p in pages:
            p["source"] = "torch"
        all_pages.extend(pages)

        print(f"[*] Haystak   → {kw}")
        results = search_haystak(kw, session)
        pages   = fetch_result_pages(results, session, max_pages=min(max_pages, 3))
        for p in pages:
            p["source"] = "haystak"
        all_pages.extend(pages)

        print(f"[*] DarkSearch → {kw}")
        ds_results = search_darksearch(kw)
        for r in ds_results[:5]:
            r["source"] = "darksearch"
        all_pages.extend(ds_results[:5])

    # Paste sites
    print("[*] Dark web paste sites (.onion)…")
    paste_hits = scan_paste_sites(org_profile["keywords"], session)
    for p in paste_hits:
        p["source"] = "paste_onion"
    all_pages.extend(paste_hits)

    print("[*] Clearnet paste sites (Pastebin, paste.ee)…")
    clearnet_pastes = scan_pastebin_clearnet(org_profile["keywords"])
    for p in clearnet_pastes:
        p["source"] = "paste_clearnet"
    all_pages.extend(clearnet_pastes)

    # Telegram threat intel channels
    print("[*] Telegram threat intel channels…")
    extra_tg = config.get("telegram", {}).get("extra_channels", [])
    tg_hits = scan_telegram_channels(org_profile["keywords"], extra_channels=extra_tg)
    for p in tg_hits:
        p["source"] = "telegram"
    all_pages.extend(tg_hits)

    # Ransomware .onion blogs (manual list)
    print("[*] Ransomware blogs (.onion)…")
    ransom_hits = scan_ransomware_blogs(org_profile["keywords"], session, _BLOGS_FILE)
    for p in ransom_hits:
        p["source"] = "ransomware_blogs"
    all_pages.extend(ransom_hits)

    print(f"[*] Analysing {len(all_pages)} page(s) from {len(pre_scored)} pre-scored source(s)…")

    # ── Analyse pages ─────────────────────────────────────────────────────────
    candidate_findings: list[Finding] = []

    for page in all_pages:
        findings = analyze_page(
            page.get("content", ""),
            page.get("url", ""),
            page.get("source", "unknown"),
            org_profile,
        )
        candidate_findings.extend(findings)

    # Convert pre-scored items to Findings
    for page in pre_scored:
        candidate_findings.append(_prescore_to_finding(page, org_profile))

    # ── Filter + deduplicate ──────────────────────────────────────────────────
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
        print(f"\n[!] {len(new_findings)} NEW finding(s) detected.")
        send_alert(org_name, new_findings)
    else:
        print("[+] No new findings this cycle — all results already seen or below threshold.")

    write_log(f"Cycle complete — new findings: {len(new_findings)}")
    return new_findings


# ── Continuous mode ──────────────────────────────────────────────────────────

def run_continuous(org_name: str = None, interval_hours: float = None, config: dict = None) -> None:
    if config is None:
        config = load_profile()

    if org_name:
        config.setdefault("organization", {})["name"] = org_name

    interval = interval_hours or config.get("monitoring", {}).get("interval_hours", 6.0)

    print_banner()
    start_tor_service()

    write_log(f"Continuous monitoring started — org: {config['organization']['name']}, interval: {interval}h")
    print(f"[*] Continuous mode — every {interval}h")

    cycle = 0
    while True:
        cycle += 1
        org = config.get("organization", {}).get("name", "?")
        print(f"\n{'─'*60}")
        print(f"  Cycle #{cycle}   |   {org}")
        print(f"{'─'*60}")
        run_cycle(config)
        print(f"\n[*] Sleeping {interval}h until next cycle…")
        time.sleep(interval * 3600)
