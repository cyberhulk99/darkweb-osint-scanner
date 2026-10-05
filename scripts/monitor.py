import time
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import write_log, print_banner
from tor_control import start_tor_service
from result_store import is_new, record
from alert import send_alert
from analyzer import analyze_page, _severity_rank
from scanner import (
    tor_session, check_tor,
    search_ahmia, search_torch, search_haystak,
    fetch_result_pages,
    scan_paste_sites,
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

def run_cycle(config: dict = None) -> list:
    if config is None:
        config = load_profile()

    org_profile  = _build_org_profile(config)
    org_name     = org_profile["name"]
    monitoring   = config.get("monitoring", {})
    min_severity = monitoring.get("min_severity", "medium")
    max_pages    = monitoring.get("max_results_per_query", 10)

    write_log(f"Cycle started — org: {org_name}")
    print(f"\n[*] Monitoring cycle for: {org_name}")

    session = tor_session()

    # Verify Tor
    if check_tor(session):
        print("[+] Tor routing confirmed.")
        write_log("Tor routing confirmed")
    else:
        print("[!] WARNING: traffic may not be routing through Tor — check the service.")
        write_log("WARNING: Tor check failed")

    # ── Collect pages from all sources ──────────────────────────────────────
    all_pages: list[dict] = []

    # Use only the top keywords to respect rate limits
    search_keywords = org_profile["keywords"][:5]

    for kw in search_keywords:
        print(f"[*] Ahmia  → {kw}")
        results = search_ahmia(kw, session)
        pages   = fetch_result_pages(results, session, max_pages=min(max_pages, 5))
        for p in pages:
            p["source"] = "ahmia"
        all_pages.extend(pages)

        print(f"[*] Torch  → {kw}")
        results = search_torch(kw, session)
        pages   = fetch_result_pages(results, session, max_pages=min(max_pages, 3))
        for p in pages:
            p["source"] = "torch"
        all_pages.extend(pages)

        print(f"[*] Haystak → {kw}")
        results = search_haystak(kw, session)
        pages   = fetch_result_pages(results, session, max_pages=min(max_pages, 3))
        for p in pages:
            p["source"] = "haystak"
        all_pages.extend(pages)

    print("[*] Scanning paste sites…")
    paste_hits = scan_paste_sites(org_profile["keywords"], session)
    for p in paste_hits:
        p["source"] = "paste_sites"
    all_pages.extend(paste_hits)

    print("[*] Checking ransomware blogs…")
    ransom_hits = scan_ransomware_blogs(org_profile["keywords"], session, _BLOGS_FILE)
    for p in ransom_hits:
        p["source"] = "ransomware_blogs"
    all_pages.extend(ransom_hits)

    print(f"[*] Analysing {len(all_pages)} page(s)…")

    # ── Analyse and deduplicate ──────────────────────────────────────────────
    new_findings = []
    for page in all_pages:
        findings = analyze_page(
            page.get("content", ""),
            page.get("url", ""),
            page.get("source", "unknown"),
            org_profile,
        )
        for f in findings:
            if _severity_rank(f.severity) < _severity_rank(min_severity):
                continue
            # Dedup key: URL + indicator + matched keyword
            dedup_key = f"{f.url}|{f.indicator}|{f.matched_keyword}"
            if is_new("monitor", dedup_key):
                record("monitor", dedup_key, keyword=f.matched_keyword)
                new_findings.append(f)

    if new_findings:
        # Sort highest severity first for the alert
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
