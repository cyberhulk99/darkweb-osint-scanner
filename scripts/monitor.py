import time
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import generate_keywords, update_keywords_file, write_log, print_banner
from runner import run_all_tools
from tor_control import start_tor_service
from result_store import is_new, record
from alert import send_alert


def run_cycle(org):
    write_log(f"Monitoring cycle started for: {org}")
    print(f"\n[*] Running monitoring cycle for: {org}")

    keywords = generate_keywords(org)
    update_keywords_file(keywords)

    results = run_all_tools(keywords=keywords)

    new_findings = {}
    for tool, output in results.items():
        if output and output.strip() and is_new(tool, output):
            record(tool, output, keyword=org)
            new_findings[tool] = output
        elif output and output.strip():
            print(f"[=] {tool}: output unchanged since last run, skipping.")

    if new_findings:
        print(f"[!] {len(new_findings)} tool(s) returned NEW data.")
        send_alert(org, new_findings)
    else:
        print("[+] No new findings this cycle.")

    write_log(f"Cycle complete — new findings: {len(new_findings)}")


def run_continuous(org, interval_hours=6.0):
    print_banner()
    start_tor_service()

    print(f"[*] Continuous monitoring mode — interval: {interval_hours}h")
    write_log(f"Continuous monitoring started for '{org}' every {interval_hours}h")

    cycle = 0
    while True:
        cycle += 1
        print(f"\n{'─'*50}")
        print(f"  Cycle #{cycle}  |  org: {org}")
        print(f"{'─'*50}")
        run_cycle(org)
        print(f"\n[*] Sleeping {interval_hours}h until next cycle…")
        time.sleep(interval_hours * 3600)
