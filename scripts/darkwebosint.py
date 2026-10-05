import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import print_banner
from tor_control import start_tor_service

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WODS - World of Dark Side OSINT Scanner")
    parser.add_argument("-org", "--organization", help="Organization name to monitor")
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run in continuous monitoring mode (loops forever)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=6.0,
        metavar="HOURS",
        help="Hours between monitoring cycles in continuous mode (default: 6)",
    )
    args = parser.parse_args()

    org = (args.organization or input("🔍 Enter your organization name for OSINT: ")).strip()

    if args.continuous:
        from monitor import run_continuous
        run_continuous(org, interval_hours=args.interval)
    else:
        print_banner()
        start_tor_service()
        from monitor import run_cycle
        run_cycle(org)
