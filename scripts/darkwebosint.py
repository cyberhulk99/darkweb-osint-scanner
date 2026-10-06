import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="WODS — Dark Web OSINT Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # One-shot scan using org_profile.toml
  python3 darkwebosint.py

  # Quick setup check (no scanning)
  python3 darkwebosint.py --check

  # Continuous monitoring (interval from profile, default 6h)
  python3 darkwebosint.py --continuous

  # Override org name and interval
  python3 darkwebosint.py -org "Acme Corp" --continuous --interval 2

  # Use a custom profile file
  python3 darkwebosint.py --profile /path/to/my_profile.toml --continuous
        """,
    )
    parser.add_argument("-org", "--organization",
                        help="Override organization name from profile")
    parser.add_argument("--profile",
                        help="Path to org_profile.toml (default: config/org_profile.toml)")
    parser.add_argument("--continuous", action="store_true",
                        help="Run continuously on a schedule")
    parser.add_argument("--interval", type=float, metavar="HOURS",
                        help="Override monitoring interval in hours")
    parser.add_argument("--check", action="store_true",
                        help="Verify setup (Tor, config, API keys) without scanning")
    args = parser.parse_args()

    from monitor import load_profile, run_cycle, run_continuous, check_setup
    from utils import print_banner
    from tor_control import start_tor_service

    config = load_profile(args.profile) if args.profile else load_profile()

    if args.organization:
        config.setdefault("organization", {})["name"] = args.organization

    if args.check:
        print_banner()
        check_setup(config)
        sys.exit(0)

    if not config.get("organization", {}).get("name"):
        name = input("Enter your organisation name: ").strip()
        config.setdefault("organization", {})["name"] = name

    if args.interval:
        config.setdefault("monitoring", {})["interval_hours"] = args.interval

    if args.continuous:
        run_continuous(config=config)
    else:
        print_banner()
        start_tor_service()
        run_cycle(config)
