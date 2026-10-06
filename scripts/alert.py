import os
import json
from datetime import datetime

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_LOG = os.path.join(_BASE, "data", "alerts.log")

_SEV_COLOR = {
    'critical': '\033[91m',   # red
    'high':     '\033[93m',   # yellow
    'medium':   '\033[94m',   # blue
    'low':      '\033[97m',   # white
}
_RESET = '\033[0m'
_BOLD  = '\033[1m'

_SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
_SEV_EMOJI = {
    'critical': ':red_circle:',
    'high':     ':large_orange_circle:',
    'medium':   ':large_yellow_circle:',
    'low':      ':white_circle:',
}


def send_alert(org: str, findings: list) -> None:
    """
    Print a colour-coded console summary and append to the persistent alert log.
    Set SLACK_WEBHOOK_URL env var to also push to Slack.
    findings: list of Finding objects (from analyzer.py)
    """
    os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sorted_findings = sorted(findings, key=lambda f: _SEV_ORDER.get(
        getattr(f, 'severity', 'low'), 3
    ))

    # ── Console output ───────────────────────────────────────────────────────
    print(f"\n{_BOLD}{'═'*62}{_RESET}")
    print(f"{_BOLD}  DARK WEB ALERT  —  {org}{_RESET}")
    print(f"  {timestamp}   |   {len(findings)} new finding(s)")
    print(f"{_BOLD}{'═'*62}{_RESET}")

    for f in sorted_findings:
        sev = getattr(f, 'severity', 'low')
        color = _SEV_COLOR.get(sev, '')
        print(f"\n  {color}{_BOLD}[{sev.upper()}]{_RESET}  {getattr(f, 'indicator', '')}")
        print(f"    Category : {getattr(f, 'category', '-')}")
        print(f"    Source   : {getattr(f, 'source', '-')}")
        print(f"    URL      : {getattr(f, 'url', '-')}")
        print(f"    Keyword  : {getattr(f, 'matched_keyword', '-')}")
        ctx = getattr(f, 'context', '')[:200]
        print(f"    Context  : {ctx}…")

    print(f"\n{_BOLD}{'═'*62}{_RESET}\n")

    # ── Persist to log ───────────────────────────────────────────────────────
    with open(ALERT_LOG, "a") as log:
        log.write(f"\n[{timestamp}]  ALERT — {org}  ({len(findings)} finding(s))\n")
        for f in sorted_findings:
            sev = getattr(f, 'severity', 'low')
            log.write(f"  [{sev.upper()}]  {getattr(f, 'indicator', '')}  |  "
                      f"{getattr(f, 'source', '-')}  |  {getattr(f, 'url', '-')}\n")
            log.write(f"  Keyword : {getattr(f, 'matched_keyword', '-')}\n")
            log.write(f"  Context : {getattr(f, 'context', '')[:300]}\n")
            log.write("  " + "─" * 50 + "\n")

    # ── Optional Slack alert ─────────────────────────────────────────────────
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if webhook:
        _slack(org, sorted_findings, webhook, timestamp)


def _slack(org: str, findings: list, webhook_url: str, timestamp: str) -> None:
    try:
        import urllib.request
        lines = [f"*{_BOLD}Dark Web Alert — {org}*   {timestamp}"]
        for f in findings[:10]:
            sev = getattr(f, 'severity', 'low')
            emoji = _SEV_EMOJI.get(sev, ':white_circle:')
            lines.append(
                f"{emoji} *{sev.upper()}* — "
                f"{getattr(f, 'indicator', '')}  ({getattr(f, 'source', '-')})"
            )
        if len(findings) > 10:
            lines.append(f"…and {len(findings) - 10} more. Check data/alerts.log")
        payload = json.dumps({"text": "\n".join(lines)}).encode()
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)
        print("[+] Slack alert sent.")
    except Exception as e:
        print(f"[!] Slack alert failed: {e}")
