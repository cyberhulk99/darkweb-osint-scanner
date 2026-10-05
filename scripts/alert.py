import os
import json
from datetime import datetime

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_LOG = os.path.join(_BASE, "data", "alerts.log")


def send_alert(org, findings):
    """
    Print a console alert and append to the alert log for every new finding.
    findings: dict of {tool_name: output_string}
    Set SLACK_WEBHOOK_URL env var to also push to a Slack channel.
    """
    os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*60}")
    print(f"  [!] NEW DARK WEB FINDINGS — {org}")
    print(f"      Time   : {timestamp}")
    print(f"      Sources: {', '.join(findings.keys())}")
    print(f"{'='*60}\n")

    with open(ALERT_LOG, "a") as f:
        f.write(f"\n[{timestamp}] NEW FINDINGS — {org}\n")
        for tool, output in findings.items():
            f.write(f"  Tool   : {tool}\n")
            f.write(f"  Snippet: {output[:500]}\n")
            f.write("  " + "-" * 40 + "\n")

    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if webhook:
        _slack(org, findings, webhook, timestamp)


def _slack(org, findings, webhook_url, timestamp):
    try:
        import urllib.request
        body = (
            f":rotating_light: *Dark Web Alert: {org}*\n"
            f"Time: {timestamp}\n"
            f"New findings from: {', '.join(findings.keys())}"
        )
        data = json.dumps({"text": body}).encode()
        req = urllib.request.Request(
            webhook_url, data=data, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)
        print("[+] Slack alert sent.")
    except Exception as e:
        print(f"[!] Slack alert failed: {e}")
