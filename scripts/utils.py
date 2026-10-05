import os
from rich.console import Console
from rich.text import Text
from datetime import datetime

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

tool_entry_points = {
    "Katana": "kds.py",
    "OnionSearch": "main.py",
    "darkdump": "darkdump.py",
    "ahmia-site": None,
    "Darkus": None,
    "Onioff": "onioff.py",
    "docker-onion-nmap": None,
    "TorBot": "main.py",
    "TorCrawl.py": None,
    "VigilantOnion": None,
    "OnionIngestor": None,
    "Darc": None,
    "midnight_sea": None,
    "pryingdeep": None,
    "deepdarkCTI": None,
}

# Single log file per session, created on first write
_SESSION_LOG = None


def _session_log_path():
    global _SESSION_LOG
    if _SESSION_LOG is None:
        log_dir = os.path.join(_BASE, "logs")
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        _SESSION_LOG = os.path.join(log_dir, f"session_{ts}.log")
    return _SESSION_LOG


def print_banner():
    os.system("clear")
    console = Console()
    banner = Text()
    banner.append("\n#########################################\n", style="bold white")
    banner.append("██     ██  ██████  ██████   ██████  ███████\n", style="bold red")
    banner.append("██     ██ ██    ██ ██   ██ ██    ██ ██     \n", style="bold yellow")
    banner.append("██  █  ██ ██    ██ ██   ██ ██    ██ █████  \n", style="bold green")
    banner.append("██ ███ ██ ██    ██ ██   ██ ██    ██ ██     \n", style="bold cyan")
    banner.append(" ███ ███   ██████  ██████   ██████  ███████\n", style="bold magenta")
    banner.append("#########################################\n", style="bold white")
    banner.append("          Welcome to the World of Dark Side (WODS)\n", style="bold blue")
    banner.append("          Author: @Sumandas\n", style="bold white")
    console.print(banner)


def list_available_tools():
    return list(tool_entry_points)


def write_log(message):
    with open(_session_log_path(), "a") as f:
        f.write(f"{datetime.now().isoformat()} - {message}\n")


def generate_keywords(org_name):
    base_keywords = [
        "credentials", "confidential", "vpn", "admin panel", "email",
        "database", "db dump", "internal login", "source code",
        "employee data", "leaked creds", "ssh key", "jwt", "jira",
        "slack", "github", "zendesk", "production.db", "tokens",
    ]
    return [f"{org_name} {kw}" for kw in base_keywords]


def update_keywords_file(org_keywords):
    config_path = os.path.join(_BASE, "config", "keywords.txt")
    with open(config_path, "w") as f:
        for keyword in org_keywords:
            f.write(f"{keyword}\n")
