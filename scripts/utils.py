import os
from datetime import datetime

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console
    from rich.text import Text
    _RICH = True
except ImportError:
    _RICH = False

# Single log file per session, created on first write
_SESSION_LOG = None


def _session_log_path() -> str:
    global _SESSION_LOG
    if _SESSION_LOG is None:
        log_dir = os.path.join(_BASE, "logs")
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        _SESSION_LOG = os.path.join(log_dir, f"session_{ts}.log")
    return _SESSION_LOG


def write_log(message: str) -> None:
    with open(_session_log_path(), "a") as f:
        f.write(f"{datetime.now().isoformat()} — {message}\n")


def print_banner() -> None:
    os.system("clear")
    if _RICH:
        console = Console()
        banner = Text()
        banner.append("\n#########################################\n", style="bold white")
        banner.append("██     ██  ██████  ██████   ██████  ███████\n", style="bold red")
        banner.append("██     ██ ██    ██ ██   ██ ██    ██ ██     \n", style="bold yellow")
        banner.append("██  █  ██ ██    ██ ██   ██ ██    ██ █████  \n", style="bold green")
        banner.append("██ ███ ██ ██    ██ ██   ██ ██    ██ ██     \n", style="bold cyan")
        banner.append(" ███ ███   ██████  ██████   ██████  ███████\n", style="bold magenta")
        banner.append("#########################################\n", style="bold white")
        banner.append("    WODS — World of Dark Side\n", style="bold blue")
        banner.append("    Dark Web OSINT Monitor\n", style="bold white")
        console.print(banner)
    else:
        print("\n" + "=" * 50)
        print("  WODS — Dark Web OSINT Monitor")
        print("=" * 50 + "\n")


def generate_keywords(org_name: str) -> list:
    """Generate search keyword variants from an org name."""
    suffixes = [
        "credentials", "db dump", "leaked creds", "breach",
        "employee data", "source code", "vpn", "ssh key",
        "api key", "internal", "confidential",
    ]
    return [f"{org_name} {s}" for s in suffixes]
