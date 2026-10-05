import os
import subprocess
from utils import tool_entry_points, write_log

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(_BASE, "tools")
TOOL_TIMEOUT = 300  # seconds per tool


def _build_cmd(tool_name, entry_path, keywords=None):
    name = tool_name.lower()
    if name == "katana":
        return ["python3", entry_path, "-t"]
    elif name == "darkdump":
        cmd = ["python3", entry_path]
        if keywords:
            cmd += ["--query", keywords[0]]
        return cmd
    elif name == "onionsearch":
        cmd = ["python3", entry_path]
        if keywords:
            cmd += [keywords[0]]
        return cmd
    elif name == "onioff":
        return ["python3", entry_path]
    elif name == "torbot":
        return ["python3", entry_path, "--help"]
    else:
        return ["python3", entry_path]


def run_tool(tool_name, entry_script, keywords=None):
    """Run a single tool and return its combined stdout+stderr, or None on failure."""
    tool_path = os.path.join(TOOLS_DIR, tool_name)

    if not os.path.exists(tool_path):
        print(f"[!] {tool_name} not found in tools/. Skipping.")
        write_log(f"Skipped {tool_name}: directory not found")
        return None

    if not entry_script:
        print(f"[-] No entry point for {tool_name}. Skipping.")
        write_log(f"Skipped {tool_name}: no entry point defined")
        return None

    entry_path = os.path.join(tool_path, entry_script)
    print(f"[*] Running {tool_name}…")
    write_log(f"Running {tool_name} ({entry_script})")

    try:
        cmd = _build_cmd(tool_name, entry_path, keywords)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            cwd=tool_path,
        )
        output = (result.stdout + result.stderr).strip()
        write_log(f"Finished {tool_name} (exit {result.returncode}, {len(output)} chars)")
        return output or None
    except subprocess.TimeoutExpired:
        print(f"[!] {tool_name} timed out after {TOOL_TIMEOUT}s.")
        write_log(f"Timeout running {tool_name}")
        return None
    except Exception as e:
        print(f"[!] Error running {tool_name}: {e}")
        write_log(f"Error running {tool_name}: {e}")
        return None


def run_all_tools(keywords=None):
    """Run every configured tool and return {tool_name: output} for tools that produced output."""
    print("[*] Running all tools…")
    results = {}
    for tool, entry in tool_entry_points.items():
        output = run_tool(tool, entry, keywords=keywords)
        if output:
            results[tool] = output
    return results
