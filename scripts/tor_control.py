import socket
import subprocess


def _tor_is_listening() -> bool:
    """Check if something is already accepting connections on the Tor SOCKS port."""
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=3):
            return True
    except OSError:
        return False


def start_tor_service():
    print("[*] Checking Tor service...")

    if _tor_is_listening():
        print("[+] Tor is running on port 9050.")
        return

    # Try systemctl (modern Linux) then service (Debian/init.d)
    started = False
    for cmd in [
        ["systemctl", "start", "tor"],
        ["service",   "tor",   "start"],
    ]:
        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
            if _tor_is_listening():
                print("[+] Tor service started.")
                started = True
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except Exception:
            continue

    if not started:
        print("[!] Could not auto-start Tor.")
        print("[!] Start it manually:  sudo service tor start")
        print("[!] Continuing — scanner will report Tor check failure per cycle.")


def stop_tor_service():
    print("[*] Stopping Tor service...")
    try:
        subprocess.run(
            ["service", "tor", "stop"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        print("[+] Tor service stopped.")
    except Exception as e:
        print(f"[!] Failed to stop Tor: {e}")
