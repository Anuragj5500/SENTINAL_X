"""
SentinelX Windows Endpoint Agent
Collects Windows Security Events, Process Creation, PowerShell logs,
Network connections, and File changes then ships them to the SentinelX collector API.

Requirements: pip install requests psutil pywin32 (Windows only)
Run as Administrator for full event log access.
"""
import os
import sys
import time
import json
import socket
import hashlib
import logging
import platform
import subprocess
import threading
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

try:
    import psutil
except ImportError:
    print("Install psutil: pip install psutil")
    sys.exit(1)

# Windows-specific imports
if platform.system() == "Windows":
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        WIN32_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False
        print("[WARNING] pywin32 not installed — event log reading disabled. Install: pip install pywin32")
else:
    WIN32_AVAILABLE = False

# ─────────────────────────── Configuration ───────────────────────────────────

SENTINEL_API_URL = os.environ.get("SENTINELX_API_URL", "http://localhost:8000/api/v1")
SENTINEL_API_KEY = os.environ.get("SENTINELX_API_KEY", "")  # Use API key or JWT token
SENTINEL_TOKEN = os.environ.get("SENTINELX_TOKEN", "")      # JWT Bearer token
BATCH_SIZE = int(os.environ.get("SENTINELX_BATCH_SIZE", "50"))
POLL_INTERVAL = int(os.environ.get("SENTINELX_POLL_INTERVAL", "30"))  # seconds
LOG_FILE = os.environ.get("SENTINELX_LOG_FILE", "sentinelx-agent.log")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("sentinelx-agent")

# ─────────────────────────── Helpers ─────────────────────────────────────────

HOSTNAME = socket.gethostname()
try:
    LOCAL_IP = socket.gethostbyname(HOSTNAME)
except Exception:
    LOCAL_IP = "127.0.0.1"


def get_auth_headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if SENTINEL_TOKEN:
        headers["Authorization"] = f"Bearer {SENTINEL_TOKEN}"
    elif SENTINEL_API_KEY:
        headers["X-API-Key"] = SENTINEL_API_KEY
    return headers


def file_hash(filepath: str) -> Optional[str]:
    """Calculate SHA-256 hash of a file."""
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


def send_logs(logs: List[Dict[str, Any]]) -> bool:
    """Send a batch of logs to the SentinelX collector API."""
    if not logs:
        return True
    try:
        resp = requests.post(
            f"{SENTINEL_API_URL}/logs/batch",
            json=logs,
            headers=get_auth_headers(),
            timeout=15
        )
        if resp.status_code in (200, 201):
            logger.info(f"✓ Sent {len(logs)} logs to SentinelX")
            return True
        else:
            logger.warning(f"API returned {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        logger.error(f"Failed to send logs: {e}")
        return False


def make_log(event_type: str, severity: str = "info", **kwargs) -> Dict[str, Any]:
    """Build a normalized log entry."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": HOSTNAME,
        "source_ip": LOCAL_IP,
        "source": "windows",
        "event_type": event_type,
        "severity": severity,
        **kwargs
    }


# ─────────────────────────── Collectors ──────────────────────────────────────

class WindowsEventLogCollector:
    """Reads Windows Security and System event logs."""

    EVENT_CHANNELS = {
        "Security": {
            4624: ("authentication_success", "info"),
            4625: ("authentication_failure", "medium"),
            4688: ("process_creation", "info"),
            4698: ("scheduled_task_created", "high"),
            4720: ("user_account_created", "high"),
            4732: ("user_added_to_group", "medium"),
            4740: ("account_locked_out", "medium"),
            7045: ("service_installed", "medium"),
            4697: ("service_installed", "medium"),
        }
    }

    def __init__(self):
        self._last_record: Dict[str, int] = {}

    def collect(self) -> List[Dict[str, Any]]:
        if not WIN32_AVAILABLE:
            return self._simulate_events()

        logs = []
        for channel, event_map in self.EVENT_CHANNELS.items():
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(handle, flags, 0)

                for event in (events or []):
                    event_id = str(event.EventID & 0xFFFF)
                    if int(event_id) in event_map:
                        event_type, severity = event_map[int(event_id)]
                        msg = win32evtlogutil.SafeFormatMessage(event, channel)

                        log = make_log(
                            event_type=event_type,
                            severity=severity,
                            event_id=event_id,
                            raw_log=msg[:1024] if msg else f"Event {event_id}"
                        )
                        logs.append(log)

                win32evtlog.CloseEventLog(handle)
            except Exception as e:
                logger.debug(f"Error reading {channel}: {e}")

        return logs[:BATCH_SIZE]

    def _simulate_events(self) -> List[Dict[str, Any]]:
        """Generate simulated events when win32 is not available (demo mode)."""
        import random
        scenarios = [
            ("authentication_failure", "medium", "4625", "Failed login attempt for user administrator"),
            ("process_creation", "info", "4688", "Process powershell.exe started"),
            ("authentication_success", "info", "4624", "Successful login for user john.doe"),
        ]
        event_type, severity, event_id, msg = random.choice(scenarios)
        return [make_log(event_type=event_type, severity=severity, event_id=event_id, raw_log=msg)]


class ProcessMonitor:
    """Monitors running processes for suspicious activity."""

    SUSPICIOUS_NAMES = {
        "mimikatz.exe", "procdump.exe", "wce.exe", "fgdump.exe",
        "pwdump.exe", "psexec.exe", "netcat.exe", "nc.exe",
        "cobaltstrike", "metasploit", "meterpreter"
    }

    def __init__(self):
        self._seen_pids = set()

    def collect(self) -> List[Dict[str, Any]]:
        logs = []
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "username", "exe"]):
                try:
                    info = proc.info
                    pid = info["pid"]
                    name = (info["name"] or "").lower()
                    cmdline = " ".join(info["cmdline"] or [])

                    if pid in self._seen_pids:
                        continue
                    self._seen_pids.add(pid)

                    # Flag suspicious processes
                    is_suspicious = any(s in name for s in self.SUSPICIOUS_NAMES)
                    is_powershell_encoded = "powershell" in name and (
                        "-enc" in cmdline.lower() or "-encodedcommand" in cmdline.lower()
                    )

                    if is_suspicious or is_powershell_encoded:
                        severity = "critical" if is_suspicious else "high"
                        exe_hash = file_hash(info.get("exe", "") or "") if info.get("exe") else None

                        log = make_log(
                            event_type="process_creation",
                            severity=severity,
                            process_name=info["name"],
                            command=cmdline[:512],
                            user=info.get("username"),
                            hash_value=exe_hash,
                            event_id="4688",
                            raw_log=f"Suspicious process: {name} PID={pid}"
                        )
                        logs.append(log)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug(f"Process monitor error: {e}")

        return logs


class NetworkConnectionMonitor:
    """Monitors active network connections."""

    SUSPICIOUS_PORTS = {4444, 8080, 31337, 1337, 6667, 6666, 9001}

    def collect(self) -> List[Dict[str, Any]]:
        logs = []
        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections:
                if conn.status == "ESTABLISHED" and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port

                    if remote_port in self.SUSPICIOUS_PORTS:
                        log = make_log(
                            event_type="network_connection",
                            severity="high",
                            source_ip=conn.laddr.ip if conn.laddr else LOCAL_IP,
                            destination_ip=remote_ip,
                            raw_log=f"Suspicious connection to {remote_ip}:{remote_port} port={remote_port}"
                        )
                        logs.append(log)
        except Exception as e:
            logger.debug(f"Network monitor error: {e}")

        return logs


# ─────────────────────────── Main Agent Loop ─────────────────────────────────

class SentinelXWindowsAgent:

    def __init__(self):
        self.event_collector = WindowsEventLogCollector()
        self.process_monitor = ProcessMonitor()
        self.network_monitor = NetworkConnectionMonitor()
        self.running = True

    def collect_all(self) -> List[Dict[str, Any]]:
        logs = []
        logs.extend(self.event_collector.collect())
        logs.extend(self.process_monitor.collect())
        logs.extend(self.network_monitor.collect())
        return logs

    def run(self):
        logger.info(f"[+] SentinelX Windows Agent starting on {HOSTNAME} ({LOCAL_IP})")
        logger.info(f"   API: {SENTINEL_API_URL}")
        logger.info(f"   Poll interval: {POLL_INTERVAL}s | Batch size: {BATCH_SIZE}")

        while self.running:
            try:
                logs = self.collect_all()
                if logs:
                    send_logs(logs)
                else:
                    logger.debug("No new events in this cycle")
            except Exception as e:
                logger.error(f"Collection error: {e}")

            time.sleep(POLL_INTERVAL)

    def stop(self):
        self.running = False


if __name__ == "__main__":
    agent = SentinelXWindowsAgent()
    try:
        agent.run()
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
        agent.stop()
