"""
SentinelX Linux Endpoint Agent
Collects auth.log, syslog, process creation, SSH events, bash history changes,
cron modifications, and network connections then ships to SentinelX collector API.

Run as root for full log access.
Requirements: pip install requests psutil
"""
import os
import sys
import re
import time
import json
import socket
import hashlib
import logging
import subprocess
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pathlib import Path

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

# ─────────────────────────── Configuration ───────────────────────────────────

SENTINEL_API_URL = os.environ.get("SENTINELX_API_URL", "http://localhost:8000/api/v1")
SENTINEL_TOKEN   = os.environ.get("SENTINELX_TOKEN", "")
BATCH_SIZE       = int(os.environ.get("SENTINELX_BATCH_SIZE", "50"))
POLL_INTERVAL    = int(os.environ.get("SENTINELX_POLL_INTERVAL", "30"))
LOG_FILE         = os.environ.get("SENTINELX_LOG_FILE", "/var/log/sentinelx-agent.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("sentinelx-linux-agent")

HOSTNAME = socket.gethostname()
try:
    LOCAL_IP = socket.gethostbyname(HOSTNAME)
except Exception:
    LOCAL_IP = "127.0.0.1"

# ─────────────────────────── Helpers ─────────────────────────────────────────

def get_auth_headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if SENTINEL_TOKEN:
        headers["Authorization"] = f"Bearer {SENTINEL_TOKEN}"
    return headers


def send_logs(logs: List[Dict]) -> bool:
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
            logger.info(f"✓ Sent {len(logs)} logs")
            return True
        logger.warning(f"API {resp.status_code}: {resp.text[:200]}")
        return False
    except Exception as e:
        logger.error(f"Send error: {e}")
        return False


def make_log(event_type: str, severity: str = "info", **kwargs) -> Dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": HOSTNAME,
        "source_ip": LOCAL_IP,
        "source": "linux",
        "event_type": event_type,
        "severity": severity,
        **kwargs
    }


# ─────────────────────────── Collectors ──────────────────────────────────────

class AuthLogCollector:
    """Parse /var/log/auth.log for authentication events."""

    LOG_FILES = ["/var/log/auth.log", "/var/log/secure"]
    SSH_FAIL_PATTERN = re.compile(r"Failed (password|publickey) for (\S+) from ([\d.]+)")
    SSH_SUCCESS_PATTERN = re.compile(r"Accepted (password|publickey) for (\S+) from ([\d.]+)")
    SUDO_PATTERN = re.compile(r"sudo:\s+(\S+)\s+:\s+.*COMMAND=(.*)")

    def __init__(self):
        self._file_positions: Dict[str, int] = {}

    def collect(self) -> List[Dict]:
        logs = []
        for log_file in self.LOG_FILES:
            if not os.path.exists(log_file):
                continue
            try:
                current_pos = self._file_positions.get(log_file, 0)
                with open(log_file, "r", errors="ignore") as f:
                    f.seek(current_pos)
                    new_lines = f.readlines()
                    self._file_positions[log_file] = f.tell()

                for line in new_lines[-BATCH_SIZE:]:
                    line = line.strip()
                    if not line:
                        continue

                    m = self.SSH_FAIL_PATTERN.search(line)
                    if m:
                        logs.append(make_log(
                            event_type="authentication_failure",
                            severity="medium",
                            user=m.group(2),
                            source_ip=m.group(3),
                            raw_log=line[:512]
                        ))
                        continue

                    m = self.SSH_SUCCESS_PATTERN.search(line)
                    if m:
                        logs.append(make_log(
                            event_type="authentication_success",
                            severity="info",
                            user=m.group(2),
                            source_ip=m.group(3),
                            raw_log=line[:512]
                        ))
                        continue

                    m = self.SUDO_PATTERN.search(line)
                    if m:
                        logs.append(make_log(
                            event_type="privilege_escalation",
                            severity="high",
                            user=m.group(1),
                            command=m.group(2)[:256],
                            raw_log=line[:512]
                        ))
            except Exception as e:
                logger.debug(f"Auth log error {log_file}: {e}")

        return logs


class SyslogCollector:
    """Parse /var/log/syslog for system events."""

    SUSPICIOUS_PATTERNS = [
        (re.compile(r"crontab", re.I), "cron_modification", "medium"),
        (re.compile(r"useradd|adduser|groupadd", re.I), "user_account_created", "high"),
        (re.compile(r"userdel|deluser", re.I), "user_deleted", "high"),
        (re.compile(r"passwd.*changed", re.I), "password_changed", "medium"),
        (re.compile(r"systemctl.*start|service.*start", re.I), "service_started", "info"),
    ]

    def __init__(self):
        self._file_pos = 0

    def collect(self) -> List[Dict]:
        logs = []
        syslog = "/var/log/syslog"
        if not os.path.exists(syslog):
            syslog = "/var/log/messages"
        if not os.path.exists(syslog):
            return logs

        try:
            with open(syslog, "r", errors="ignore") as f:
                f.seek(self._file_pos)
                lines = f.readlines()
                self._file_pos = f.tell()

            for line in lines[-BATCH_SIZE:]:
                line = line.strip()
                for pattern, event_type, severity in self.SUSPICIOUS_PATTERNS:
                    if pattern.search(line):
                        logs.append(make_log(
                            event_type=event_type,
                            severity=severity,
                            raw_log=line[:512]
                        ))
                        break
        except Exception as e:
            logger.debug(f"Syslog error: {e}")

        return logs


class ProcessMonitor:
    """Monitor processes for suspicious executables."""

    SUSPICIOUS_NAMES = {
        "nmap", "masscan", "metasploit", "msfconsole",
        "netcat", "nc", "socat", "hydra", "john", "hashcat",
        "tcpdump", "wireshark", "aircrack-ng", "ettercap"
    }

    def __init__(self):
        self._seen_pids: set = set()

    def collect(self) -> List[Dict]:
        logs = []
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
                try:
                    info = proc.info
                    pid = info["pid"]
                    if pid in self._seen_pids:
                        continue
                    self._seen_pids.add(pid)

                    name = (info["name"] or "").lower()
                    cmdline = " ".join(info["cmdline"] or [])

                    if any(s in name for s in self.SUSPICIOUS_NAMES):
                        logs.append(make_log(
                            event_type="process_creation",
                            severity="high",
                            process_name=info["name"],
                            command=cmdline[:512],
                            user=info.get("username"),
                            raw_log=f"Suspicious process: {name} (PID {pid})"
                        ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug(f"Process monitor error: {e}")
        return logs


class FileIntegrityMonitor:
    """Monitor critical files for unauthorized modifications."""

    WATCH_PATHS = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/crontab", "/etc/hosts", "/root/.bashrc",
        "/root/.bash_profile", "/etc/rc.local",
    ]

    def __init__(self):
        self._hashes: Dict[str, str] = {}
        # Initialize baseline
        for path in self.WATCH_PATHS:
            if os.path.exists(path):
                self._hashes[path] = self._hash_file(path)

    def _hash_file(self, path: str) -> str:
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""

    def collect(self) -> List[Dict]:
        logs = []
        for path in self.WATCH_PATHS:
            if not os.path.exists(path):
                continue
            current = self._hash_file(path)
            previous = self._hashes.get(path, "")
            if previous and current != previous:
                logs.append(make_log(
                    event_type="file_modification",
                    severity="critical",
                    file_path=path,
                    hash_value=current,
                    raw_log=f"Critical file modified: {path}"
                ))
            self._hashes[path] = current
        return logs


class NetworkConnectionMonitor:
    """Monitor active network connections for suspicious activity."""

    SUSPICIOUS_PORTS = {4444, 31337, 1337, 6667, 6666, 9001, 8888}

    def collect(self) -> List[Dict]:
        logs = []
        try:
            conns = psutil.net_connections(kind="inet")
            for conn in conns:
                if conn.status == "ESTABLISHED" and conn.raddr:
                    if conn.raddr.port in self.SUSPICIOUS_PORTS:
                        logs.append(make_log(
                            event_type="network_connection",
                            severity="high",
                            source_ip=conn.laddr.ip if conn.laddr else LOCAL_IP,
                            destination_ip=conn.raddr.ip,
                            raw_log=f"Suspicious outbound to {conn.raddr.ip}:{conn.raddr.port}"
                        ))
        except Exception as e:
            logger.debug(f"Network monitor error: {e}")
        return logs


# ─────────────────────────── Main Agent ──────────────────────────────────────

class SentinelXLinuxAgent:

    def __init__(self):
        self.collectors = [
            AuthLogCollector(),
            SyslogCollector(),
            ProcessMonitor(),
            FileIntegrityMonitor(),
            NetworkConnectionMonitor(),
        ]
        self.running = True

    def collect_all(self) -> List[Dict]:
        logs = []
        for collector in self.collectors:
            try:
                logs.extend(collector.collect())
            except Exception as e:
                logger.error(f"Collector {collector.__class__.__name__} error: {e}")
        return logs

    def run(self):
        logger.info(f"🛡️  SentinelX Linux Agent starting on {HOSTNAME} ({LOCAL_IP})")
        logger.info(f"   API: {SENTINEL_API_URL}")
        logger.info(f"   Poll: {POLL_INTERVAL}s | Batch: {BATCH_SIZE}")

        while self.running:
            try:
                logs = self.collect_all()
                if logs:
                    send_logs(logs)
                else:
                    logger.debug("No new events")
            except Exception as e:
                logger.error(f"Collection cycle error: {e}")
            time.sleep(POLL_INTERVAL)

    def stop(self):
        self.running = False


if __name__ == "__main__":
    agent = SentinelXLinuxAgent()
    try:
        agent.run()
    except KeyboardInterrupt:
        logger.info("Agent stopped")
        agent.stop()
