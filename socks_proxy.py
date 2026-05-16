"""OrbWall SOCKS5 filter addon.

Hooks into asyncio-socks-server via the Addon API. On every CONNECT, we
consult the allow/block lists; allowed flows pass through to the server's
default direct-connect path, blocked or unknown flows raise to reject.
"""

import os
import queue
import threading
import time
from pathlib import Path

from asyncio_socks_server import Addon


CONFIG_DIR = Path(os.path.expanduser("~/.orbwall"))
ALLOWLIST_PATH = CONFIG_DIR / "allowlist.txt"
BLOCKLIST_PATH = CONFIG_DIR / "blocklist.txt"


def _read_set(path: Path) -> set:
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text().splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.add(s.lower())
    return out


def _write_set(path: Path, items: set) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(items)) + "\n")


def _matches(domain: str, pat: str) -> bool:
    if domain == pat:
        return True
    if pat.startswith("*.") and (domain == pat[2:] or domain.endswith(pat[1:])):
        return True
    return False


class OrbWallFilter(Addon):
    """SOCKS5 server addon implementing domain allow/block/prompt."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self.allowlist = _read_set(ALLOWLIST_PATH)
        self.blocklist = _read_set(BLOCKLIST_PATH)
        self.pending: "queue.Queue[str]" = queue.Queue()
        self._pending_seen: set = set()
        self.paused = False
        self.allowed_count = 0
        self.blocked_count = 0
        self.recent: list = []

    # ---------- list logic ----------

    def check_domain(self, domain: str) -> str:
        d = domain.lower()
        with self._lock:
            if self.paused:
                return "allow"
            for pat in self.blocklist:
                if _matches(d, pat):
                    return "block"
            for pat in self.allowlist:
                if _matches(d, pat):
                    return "allow"
        return "unknown"

    def allow_domain(self, domain: str) -> None:
        d = domain.lower()
        with self._lock:
            self.allowlist.add(d)
            self.blocklist.discard(d)
            _write_set(ALLOWLIST_PATH, self.allowlist)
            _write_set(BLOCKLIST_PATH, self.blocklist)
            self._pending_seen.discard(d)

    def block_domain(self, domain: str) -> None:
        d = domain.lower()
        with self._lock:
            self.blocklist.add(d)
            self.allowlist.discard(d)
            _write_set(ALLOWLIST_PATH, self.allowlist)
            _write_set(BLOCKLIST_PATH, self.blocklist)
            self._pending_seen.discard(d)

    def reload_lists(self) -> None:
        with self._lock:
            self.allowlist = _read_set(ALLOWLIST_PATH)
            self.blocklist = _read_set(BLOCKLIST_PATH)

    def set_paused(self, paused: bool) -> None:
        with self._lock:
            self.paused = paused

    def pending_snapshot(self) -> list:
        with self._lock:
            return sorted(self._pending_seen)

    def _record(self, domain: str, action: str) -> None:
        with self._lock:
            self.recent.append((time.time(), domain, action))
            del self.recent[:-200]
            if action == "allow":
                self.allowed_count += 1
            elif action == "block":
                self.blocked_count += 1

    def _enqueue_pending(self, domain: str) -> None:
        d = domain.lower()
        with self._lock:
            if d in self._pending_seen:
                return
            self._pending_seen.add(d)
        self.pending.put(d)

    # ---------- addon hook ----------

    async def on_connect(self, flow):
        host = str(flow.dst.host)
        verdict = self.check_domain(host)
        if verdict == "allow":
            self._record(host, "allow")
            return None  # abstain → server does direct connect
        if verdict == "block":
            self._record(host, "block")
            raise ConnectionRefusedError(f"blocked by OrbWall: {host}")
        self._record(host, "unknown")
        self._enqueue_pending(host)
        raise ConnectionRefusedError(f"unknown to OrbWall: {host}")
