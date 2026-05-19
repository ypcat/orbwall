# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "rumps",
#     "asyncio-socks-server",
# ]
# ///
"""OrbWall — domain-level firewall for OrbStack VMs.

Run with:  uv run orbwall.py [--port PORT]
Or one-liner:  uv run https://raw.githubusercontent.com/ypcat/orbwall/main/orbwall.py
"""

import argparse
import atexit
import ctypes
import fcntl
import os
import queue
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import rumps
from asyncio_socks_server import Addon, Server


# ── paths & constants ────────────────────────────────────────────────────────

CONFIG_DIR = Path(os.path.expanduser("~/.orbwall"))
ALLOWLIST_PATH = CONFIG_DIR / "allowlist.txt"
BLOCKLIST_PATH = CONFIG_DIR / "blocklist.txt"

ICON = "🔒"

DEFAULT_ALLOWLIST_TEXT = """\
# OrbWall default allowlist. One domain per line. Wildcards: *.example.com
api.anthropic.com
statsig.anthropic.com
sentry.io
*.sentry.io
registry.npmjs.org
*.npmjs.org
pypi.org
files.pythonhosted.org
*.pythonhosted.org
github.com
*.github.com
*.githubusercontent.com
"""


# ── list helpers ─────────────────────────────────────────────────────────────

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
    return domain == pat or (
        pat.startswith("*.") and (domain == pat[2:] or domain.endswith(pat[1:]))
    )


def init_config() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not ALLOWLIST_PATH.exists():
        ALLOWLIST_PATH.write_text(DEFAULT_ALLOWLIST_TEXT)
    if not BLOCKLIST_PATH.exists():
        BLOCKLIST_PATH.write_text("")


def parent_domain(domain: str) -> str:
    parts = domain.lower().split(".")
    if len(parts) <= 2:
        return domain.lower()
    two_label_tlds = {"co.uk", "ac.uk", "org.uk", "com.au", "co.jp", "co.kr"}
    if ".".join(parts[-2:]) in two_label_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ── port + orb helpers ───────────────────────────────────────────────────────

def find_free_port(start: int, count: int = 20) -> int:
    for p in range(start, start + count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", p))
                return p
        except OSError:
            continue
    raise RuntimeError(f"no free TCP port in {start}..{start+count-1}")


def _orb_available() -> bool:
    return shutil.which("orb") is not None


def orb_get_proxy() -> str | None:
    if not _orb_available():
        return None
    try:
        r = subprocess.run(
            ["orb", "config", "get", "network_proxy"],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def orb_set_proxy(value: str) -> bool:
    if not _orb_available():
        return False
    try:
        r = subprocess.run(
            ["orb", "config", "set", "network_proxy", value],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


# ── filter addon ─────────────────────────────────────────────────────────────

class OrbWallFilter(Addon):
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

    def check_domain(self, domain: str) -> str:
        d = domain.lower()
        with self._lock:
            if self.paused:
                return "allow"
            if any(_matches(d, p) for p in self.blocklist):
                return "block"
            if any(_matches(d, p) for p in self.allowlist):
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

    async def on_connect(self, flow):
        host = str(flow.dst.host)
        verdict = self.check_domain(host)
        if verdict == "allow":
            self._record(host, "allow")
            return None  # abstain → server proxies directly
        if verdict == "block":
            self._record(host, "block")
            raise ConnectionRefusedError(f"blocked: {host}")
        self._record(host, "unknown")
        self._enqueue_pending(host)
        raise ConnectionRefusedError(f"unknown: {host}")


# ── menu bar app ─────────────────────────────────────────────────────────────

class OrbWallApp(rumps.App):
    def __init__(self, preferred_port: int) -> None:
        super().__init__("OrbWall", title=ICON, quit_button=None)
        init_config()

        self._proxy_host = "127.0.0.1"
        self._proxy_port = find_free_port(preferred_port)
        self._proxy_url = f"socks5://{self._proxy_host}:{self._proxy_port}"

        # Proxy revert state
        self._original_orb_proxy: str | None = None
        self._we_set_orb = False

        self.filter = OrbWallFilter()
        self.server = Server(
            host=self._proxy_host, port=self._proxy_port,
            addons=[self.filter], log_level="WARNING",
        )
        # Server.run() installs signal handlers on the asyncio loop, which
        # only works from the main thread. rumps owns main.
        self.server._install_signal_handlers = lambda: None

        self.status_item = rumps.MenuItem("Status: starting…")
        # callback=lambda _: None enables the item; without it rumps grays it out
        self.pending_menu = rumps.MenuItem("Pending (0)", callback=lambda _: None)
        self.recent_menu = rumps.MenuItem("Recent", callback=lambda _: None)
        self.allowed_menu = rumps.MenuItem("Allowed Domains", callback=lambda _: None)
        self.blocked_menu = rumps.MenuItem("Blocked Domains", callback=lambda _: None)
        self.pause_item = rumps.MenuItem("Pause Filtering", callback=self.toggle_pause)
        self.edit_allow_item = rumps.MenuItem("Edit Allowlist", callback=self.edit_allowlist)
        self.edit_block_item = rumps.MenuItem("Edit Blocklist", callback=self.edit_blocklist)
        self.reload_item = rumps.MenuItem("Reload Lists", callback=self.reload_lists)
        self.configure_orb_item = rumps.MenuItem("Configure OrbStack", callback=self.configure_orb)
        self.quit_item = rumps.MenuItem("Quit", callback=rumps.quit_application)

        self.menu = [
            self.status_item,
            None,
            self.pending_menu,
            self.recent_menu,
            None,
            self.allowed_menu,
            self.blocked_menu,
            None,
            self.pause_item,
            self.edit_allow_item,
            self.edit_block_item,
            self.reload_item,
            None,
            self.configure_orb_item,
            None,
            self.quit_item,
        ]

        print(f"OrbWall listening on {self._proxy_url}", flush=True)

        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

        self._alert_lock = threading.Lock()
        self._showing_alert = False

        self._timers = [
            rumps.Timer(self.check_pending, 0.5),
            rumps.Timer(self.refresh_ui, 2.0),
        ]
        for t in self._timers:
            t.start()

        # One-shot bootstrap: ask to configure OrbStack once the run loop is up.
        self._bootstrap_timer = rumps.Timer(self._bootstrap, 0.3)
        self._bootstrap_timer.start()

        atexit.register(self.shutdown)

    @staticmethod
    def _safe_clear(mi) -> None:
        if getattr(mi, "_menu", None) is not None:
            mi.clear()

    @staticmethod
    def _ensure_enabled(mi) -> None:
        """Force-enable a submenu parent item and disable auto-validation on its submenu."""
        try:
            mi._menuitem.setEnabled_(True)
        except Exception:
            pass
        if getattr(mi, "_menu", None) is not None:
            try:
                mi._menu.setAutoenablesItems_(False)
            except Exception:
                pass

    def _run_server(self) -> None:
        try:
            self.server.run()
        except Exception as e:
            print(f"OrbWall proxy error: {e}", file=sys.stderr, flush=True)

    # ── bootstrap & shutdown ─────────────────────────────────────────────────

    def _bootstrap(self, sender) -> None:
        sender.stop()

        # _nsapp is only available after run() → set icon + menu state here.
        try:
            from AppKit import NSImage
            img = NSImage.imageWithSystemSymbolName_accessibilityDescription_("lock.fill", None)
            if img:
                img.setTemplate_(True)
                self._nsapp.nsstatusitem.setImage_(img)
                self._nsapp.nsstatusitem.setTitle_("")
        except Exception as e:
            print(f"SF Symbol icon setup failed: {e}", file=sys.stderr, flush=True)

        # Disable macOS responder-chain auto-validation, which grays items in LSUIElement apps.
        try:
            self._nsapp.nsstatusitem.menu().setAutoenablesItems_(False)
        except Exception as e:
            print(f"setAutoenablesItems_ failed: {e}", file=sys.stderr, flush=True)

        for mi in [self.pending_menu, self.recent_menu, self.allowed_menu, self.blocked_menu]:
            self._ensure_enabled(mi)

        if not _orb_available():
            print("orb CLI not found — skipping auto-configuration.", flush=True)
            return
        self._maybe_configure_orb(initial=True)

    def _maybe_configure_orb(self, initial: bool = False) -> None:
        current = orb_get_proxy()
        if current is None:
            rumps.alert(
                title="OrbWall",
                message="Could not read `orb config get network_proxy`. "
                        "Is OrbStack installed?",
                ok="OK",
            )
            return
        if current == self._proxy_url:
            if not initial:
                rumps.alert(
                    title="OrbWall",
                    message=f"OrbStack is already pointing at {self._proxy_url}.",
                    ok="OK",
                )
            return

        response = rumps.alert(
            title="OrbWall: configure OrbStack?",
            message=(
                f"OrbStack network_proxy is currently:\n    {current}\n\n"
                f"Set it to:\n    {self._proxy_url}\n\n"
                f"OrbWall will restore the original value on quit."
            ),
            ok="Set",
            cancel="Skip",
        )
        if response == 1 and orb_set_proxy(self._proxy_url):
            self._original_orb_proxy = current
            self._we_set_orb = True
            print(f"orb network_proxy: {current} → {self._proxy_url}", flush=True)

    def shutdown(self) -> None:
        if self._we_set_orb and self._original_orb_proxy is not None:
            ok = orb_set_proxy(self._original_orb_proxy)
            print(
                f"orb network_proxy restored to {self._original_orb_proxy}"
                if ok else
                f"failed to restore orb network_proxy to {self._original_orb_proxy}",
                flush=True,
            )
            self._we_set_orb = False

    # ── timers ───────────────────────────────────────────────────────────────

    def check_pending(self, _) -> None:
        if self._showing_alert:
            return
        try:
            domain = self.filter.pending.get_nowait()
        except Exception:
            return
        with self._alert_lock:
            self._showing_alert = True
        try:
            self.show_domain_alert(domain)
        finally:
            with self._alert_lock:
                self._showing_alert = False

    def refresh_ui(self, _) -> None:
        pending_items = self.filter.pending_snapshot()

        paused = self.filter.paused
        self.status_item.title = (
            f"Status: {'Paused (allow all)' if paused else 'Active'} "
            f"@ :{self._proxy_port} "
            f"(✓ {self.filter.allowed_count} · ✗ {self.filter.blocked_count})"
        )
        self.pause_item.title = "Resume Filtering" if paused else "Pause Filtering"

        self.pending_menu.title = f"Pending ({len(pending_items)})"
        self._safe_clear(self.pending_menu)
        for d in pending_items:
            self.pending_menu.add(
                rumps.MenuItem(d, callback=lambda _s, dom=d: self.prompt_for(dom))
            )
        self._ensure_enabled(self.pending_menu)

        self._safe_clear(self.recent_menu)
        for _ts, dom, action in reversed(self.filter.recent[-20:]):
            mark = {"allow": "✓", "block": "✗"}.get(action, "?")
            self.recent_menu.add(rumps.MenuItem(f"{mark} {dom}"))
        self._ensure_enabled(self.recent_menu)

        self._safe_clear(self.allowed_menu)
        for d in sorted(self.filter.allowlist):
            self.allowed_menu.add(
                rumps.MenuItem(d, callback=lambda _s, dom=d: self.remove_allow(dom))
            )
        self._ensure_enabled(self.allowed_menu)

        self._safe_clear(self.blocked_menu)
        for d in sorted(self.filter.blocklist):
            self.blocked_menu.add(
                rumps.MenuItem(d, callback=lambda _s, dom=d: self.remove_block(dom))
            )
        self._ensure_enabled(self.blocked_menu)

    # ── alerts ───────────────────────────────────────────────────────────────

    def show_domain_alert(self, domain: str) -> None:
        parent = parent_domain(domain)
        try:
            rumps.notification(
                title="OrbWall",
                subtitle="New domain blocked",
                message=f"{domain} — click OrbWall to allow",
            )
        except Exception:
            pass

        # NSAlert.runModal() is invisible in LSUIElement apps without explicit activation.
        # Temporarily switch to Regular policy so the alert window can come to the front.
        try:
            from AppKit import NSApp
            NSApp.setActivationPolicy_(0)  # NSApplicationActivationPolicyRegular
            NSApp.activateIgnoringOtherApps_(True)
        except Exception as e:
            print(f"activation failed: {e}", file=sys.stderr, flush=True)

        response = rumps.alert(
            title="OrbWall: New Domain",
            message=f"'{domain}' is requesting network access.\n\nAllow this domain?",
            ok="Allow",
            cancel="Block",
            other=f"Allow *.{parent}",
        )

        try:
            from AppKit import NSApp
            NSApp.setActivationPolicy_(1)  # NSApplicationActivationPolicyAccessory
        except Exception:
            pass

        if response == 1:
            self.filter.allow_domain(domain)
        elif response == 0:
            self.filter.block_domain(domain)
        elif response == 2:
            self.filter.allow_domain(f"*.{parent}")

    def prompt_for(self, domain: str) -> None:
        with self._alert_lock:
            if self._showing_alert:
                return
            self._showing_alert = True
        try:
            self.show_domain_alert(domain)
        finally:
            with self._alert_lock:
                self._showing_alert = False

    # ── menu callbacks ───────────────────────────────────────────────────────

    def toggle_pause(self, _) -> None:
        self.filter.set_paused(not self.filter.paused)

    def edit_allowlist(self, _) -> None:
        subprocess.Popen(["open", "-t", str(ALLOWLIST_PATH)])

    def edit_blocklist(self, _) -> None:
        subprocess.Popen(["open", "-t", str(BLOCKLIST_PATH)])

    def reload_lists(self, _) -> None:
        self.filter.reload_lists()

    def configure_orb(self, _) -> None:
        self._maybe_configure_orb(initial=False)

    def remove_allow(self, domain: str) -> None:
        with self.filter._lock:
            self.filter.allowlist.discard(domain)
            _write_set(ALLOWLIST_PATH, self.filter.allowlist)

    def remove_block(self, domain: str) -> None:
        with self.filter._lock:
            self.filter.blocklist.discard(domain)
            _write_set(BLOCKLIST_PATH, self.filter.blocklist)


# ── entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    try:
        ctypes.CDLL(None).setprogname(b"orbwall")
    except Exception:
        pass
    try:
        from Foundation import NSProcessInfo
        NSProcessInfo.processInfo().setProcessName_("orbwall")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="OrbWall — domain firewall for OrbStack VMs")
    parser.add_argument(
        "--port", type=int, default=1080,
        help="Preferred SOCKS5 port (auto-increments if taken). Default: 1080",
    )
    args = parser.parse_args()
    app = OrbWallApp(preferred_port=args.port)

    # Ctrl-C: AppKit's run loop is C code; signal.set_wakeup_fd is the C-level
    # mechanism that writes to a pipe when a signal arrives, even inside C extensions.
    # The write end must be non-blocking (required by set_wakeup_fd).
    _r, _w = os.pipe()
    _flags = fcntl.fcntl(_w, fcntl.F_GETFL)
    fcntl.fcntl(_w, fcntl.F_SETFL, _flags | os.O_NONBLOCK)
    signal.signal(signal.SIGINT, lambda *_: None)
    signal.set_wakeup_fd(_w)
    def _quit_watcher():
        os.read(_r, 1)
        app.shutdown()
        os._exit(130)
    threading.Thread(target=_quit_watcher, daemon=True).start()

    try:
        app.run()
    finally:
        app.shutdown()


if __name__ == "__main__":
    main()
