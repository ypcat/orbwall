# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "rumps",
#     "asyncio-socks-server",
# ]
# ///
"""OrbWall menu bar app.

Run with:  uv run orbwall.py
"""

import subprocess
import sys
import threading
from pathlib import Path

import rumps
from asyncio_socks_server import Server

from socks_proxy import (
    ALLOWLIST_PATH,
    BLOCKLIST_PATH,
    CONFIG_DIR,
    OrbWallFilter,
    _write_set,
)


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ALLOWLIST = SCRIPT_DIR / "default_allowlist.txt"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080
ICON_IDLE = "\U0001F6E1️"   # 🛡️
ICON_ALERT = "\U0001F534"        # 🔴

PROXY_HINT = (
    "Point OrbStack at OrbWall:\n"
    f"    orb config set network_proxy socks5://{PROXY_HOST}:{PROXY_PORT}\n"
    "Restore default routing later:\n"
    "    orb config set network_proxy auto"
)


def init_config() -> None:
    """Create ~/.orbwall/ and seed lists on first run."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not ALLOWLIST_PATH.exists():
        if DEFAULT_ALLOWLIST.exists():
            ALLOWLIST_PATH.write_text(DEFAULT_ALLOWLIST.read_text())
        else:
            ALLOWLIST_PATH.write_text("")
    if not BLOCKLIST_PATH.exists():
        BLOCKLIST_PATH.write_text("")


def parent_domain(domain: str) -> str:
    """Best-effort registrable parent (no PSL)."""
    parts = domain.lower().split(".")
    if len(parts) <= 2:
        return domain.lower()
    two_label_tlds = {"co.uk", "ac.uk", "org.uk", "com.au", "co.jp", "co.kr"}
    if ".".join(parts[-2:]) in two_label_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class OrbWallApp(rumps.App):
    def __init__(self) -> None:
        super().__init__("OrbWall", title=ICON_IDLE, quit_button=None)
        init_config()
        self.filter = OrbWallFilter()
        self.server = Server(
            host=PROXY_HOST, port=PROXY_PORT, addons=[self.filter]
        )
        # Server.run() installs SIGTERM/SIGINT handlers via the asyncio loop,
        # which only works on the main thread. rumps owns the main thread,
        # so we run the SOCKS server in a worker and skip signal wiring.
        self.server._install_signal_handlers = lambda: None

        self.status_item = rumps.MenuItem("Status: starting…")
        self.pending_menu = rumps.MenuItem("Pending (0)")
        self.recent_menu = rumps.MenuItem("Recent")
        self.allowed_menu = rumps.MenuItem("Allowed Domains")
        self.blocked_menu = rumps.MenuItem("Blocked Domains")
        self.pause_item = rumps.MenuItem(
            "Pause Filtering", callback=self.toggle_pause
        )
        self.edit_allow_item = rumps.MenuItem(
            "Edit Allowlist", callback=self.edit_allowlist
        )
        self.edit_block_item = rumps.MenuItem(
            "Edit Blocklist", callback=self.edit_blocklist
        )
        self.reload_item = rumps.MenuItem(
            "Reload Lists", callback=self.reload_lists
        )
        self.show_hint_item = rumps.MenuItem(
            "Show OrbStack Setup…", callback=self.show_hint
        )
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
            self.show_hint_item,
            None,
            self.quit_item,
        ]

        # Print the OrbStack setup hint to stdout — we don't touch
        # `orb config` ourselves.
        print(PROXY_HINT, flush=True)

        self.server_thread = threading.Thread(
            target=self._run_server, daemon=True
        )
        self.server_thread.start()

        self._alert_lock = threading.Lock()
        self._showing_alert = False

        self.pending_timer = rumps.Timer(self.check_pending, 0.5)
        self.pending_timer.start()
        self.ui_timer = rumps.Timer(self.refresh_ui, 2.0)
        self.ui_timer.start()

    def _run_server(self) -> None:
        try:
            self.server.run()
        except Exception as e:
            print(f"OrbWall proxy error: {e}", file=sys.stderr, flush=True)

    # ---------- timers ----------

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
        self.title = ICON_ALERT if pending_items else ICON_IDLE

        paused = self.filter.paused
        status = "Paused (allow all)" if paused else "Active"
        self.status_item.title = (
            f"Status: {status} "
            f"(✓ {self.filter.allowed_count} allowed · "
            f"✗ {self.filter.blocked_count} blocked)"
        )
        self.pause_item.title = (
            "Resume Filtering" if paused else "Pause Filtering"
        )

        self.pending_menu.title = f"Pending ({len(pending_items)})"
        self.pending_menu.clear()
        for d in pending_items:
            self.pending_menu.add(
                rumps.MenuItem(
                    d, callback=lambda _s, dom=d: self.prompt_for(dom)
                )
            )

        self.recent_menu.clear()
        for _ts, dom, action in reversed(self.filter.recent[-20:]):
            mark = {"allow": "✓", "block": "✗", "unknown": "?"}.get(action, "·")
            self.recent_menu.add(rumps.MenuItem(f"{mark} {dom}"))

        self.allowed_menu.clear()
        for d in sorted(self.filter.allowlist):
            self.allowed_menu.add(
                rumps.MenuItem(
                    d, callback=lambda _s, dom=d: self.remove_allow(dom)
                )
            )
        self.blocked_menu.clear()
        for d in sorted(self.filter.blocklist):
            self.blocked_menu.add(
                rumps.MenuItem(
                    d, callback=lambda _s, dom=d: self.remove_block(dom)
                )
            )

    # ---------- alerts ----------

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

        response = rumps.alert(
            title="OrbWall: New Domain",
            message=(
                f"'{domain}' is requesting network access.\n\n"
                "Allow this domain?"
            ),
            ok="Allow",
            cancel="Block",
            other=f"Allow *.{parent}",
        )
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

    # ---------- menu callbacks ----------

    def toggle_pause(self, _) -> None:
        self.filter.set_paused(not self.filter.paused)

    def edit_allowlist(self, _) -> None:
        subprocess.Popen(["open", "-t", str(ALLOWLIST_PATH)])

    def edit_blocklist(self, _) -> None:
        subprocess.Popen(["open", "-t", str(BLOCKLIST_PATH)])

    def reload_lists(self, _) -> None:
        self.filter.reload_lists()

    def show_hint(self, _) -> None:
        rumps.alert(title="OrbStack setup", message=PROXY_HINT, ok="OK")

    def remove_allow(self, domain: str) -> None:
        with self.filter._lock:
            self.filter.allowlist.discard(domain)
            _write_set(ALLOWLIST_PATH, self.filter.allowlist)

    def remove_block(self, domain: str) -> None:
        with self.filter._lock:
            self.filter.blocklist.discard(domain)
            _write_set(BLOCKLIST_PATH, self.filter.blocklist)


def main() -> None:
    OrbWallApp().run()


if __name__ == "__main__":
    main()
