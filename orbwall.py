"""OrbWall menu bar app.

Runs the SOCKS5 filtering proxy in a background thread and surfaces
new-domain prompts via native macOS alerts and Notification Center.
"""

import subprocess
import threading

import rumps

from socks_proxy import (
    ALLOWLIST_PATH,
    BLOCKLIST_PATH,
    CONFIG_DIR,
    SocksProxy,
    _write_set,
)


ICON_IDLE = "\U0001F6E1️"  # 🛡️
ICON_ALERT = "\U0001F534"        # 🔴


def parent_domain(domain: str) -> str:
    """Return the registrable-ish parent for a host (best-effort, no PSL)."""
    parts = domain.lower().split(".")
    if len(parts) <= 2:
        return domain.lower()
    # Common two-label TLDs we want to keep intact (e.g. .co.uk)
    two_label_tlds = {"co.uk", "ac.uk", "org.uk", "com.au", "co.jp", "co.kr"}
    tail2 = ".".join(parts[-2:])
    if tail2 in two_label_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class OrbWallApp(rumps.App):
    def __init__(self) -> None:
        super().__init__("OrbWall", title=ICON_IDLE, quit_button=None)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.proxy = SocksProxy()

        # Menu items
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
            self.quit_item,
        ]

        # Background proxy thread
        self.proxy_thread = threading.Thread(target=self.proxy.run, daemon=True)
        self.proxy_thread.start()

        # Showing an alert flag — avoid stacking dialogs
        self._alert_lock = threading.Lock()
        self._showing_alert = False

        # Timers
        self.pending_timer = rumps.Timer(self.check_pending, 0.5)
        self.pending_timer.start()
        self.ui_timer = rumps.Timer(self.refresh_ui, 2.0)
        self.ui_timer.start()

    # ---------- timers ----------

    def check_pending(self, _) -> None:
        if self._showing_alert:
            return
        try:
            domain = self.proxy.pending.get_nowait()
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
        pending_items = self.proxy.pending_snapshot()
        self.title = ICON_ALERT if pending_items else ICON_IDLE

        paused = self.proxy.paused
        status = "Paused (allow all)" if paused else "Active"
        self.status_item.title = (
            f"Status: {status} (✓ {self.proxy.allowed_count} allowed · "
            f"✗ {self.proxy.blocked_count} blocked)"
        )
        self.pause_item.title = "Resume Filtering" if paused else "Pause Filtering"

        self.pending_menu.title = f"Pending ({len(pending_items)})"
        self.pending_menu.clear()
        for d in pending_items:
            self.pending_menu.add(
                rumps.MenuItem(
                    d, callback=lambda sender, dom=d: self.prompt_for(dom)
                )
            )

        # Recent submenu
        self.recent_menu.clear()
        for ts, dom, action in reversed(self.proxy.recent[-20:]):
            mark = {"allow": "✓", "block": "✗", "unknown": "?"}.get(action, "·")
            self.recent_menu.add(rumps.MenuItem(f"{mark} {dom}"))

        # Allowed / blocked submenus
        self.allowed_menu.clear()
        for d in sorted(self.proxy.allowlist):
            self.allowed_menu.add(
                rumps.MenuItem(
                    d, callback=lambda sender, dom=d: self.remove_allow(dom)
                )
            )
        self.blocked_menu.clear()
        for d in sorted(self.proxy.blocklist):
            self.blocked_menu.add(
                rumps.MenuItem(
                    d, callback=lambda sender, dom=d: self.remove_block(dom)
                )
            )

    # ---------- alerts ----------

    def show_domain_alert(self, domain: str) -> None:
        parent = parent_domain(domain)
        # Fire a non-blocking notification too
        try:
            rumps.notification(
                title="OrbWall",
                subtitle="New domain blocked",
                message=f"{domain} — click to allow",
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
        # rumps.alert returns: 1=ok, 0=cancel, 2=other (third button)
        if response == 1:
            self.proxy.allow_domain(domain)
        elif response == 0:
            self.proxy.block_domain(domain)
        elif response == 2:
            self.proxy.allow_domain(f"*.{parent}")

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
        self.proxy.set_paused(not self.proxy.paused)

    def edit_allowlist(self, _) -> None:
        subprocess.Popen(["open", "-t", str(ALLOWLIST_PATH)])

    def edit_blocklist(self, _) -> None:
        subprocess.Popen(["open", "-t", str(BLOCKLIST_PATH)])

    def reload_lists(self, _) -> None:
        self.proxy.reload_lists()

    def remove_allow(self, domain: str) -> None:
        with self.proxy._lock:
            self.proxy.allowlist.discard(domain)
            _write_set(ALLOWLIST_PATH, self.proxy.allowlist)

    def remove_block(self, domain: str) -> None:
        with self.proxy._lock:
            self.proxy.blocklist.discard(domain)
            _write_set(BLOCKLIST_PATH, self.proxy.blocklist)


def main() -> None:
    OrbWallApp().run()


if __name__ == "__main__":
    main()
