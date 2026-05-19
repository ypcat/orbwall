# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "rumps",
# ]
# ///
"""OrbWall — domain-level firewall for OrbStack VMs.

Run with:  uv run orbwall.py [--port PORT]
Or one-liner:  uv run https://raw.githubusercontent.com/ypcat/orbwall/main/orbwall.py
"""

import argparse
import asyncio
import atexit
import ctypes
import fcntl
import ipaddress
import os
import queue
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import rumps


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
*.ubuntu.com
*.debian.org
packages.microsoft.com
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

class OrbWallFilter:
    def __init__(self) -> None:
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
            if d.startswith("*."):
                self._pending_seen = {p for p in self._pending_seen if not _matches(p, d)}

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
                print(f"OrbWall: ✗ {domain}", flush=True)

    def remove_allow_domain(self, domain: str) -> None:
        d = domain.lower()
        with self._lock:
            self.allowlist.discard(d)
            _write_set(ALLOWLIST_PATH, self.allowlist)

    def remove_block_domain(self, domain: str) -> None:
        d = domain.lower()
        with self._lock:
            self.blocklist.discard(d)
            _write_set(BLOCKLIST_PATH, self.blocklist)

    def _enqueue_pending(self, domain: str) -> None:
        d = domain.lower()
        with self._lock:
            if d in self._pending_seen:
                return
            self._pending_seen.add(d)
        print(f"OrbWall: ? {d} — awaiting approval", flush=True)
        self.pending.put(d)


# ── SOCKS5 proxy ─────────────────────────────────────────────────────────────

_SOCKS5_OK   = bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])  # SUCCEEDED, BND 0.0.0.0:0
_SOCKS5_DENY = bytes([5, 2, 0, 1, 0, 0, 0, 0, 0, 0])  # CONNECTION NOT ALLOWED
_TLS_PORTS   = frozenset((443, 8443))
_HTTP_PORTS  = frozenset((80, 8080))
_PEEK_PORTS  = _TLS_PORTS | _HTTP_PORTS


def _host_from_http(data: bytes) -> str | None:
    """Extract Host header value from an HTTP/1.x request."""
    try:
        for line in data.split(b"\r\n")[1:]:
            if line.lower().startswith(b"host:"):
                host = line[5:].strip().decode("ascii", errors="ignore")
                return host.split(":")[0] if ":" in host else host
    except Exception:
        pass
    return None


def _sni_from_hello(data: bytes) -> str | None:
    """Extract SNI hostname from a TLS ClientHello record."""
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        pos = 43  # record(5) + handshake hdr(4) + client_version(2) + random(32)
        if pos >= len(data):
            return None
        pos += 1 + data[pos]  # skip session_id
        if pos + 2 > len(data):
            return None
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")  # skip cipher_suites
        if pos >= len(data):
            return None
        pos += 1 + data[pos]  # skip compression_methods
        if pos + 2 > len(data):
            return None
        ext_end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= min(ext_end, len(data)):
            etype = int.from_bytes(data[pos:pos + 2], "big")
            elen  = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos  += 4
            if etype == 0:  # SNI extension
                p = pos + 2  # skip server_name_list_length
                if p + 3 <= len(data) and data[p] == 0:
                    nlen = int.from_bytes(data[p + 1:p + 3], "big")
                    if p + 3 + nlen <= len(data):
                        return data[p + 3:p + 3 + nlen].decode("ascii", errors="ignore")
                return None
            pos += elen
    except Exception:
        pass
    return None


async def _splice(
    r_a: asyncio.StreamReader, w_b: asyncio.StreamWriter,
    r_b: asyncio.StreamReader, w_a: asyncio.StreamWriter,
) -> None:
    async def _pipe(r, w):
        try:
            while chunk := await r.read(65536):
                w.write(chunk)
                await w.drain()
        except (ConnectionError, asyncio.CancelledError, OSError):
            pass
        finally:
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass
    async with asyncio.TaskGroup() as tg:
        tg.create_task(_pipe(r_a, w_b))
        tg.create_task(_pipe(r_b, w_a))


async def _socks5_serve(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    fltr: "OrbWallFilter",
) -> None:
    try:
        # Greeting
        n = (await reader.readexactly(2))[1]
        await reader.readexactly(n)
        writer.write(b"\x05\x00")
        await writer.drain()

        # CONNECT request
        hdr = await reader.readexactly(4)
        if hdr[0] != 5 or hdr[1] != 1:
            writer.write(_SOCKS5_DENY)
            await writer.drain()
            return

        atyp = hdr[3]
        if atyp == 1:
            host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
            is_ip = True
        elif atyp == 4:
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
            is_ip = True
        elif atyp == 3:
            n = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode("ascii")
            is_ip = False
        else:
            writer.write(_SOCKS5_DENY)
            await writer.drain()
            return

        port = struct.unpack("!H", await reader.readexactly(2))[0]

        # For IP+known ports: send provisional OK, peek at first bytes for hostname.
        buffered = b""
        if is_ip and port in _PEEK_PORTS:
            writer.write(_SOCKS5_OK)
            await writer.drain()
            try:
                buffered = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            except asyncio.TimeoutError:
                pass
            if port in _TLS_PORTS:
                effective_host = _sni_from_hello(buffered) or host
            else:
                effective_host = _host_from_http(buffered) or host
        else:
            effective_host = host

        # Hold unknown connections until user decides (up to 30 s).
        verdict = fltr.check_domain(effective_host)
        if verdict == "unknown":
            fltr._enqueue_pending(effective_host)
            for _ in range(60):
                await asyncio.sleep(0.5)
                verdict = fltr.check_domain(effective_host)
                if verdict != "unknown":
                    break

        peeked = is_ip and port in _PEEK_PORTS
        if verdict == "allow":
            fltr._record(effective_host, "allow")
            if not peeked:
                writer.write(_SOCKS5_OK)
                await writer.drain()
        else:
            fltr._record(effective_host, "block")
            if not peeked:
                writer.write(_SOCKS5_DENY)
                await writer.drain()
            return  # peeked path: client sees TCP RST

        # Connect to real destination and relay.
        try:
            remote_r, remote_w = await asyncio.open_connection(host, port)
        except Exception:
            return
        if buffered:
            remote_w.write(buffered)
            await remote_w.drain()
        await _splice(reader, remote_w, remote_r, writer)

    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


class Socks5Proxy:
    def __init__(self, host: str, port: int, fltr: "OrbWallFilter") -> None:
        self._host = host
        self._port = port
        self._fltr = fltr

    def run(self) -> None:
        asyncio.run(self._run())

    async def _run(self) -> None:
        server = await asyncio.start_server(
            lambda r, w: _socks5_serve(r, w, self._fltr),
            self._host, self._port,
        )
        async with server:
            await server.serve_forever()


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
        self.proxy = Socks5Proxy(host=self._proxy_host, port=self._proxy_port, fltr=self.filter)

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

        self.server_thread = threading.Thread(target=self._run_proxy, daemon=True)
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

    def _run_proxy(self) -> None:
        try:
            self.proxy.run()
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
            if initial and not self._we_set_orb:
                # Leftover from a previous run (e.g., crash). Claim it so we restore on quit.
                self._original_orb_proxy = "auto"
                self._we_set_orb = True
                print(f"orb network_proxy already set to {self._proxy_url} — inherited.", flush=True)
            elif not initial:
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
        except queue.Empty:
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

        response = 1002  # default: block on any error
        try:
            from AppKit import NSAlert, NSApp
            # Switch to Regular policy so the alert can become frontmost.
            NSApp.setActivationPolicy_(0)
            NSApp.activateIgnoringOtherApps_(True)

            alert = NSAlert.alloc().init()
            alert.setMessageText_("OrbWall: New Domain")
            alert.setInformativeText_(
                f"'{domain}' is requesting network access.\n\nAllow this domain?"
            )
            alert.addButtonWithTitle_("Allow")
            alert.addButtonWithTitle_(f"Allow *.{parent}")
            alert.addButtonWithTitle_("Block")
            # NSModalPanelWindowLevel (8) floats above normal app windows.
            alert.window().setLevel_(8)
            response = alert.runModal()
        except Exception as e:
            print(f"alert failed: {e}", file=sys.stderr, flush=True)
        finally:
            try:
                from AppKit import NSApp
                NSApp.setActivationPolicy_(1)
            except Exception:
                pass

        # NSAlertFirstButtonReturn = 1000
        if response == 1000:
            self.filter.allow_domain(domain)
        elif response == 1001:
            self.filter.allow_domain(f"*.{parent}")
        elif response == 1002:
            self.filter.block_domain(domain)

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
        self.filter.remove_allow_domain(domain)

    def remove_block(self, domain: str) -> None:
        self.filter.remove_block_domain(domain)


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
        # Hard exit if shutdown hangs (e.g. orb CLI slow or blocked).
        killer = threading.Timer(3.0, lambda: os._exit(130))
        killer.daemon = True
        killer.start()
        app.shutdown()
        killer.cancel()
        os._exit(130)
    threading.Thread(target=_quit_watcher, daemon=True).start()

    try:
        app.run()
    finally:
        app.shutdown()


if __name__ == "__main__":
    main()
