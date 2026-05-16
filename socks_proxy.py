"""SOCKS5 filtering proxy for OrbWall.

Listens on 127.0.0.1:1080. For each CONNECT request, extracts the domain
name (SOCKS5 atyp=0x03) and consults the allow/block lists. Allowed
connections are spliced bidirectionally. Unknown domains are rejected
and queued for user decision via the menu bar app.
"""

import asyncio
import os
import queue
import socket
import struct
import threading
import time
from pathlib import Path


CONFIG_DIR = Path(os.path.expanduser("~/.orbwall"))
ALLOWLIST_PATH = CONFIG_DIR / "allowlist.txt"
BLOCKLIST_PATH = CONFIG_DIR / "blocklist.txt"

SOCKS_VERSION = 0x05
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_HOST_UNREACHABLE = 0x04


def _read_set(path: Path) -> set:
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.add(line.lower())
    return out


def _write_set(path: Path, items: set) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(items)) + "\n")


class SocksProxy:
    def __init__(self, host: str = "127.0.0.1", port: int = 1080):
        self.host = host
        self.port = port
        self._lock = threading.Lock()
        self.allowlist = _read_set(ALLOWLIST_PATH)
        self.blocklist = _read_set(BLOCKLIST_PATH)
        self.pending: "queue.Queue[str]" = queue.Queue()
        self._pending_seen: set = set()
        self.paused = False
        self.allowed_count = 0
        self.blocked_count = 0
        self.recent: list = []  # list of (ts, domain, action)
        self.on_event = None  # optional callback(domain, action)
        self._loop: asyncio.AbstractEventLoop | None = None

    # ---------- list management ----------

    def check_domain(self, domain: str) -> str:
        """Return 'allow', 'block', or 'unknown'."""
        d = domain.lower()
        with self._lock:
            if self.paused:
                return "allow"
            if d in self.blocklist:
                return "block"
            for pat in self.blocklist:
                if pat.startswith("*.") and (d == pat[2:] or d.endswith(pat[1:])):
                    return "block"
            if d in self.allowlist:
                return "allow"
            for pat in self.allowlist:
                if pat.startswith("*.") and (d == pat[2:] or d.endswith(pat[1:])):
                    return "allow"
        return "unknown"

    def allow_domain(self, domain: str) -> None:
        with self._lock:
            self.allowlist.add(domain.lower())
            self.blocklist.discard(domain.lower())
            _write_set(ALLOWLIST_PATH, self.allowlist)
            _write_set(BLOCKLIST_PATH, self.blocklist)
            self._pending_seen.discard(domain.lower())

    def block_domain(self, domain: str) -> None:
        with self._lock:
            self.blocklist.add(domain.lower())
            self.allowlist.discard(domain.lower())
            _write_set(ALLOWLIST_PATH, self.allowlist)
            _write_set(BLOCKLIST_PATH, self.blocklist)
            self._pending_seen.discard(domain.lower())

    def reload_lists(self) -> None:
        with self._lock:
            self.allowlist = _read_set(ALLOWLIST_PATH)
            self.blocklist = _read_set(BLOCKLIST_PATH)

    def set_paused(self, paused: bool) -> None:
        with self._lock:
            self.paused = paused

    def _record(self, domain: str, action: str) -> None:
        with self._lock:
            self.recent.append((time.time(), domain, action))
            del self.recent[:-200]
            if action == "allow":
                self.allowed_count += 1
            elif action == "block":
                self.blocked_count += 1
        if self.on_event:
            try:
                self.on_event(domain, action)
            except Exception:
                pass

    def _enqueue_pending(self, domain: str) -> None:
        d = domain.lower()
        with self._lock:
            if d in self._pending_seen:
                return
            self._pending_seen.add(d)
        self.pending.put(d)

    def pending_snapshot(self) -> list:
        with self._lock:
            return sorted(self._pending_seen)

    # ---------- SOCKS5 protocol ----------

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            # Greeting: VER, NMETHODS, METHODS...
            hdr = await reader.readexactly(2)
            ver, nmethods = hdr[0], hdr[1]
            if ver != SOCKS_VERSION:
                writer.close()
                return
            await reader.readexactly(nmethods)
            # Reply: no-auth
            writer.write(bytes([SOCKS_VERSION, 0x00]))
            await writer.drain()

            # Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
            head = await reader.readexactly(4)
            ver, cmd, _, atyp = head
            if ver != SOCKS_VERSION or cmd != 0x01:
                await self._send_reply(writer, REP_GENERAL_FAILURE)
                writer.close()
                return

            if atyp == ATYP_DOMAIN:
                length = (await reader.readexactly(1))[0]
                raw = await reader.readexactly(length)
                try:
                    domain = raw.decode("idna")
                except UnicodeError:
                    domain = raw.decode("ascii", errors="replace")
            elif atyp == ATYP_IPV4:
                domain = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == ATYP_IPV6:
                domain = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                await self._send_reply(writer, REP_GENERAL_FAILURE)
                writer.close()
                return

            port = struct.unpack("!H", await reader.readexactly(2))[0]

            verdict = self.check_domain(domain)
            if verdict == "block":
                self._record(domain, "block")
                await self._send_reply(writer, REP_NOT_ALLOWED)
                writer.close()
                return
            if verdict == "unknown":
                self._record(domain, "unknown")
                self._enqueue_pending(domain)
                await self._send_reply(writer, REP_NOT_ALLOWED)
                writer.close()
                return

            # Allowed — open upstream
            try:
                up_reader, up_writer = await asyncio.wait_for(
                    asyncio.open_connection(domain, port), timeout=10
                )
            except (OSError, asyncio.TimeoutError):
                await self._send_reply(writer, REP_HOST_UNREACHABLE)
                writer.close()
                return

            self._record(domain, "allow")
            await self._send_reply(writer, REP_SUCCESS)
            await self._splice(reader, writer, up_reader, up_writer)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _send_reply(self, writer: asyncio.StreamWriter, rep: int) -> None:
        # VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
        writer.write(bytes([SOCKS_VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
        try:
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass

    async def _splice(self, ra, wa, rb, wb) -> None:
        async def pipe(r, w):
            try:
                while True:
                    data = await r.read(8192)
                    if not data:
                        break
                    w.write(data)
                    await w.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    w.close()
                except Exception:
                    pass

        await asyncio.gather(pipe(ra, wb), pipe(rb, wa))

    # ---------- lifecycle ----------

    async def _serve(self) -> None:
        server = await asyncio.start_server(self._handle_client, self.host, self.port)
        async with server:
            await server.serve_forever()

    def run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        finally:
            self._loop.close()


if __name__ == "__main__":
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    proxy = SocksProxy()
    print(f"OrbWall SOCKS5 proxy listening on {proxy.host}:{proxy.port}")
    proxy.run()
