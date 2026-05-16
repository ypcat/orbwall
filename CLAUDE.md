# OrbWall — Interactive Domain-Level Sandbox Firewall for Local AI Agents

## What This Is

A macOS menu bar app that acts as a domain-level firewall for OrbStack VMs. When an AI agent inside a VM tries to reach a new domain, a native macOS popup asks the user to Allow or Block. Everything else is denied by default.

## Why This Exists

AI coding agents need `--dangerously-skip-permissions` to work autonomously. That gives them sudo inside the VM. Any firewall inside the VM is useless — the agent can undo it. OrbWall runs on the host as a menu bar app, completely outside the agent's reach.

## Architecture

```
┌─────────────────────────────────┐
│  Orb VM (ubuntu, --isolated)    │
│  Claude Code (YOLO mode)        │
│                                 │
│  All traffic transparently      │
│  routed through SOCKS5 proxy    │
│  by OrbStack network stack.     │
│  VM has no idea. Can't bypass.  │
└──────────┬──────────────────────┘
           │  orb config set network_proxy socks5://127.0.0.1:1080
           ▼
┌─────────────────────────────────┐
│  macOS Host                     │
│                                 │
│  OrbWall (menu bar app)         │
│  ├── SOCKS5 proxy (:1080)       │
│  ├── Domain allowlist/blocklist │
│  ├── New domain → popup alert   │
│  ├── Allow/Block buttons        │
│  └── Menu bar status + history  │
└─────────────────────────────────┘
```

**That's it.** No Privoxy. No pf rules. No SNI proxy. No VM-side configuration.

## Why This Works

OrbStack's network stack transparently routes ALL VM traffic through the configured SOCKS proxy. Key facts:

1. **All protocols, not just HTTP.** SOCKS5 handles any TCP connection. HTTP, HTTPS, SSH, git, raw TCP — everything goes through the proxy.
2. **Transparent to the VM.** No `HTTP_PROXY` env var needed inside the VM. OrbStack intercepts at the network stack level. The agent doesn't know a proxy exists.
3. **Agent can't bypass it.** The proxy config lives on the macOS host (`orb config set`). The agent has sudo inside the VM but zero access to OrbStack's config on the host.
4. **Domain resolution happens at the proxy.** In SOCKS5, the client sends the domain name to the proxy, which resolves it. We see every domain in plaintext before any connection is made — including HTTPS.

## The SOCKS5 Proxy

A minimal SOCKS5 proxy (~150 lines Python) that:

1. Accepts SOCKS5 connections on `127.0.0.1:1080`
2. Reads the destination domain from the SOCKS5 CONNECT request
3. Checks domain against allowlist
4. If allowed → resolve DNS, connect to destination, splice streams
5. If blocked → reject connection, notify menu bar app
6. If unknown (new domain) → reject connection, notify menu bar app, which prompts user

### SOCKS5 Protocol (what we need)

The SOCKS5 handshake is simple. For our use case:

1. Client sends greeting: `\x05\x01\x00` (version 5, 1 auth method, no auth)
2. Proxy responds: `\x05\x00` (version 5, no auth required)
3. Client sends connect request: `\x05\x01\x00\x03<len><domain><port>`
   - `\x03` = domain name type (this is why SOCKS5 is perfect — client sends the domain as a string)
4. Proxy checks domain, connects (or rejects), responds with status

We only need to implement: no-auth handshake + domain-type CONNECT. That's ~60 lines for the protocol, ~40 lines for the stream splicing, ~50 lines for allowlist management.

### Implementation: `socks_proxy.py`

```python
# Pseudocode structure

class SocksProxy:
    def __init__(self, port=1080):
        self.allowlist = set()      # domains that pass
        self.blocklist = set()      # domains explicitly blocked
        self.pending = queue.Queue()  # new domains → sent to menu bar app
    
    async def handle_client(self, reader, writer):
        # 1. SOCKS5 handshake (no auth)
        # 2. Read CONNECT request → extract domain + port
        # 3. Check domain:
        #    - In allowlist (or matches wildcard) → connect + splice
        #    - In blocklist → reject (0x02 connection not allowed)
        #    - Unknown → reject + put domain in pending queue
        # 4. If allowed: open connection to real destination,
        #    send success reply, then splice bidirectionally
    
    def check_domain(self, domain: str) -> str:
        """Returns 'allow', 'block', or 'unknown'"""
        # Check exact match, then wildcard (*.example.com)
        # blocklist takes priority over allowlist
    
    def allow_domain(self, domain: str):
        """Called by menu bar app when user clicks Allow"""
        self.allowlist.add(domain)
        self.save_lists()
    
    def block_domain(self, domain: str):
        """Called by menu bar app when user clicks Block"""
        self.blocklist.add(domain)
        self.save_lists()
```

### Stream Splicing

Once a connection is allowed, the proxy just copies bytes between client and destination. No decryption, no inspection, no MITM. Use `asyncio` streams:

```python
async def splice(self, reader_a, writer_b, reader_b, writer_a):
    async def pipe(r, w):
        try:
            while True:
                data = await r.read(8192)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            w.close()
    await asyncio.gather(pipe(reader_a, writer_b), pipe(reader_b, writer_a))
```

## The Menu Bar App

Built with `rumps` — a Python library for macOS status bar apps. One file, one dependency.

### Menu Bar Layout

```
🛡️ OrbWall          ← menu bar icon (shows 🛡️ or 🔴 if pending)
├── Status: Active (✓ 12 allowed · ✗ 3 blocked)
├── ──────────────
├── Pending (1)     ← submenu, bold if items waiting
│   └── cdn.example.com  → click opens Allow/Block alert
├── Recent
│   ├── ✓ api.anthropic.com
│   ├── ✓ registry.npmjs.org
│   ├── ✗ telemetry.example.com
│   └── ✓ github.com
├── ──────────────
├── Allowed Domains  → submenu showing all allowed
├── Blocked Domains  → submenu showing all blocked
├── ──────────────
├── Pause Filtering  ← toggle: temporarily allow all
├── Edit Allowlist   ← opens allowlist.txt in default editor
├── ──────────────
└── Quit
```

### Interactive Notification Popup

When a new domain is detected, two things happen simultaneously:

**1. macOS alert dialog (blocking, in-focus):**
```python
response = rumps.alert(
    title="OrbWall: New Domain",
    message=f"'{domain}' is requesting network access.\n\nAllow this domain?",
    ok="Allow",
    cancel="Block",
    other="Allow *.{parent_domain}"  # wildcard option
)
# response == 1 → Allow
# response == 0 → Block  
# response == 2 → Allow wildcard
```

This is the primary interaction. A native macOS dialog with Allow/Block buttons. Appears immediately. User clicks one button and it takes effect instantly.

The "Allow *.parent_domain" button is a convenience — when npm tries to reach `registry.npmjs.org`, `cdn.npmjs.org`, etc., the user can allow all `*.npmjs.org` at once.

**2. macOS notification (non-blocking, for background awareness):**
```python
rumps.notification(
    title="OrbWall",
    subtitle="New domain blocked",
    message=f"{domain} — open OrbWall to allow"
)
```

This fires in parallel. If the user dismissed the alert or is away, they see the notification in Notification Center and can open OrbWall's menu to act on it later.

### Pending Queue

If the user doesn't respond to the alert immediately (dismisses it, is away), the domain stays in a "Pending" list in the menu bar dropdown. The menu bar icon changes from 🛡️ to 🔴 to indicate pending items. Clicking a pending domain re-shows the Allow/Block alert.

Meanwhile, the agent's requests to that domain keep getting rejected by the SOCKS proxy. Once the user allows it, the next request succeeds automatically.

### Implementation: `orbwall.py`

```python
# Pseudocode structure

import rumps
import threading

class OrbWallApp(rumps.App):
    def __init__(self):
        super().__init__("OrbWall", icon=None, title="🛡️")
        self.proxy = SocksProxy(port=1080)
        self.allowed_count = 0
        self.blocked_count = 0
        
        # Start proxy in background thread
        self.proxy_thread = threading.Thread(
            target=self.proxy.run, daemon=True
        )
        self.proxy_thread.start()
        
        # Timer to check for new pending domains
        self.timer = rumps.Timer(self.check_pending, 0.5)
        self.timer.start()
    
    def check_pending(self, _):
        """Poll proxy's pending queue, show alerts for new domains"""
        while not self.proxy.pending.empty():
            domain = self.proxy.pending.get()
            self.show_domain_alert(domain)
    
    def show_domain_alert(self, domain):
        """Show native macOS Allow/Block dialog"""
        parent = extract_parent_domain(domain)
        response = rumps.alert(
            title="OrbWall: New Domain",
            message=f"'{domain}' is requesting access.",
            ok="Allow",
            cancel="Block",
            other=f"Allow *.{parent}"
        )
        if response == 1:
            self.proxy.allow_domain(domain)
        elif response == 0:
            self.proxy.block_domain(domain)
        elif response == 2:
            self.proxy.allow_domain(f"*.{parent}")
```

## File Structure

```
orbwall/
├── orbwall.py         # Menu bar app + alert UI (~150 lines)
├── socks_proxy.py     # SOCKS5 filtering proxy (~150 lines)
├── setup.sh           # Install deps + configure OrbStack (~30 lines)
└── README.md
```

**Total: ~330 lines + README.**

## Setup

```bash
# One-time setup
pip3 install rumps
./setup.sh  # or just these two commands:

# Point OrbStack at our proxy
orb config set network_proxy socks5://127.0.0.1:1080

# Start OrbWall (stays in menu bar)
python3 orbwall.py
```

`setup.sh` does:
1. `pip3 install rumps` if not present
2. `orb config set network_proxy socks5://127.0.0.1:1080`
3. Create `~/.orbwall/` directory
4. Create `~/.orbwall/allowlist.txt` with pre-seeded domains
5. Create `~/.orbwall/blocklist.txt` (empty)
6. Print instructions

Pre-seeded allowlist:
```
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
```

## Teardown

```bash
# Disable proxy (back to normal)
orb config set network_proxy auto

# Or fully disable
orb config set network_proxy none
```

No pf rules to clean up. No services to stop. Just reset the proxy config.

## Protocol Coverage

| Protocol | Handled? | How |
|---|---|---|
| HTTP | ✅ | SOCKS5 sees domain in CONNECT request |
| HTTPS | ✅ | SOCKS5 sees domain in CONNECT request (before TLS) |
| SSH | ✅ | SOCKS5 sees destination domain/IP |
| Git (SSH) | ✅ | Routed through SOCKS by OrbStack |
| Git (HTTPS) | ✅ | Routed through SOCKS by OrbStack |
| Raw TCP | ✅ | All TCP goes through SOCKS |
| DNS | ✅ | Resolved by proxy, not by VM |
| UDP | ❌ | SOCKS5 doesn't handle UDP by default. Not needed for typical agent workloads. |

## CLI Interface

OrbWall is primarily a menu bar app, but for scripting:

```bash
# Start the app (menu bar + proxy)
python3 orbwall.py

# Quick commands (talk to running instance via file or socket)
orbwall allow cdn.example.com
orbwall block tracking.example.com
orbwall list
orbwall pause
orbwall resume
orbwall status
```

CLI commands write to `~/.orbwall/allowlist.txt` or `~/.orbwall/blocklist.txt` and signal the running proxy to reload. Implementation: the CLI writes a command to a Unix socket that the proxy listens on, or simply modifies the files and sends SIGUSR1.

## Design Decisions

### Why SOCKS5, not HTTP proxy?

HTTP proxies only handle HTTP/HTTPS. SOCKS5 handles all TCP. With OrbStack's SOCKS proxy support routing ALL traffic transparently, we get full protocol coverage with one component.

### Why `rumps`, not SwiftUI?

SwiftUI menu bar apps require Xcode, significant boilerplate, and have known issues (settings windows don't work properly, activation policy juggling required). `rumps` gives us a working menu bar app with native macOS alerts and notifications in ~50 lines of Python. It uses PyObjC under the hood so everything is truly native — the alerts are real `NSAlert` dialogs, the notifications go through the real Notification Center.

### Why `rumps.alert()`, not `terminal-notifier`?

`rumps.alert()` is a modal dialog with custom buttons — it blocks until the user clicks Allow or Block. This is perfect for our use case: the agent's request is already blocked, so we're not adding latency. The user sees the dialog, clicks a button, done. `terminal-notifier` requires a separate install and has less reliable button handling.

### Why OrbStack transparent proxy, not pf rules?

OrbStack's `network_proxy` setting intercepts at the virtual network stack level — more reliable than pf `rdr` rules, handles all protocols through SOCKS, and requires zero macOS kernel configuration. One `orb config set` command vs. editing `/etc/pf.conf` with sudo. And teardown is just `orb config set network_proxy auto`.

### Why not Privoxy?

Privoxy is an HTTP-only filtering proxy. It can't handle SSH, raw TCP, or transparent HTTPS without an SNI proxy helper. With SOCKS5 routing all traffic, Privoxy is unnecessary.

### Why default-deny?

For AI agent sandboxing, unknown = dangerous. The agent should only reach domains the user has explicitly approved. The pre-seeded allowlist covers the minimum needed for Claude Code to function. Everything else triggers a prompt.

## Edge Cases

1. **Agent tries to bypass proxy:** Can't. OrbStack routes at the network stack level. No env vars to unset.
2. **Agent connects by IP instead of domain:** SOCKS5 sees the raw IP. Treat as unknown → prompt user. Most legitimate services use domains.
3. **Rapid requests to same new domain:** Proxy deduplicates. Only one alert per domain. Subsequent requests get silently rejected until user decides.
4. **User allows domain while requests are pending:** Next request succeeds immediately. No restart needed.
5. **OrbWall not running but proxy config set:** All connections fail (no proxy listening). Fail-safe.
6. **Multiple VMs:** All share the same proxy and allowlist. Fine for v1.
7. **Wildcard subdomains:** `*.example.com` matches `foo.example.com`, `bar.baz.example.com`. Stored in allowlist, matched with `endswith`.
8. **UDP traffic:** Not routed through SOCKS5. Effectively blocked. Not needed for typical dev work.
9. **npm/pip installing packages (many CDN domains):** User allows `*.npmjs.org` and `*.pythonhosted.org` with the wildcard button. One click covers all subdomains.
10. **py2app bundling:** For distribution, the app can be bundled into a `.app` with `py2app` so it looks and behaves like a native macOS app.

## What NOT to Build

- No web UI.
- No TUI (replaced by menu bar app).
- No pf rules.
- No Privoxy.
- No SNI proxy.
- No per-URL filtering.
- No TLS inspection.
- No auto-learning mode.

## Success Criteria

1. Setup takes under 60 seconds (pip install + orb config set + launch)
2. All TCP traffic from VM is filtered by domain
3. New domain → macOS popup within 1 second
4. One click Allow/Block, takes effect immediately
5. Claude Code works in YOLO mode with pre-seeded allowlist
6. Agent cannot bypass the firewall with any privilege level inside VM
7. Total project under 350 lines of Python
8. Single dependency: `rumps`

## Optional Future Enhancements (v2)

- Bundle as `.app` with py2app for drag-and-drop install
- Per-VM allowlists (filter by source IP in SOCKS proxy)
- Logging/audit trail with timestamps
- "Session mode" — temporary allowlist that resets on restart
- Auto-detect common dev domains (npm, pip, cargo, go modules) and offer to allow as a group
- Export/import allowlist profiles (e.g. "python-dev", "node-dev", "rust-dev")
