# OrbWall

Interactive domain-level sandbox firewall for AI agents running inside OrbStack VMs.

OrbWall is a macOS menu bar app that filters every TCP connection an OrbStack VM tries to make. When the VM (and any agent running inside it, even with `--dangerously-skip-permissions` / sudo) tries to reach a new domain, a native macOS popup asks **Allow** or **Block**. Everything not on the allowlist is denied by default. Because the proxy lives on the host and OrbStack's network stack routes VM traffic through it transparently, the agent inside the VM has no way to bypass it.

## How it works

```
Orb VM  ──►  orb config network_proxy = socks5://127.0.0.1:1080  ──►  OrbWall (host)
                                                                     ├─ SOCKS5 server (asyncio-socks-server)
                                                                     ├─ OrbWallFilter addon → allow / block / prompt
                                                                     └─ menu bar UI (rumps)
```

SOCKS5 carries the destination host as a string in every CONNECT request — for HTTP, HTTPS, SSH, git, raw TCP, anything. OrbWall reads it, checks the lists, and either lets the server proxy through or raises to reject.

## Run

One-liner (no clone needed):

```bash
uv run https://raw.githubusercontent.com/ypcat/orbwall/main/orbwall.py
```

Or local:

```bash
uv run orbwall.py
uv run orbwall.py --port 1081     # preferred port; auto-increments if taken
```

PEP 723 metadata in the script declares the deps (`rumps`, `asyncio-socks-server`) and Python (`>=3.12`); `uv` resolves and runs in an ephemeral environment.

On launch OrbWall:

1. Creates `~/.orbwall/` with a seeded `allowlist.txt` and empty `blocklist.txt` on first run
2. Picks a free port starting from `--port` (default 1080)
3. Starts the SOCKS5 server on `127.0.0.1:<port>`
4. Reads `orb config get network_proxy` — if it isn't already pointing at OrbWall, asks once via dialog whether to set it. Says yes → OrbWall remembers the previous value and **restores it on quit**.

The same configure prompt is reachable any time from the **Configure OrbStack** menu item.

## Files

- `orbwall.py` — single file: PEP 723 deps, filter addon, menu bar UI, embedded default allowlist
- `~/.orbwall/allowlist.txt` — runtime allowlist; one domain per line; `*.example.com` wildcards
- `~/.orbwall/blocklist.txt` — runtime blocklist; same format; blocklist beats allowlist

## Menu bar

- **Status** — running state, port, ✓/✗ counters
- **Pending** — domains awaiting your decision; click one to re-show the prompt
- **Recent** — last 20 verdicts
- **Allowed / Blocked** — current rules; click an entry to remove it
- **Pause Filtering** — temporarily allow all
- **Edit Allowlist / Blocklist** — open in default text editor
- **Reload Lists** — re-read files after manual edits
- **Configure OrbStack** — set / reset `orb config network_proxy`

## Protocol coverage

| Protocol | Filtered |
|---|---|
| HTTP / HTTPS | ✅ host in SOCKS5 CONNECT |
| SSH, git, raw TCP | ✅ all TCP goes through SOCKS5 |
| DNS | ✅ resolved by proxy, VM never sees it |
| UDP | ❌ not handled by SOCKS5 — effectively blocked |

## Edge cases

- **Agent connects by raw IP** — the IP shows up as the "host"; you get prompted just like any new domain.
- **Same new domain hit repeatedly** — deduplicated; one prompt per domain. Subsequent requests fail until you decide.
- **OrbWall killed with SIGKILL** — `atexit` doesn't fire, so OrbStack stays pointing at the (now closed) port. Reset manually: `orb config set network_proxy auto`.
- **Wildcards** — `*.example.com` matches any subdomain (any depth).
