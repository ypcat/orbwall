# OrbWall

Interactive domain-level sandbox firewall for AI agents running inside OrbStack VMs.

OrbWall is a macOS menu bar app that filters every TCP connection an OrbStack VM tries to make. When the VM (and any agent running inside it, even with `--dangerously-skip-permissions` / sudo) tries to reach a new domain, a native macOS popup asks **Allow** or **Block**. Everything not on the allowlist is denied by default. Because the proxy lives on the host and OrbStack's network stack routes VM traffic through it transparently, the agent inside the VM has no way to bypass it.

## How it works

```
Orb VM  ──►  orb config network_proxy = socks5://127.0.0.1:1080  ──►  OrbWall (host)
                                                                     ├─ SOCKS5 proxy
                                                                     ├─ allow/block lists
                                                                     └─ menu bar UI
```

SOCKS5 carries the destination domain as a string in every CONNECT request — for HTTP, HTTPS, SSH, git, raw TCP, anything. OrbWall reads the domain, checks it against the lists, and either splices the connection or rejects it and prompts the user.

## Install

```bash
./setup.sh
uv run orbwall.py
```

`setup.sh` does:

1. Installs [uv](https://github.com/astral-sh/uv) if not present, then `uv sync`
2. `orb config set network_proxy socks5://127.0.0.1:1080`
3. Creates `~/.orbwall/allowlist.txt` (pre-seeded) and `~/.orbwall/blocklist.txt`

## Files

- `orbwall.py` — menu bar app, alert UI, pending queue plumbing
- `socks_proxy.py` — SOCKS5 filtering proxy (asyncio, no external deps)
- `setup.sh` — install + OrbStack config
- `~/.orbwall/allowlist.txt` — one domain per line; `*.example.com` wildcards supported
- `~/.orbwall/blocklist.txt` — same format, takes priority over allowlist

## Menu bar

- **Status** — running state and ✓/✗ counters
- **Pending** — domains awaiting your decision; click one to re-show the prompt
- **Recent** — last 20 verdicts
- **Allowed / Blocked** — submenu of current rules; click an entry to remove it
- **Pause Filtering** — temporarily allow all (turns icon red is replaced by status text)
- **Edit Allowlist / Blocklist** — open in default text editor
- **Reload Lists** — re-read files after manual edits

## Teardown

```bash
orb config set network_proxy auto
```

That's the whole rollback. No pf rules, no kernel state, nothing else to clean.

## Protocol coverage

| Protocol | Filtered |
|---|---|
| HTTP / HTTPS | ✅ domain in SOCKS5 CONNECT |
| SSH, git, raw TCP | ✅ all TCP goes through SOCKS5 |
| DNS | ✅ resolved by proxy, VM never sees it |
| UDP | ❌ not handled by SOCKS5 — effectively blocked |

## Edge cases

- **Agent connects by raw IP** — the IP shows up as the "domain"; you get prompted just like any new host.
- **Same new domain hit repeatedly** — deduplicated; one prompt per domain. Subsequent requests fail until you decide.
- **OrbWall not running** — proxy port is closed; all VM TCP fails. Fail-safe.
- **Wildcards** — `*.example.com` matches any subdomain (any depth).
