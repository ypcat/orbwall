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

```bash
uv run orbwall.py
```

That's it. The PEP 723 header at the top of `orbwall.py` declares the dependencies (`rumps`, `asyncio-socks-server`) and Python version (`>=3.12`); `uv` resolves and runs in an ephemeral environment.

On first launch OrbWall:

- creates `~/.orbwall/` with `allowlist.txt` (seeded from `default_allowlist.txt`) and `blocklist.txt`
- prints the OrbStack setup hint to stdout
- starts the SOCKS5 server on `127.0.0.1:1080`

OrbWall **does not** modify OrbStack's config for you. Wire it up yourself:

```bash
orb config set network_proxy socks5://127.0.0.1:1080
```

The same hint is reachable from the menu bar via **Show OrbStack Setup…**.

## Files

- `orbwall.py` — entry point, PEP 723 deps, menu bar UI, self-init
- `socks_proxy.py` — `OrbWallFilter` addon (allow/block/prompt logic)
- `default_allowlist.txt` — seed list copied into `~/.orbwall/allowlist.txt` on first run
- `~/.orbwall/allowlist.txt` — runtime allowlist; one domain per line; `*.example.com` wildcards
- `~/.orbwall/blocklist.txt` — runtime blocklist; same format; blocklist beats allowlist

## Menu bar

- **Status** — running state and ✓/✗ counters
- **Pending** — domains awaiting your decision; click one to re-show the prompt
- **Recent** — last 20 verdicts
- **Allowed / Blocked** — current rules; click an entry to remove it
- **Pause Filtering** — temporarily allow all
- **Edit Allowlist / Blocklist** — open in default text editor
- **Reload Lists** — re-read files after manual edits
- **Show OrbStack Setup…** — re-display the `orb config` hint

## Teardown

```bash
orb config set network_proxy auto
```

That's the whole rollback. No pf rules, no kernel state, nothing else to clean.

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
- **OrbWall not running** — proxy port is closed; all VM TCP fails. Fail-safe.
- **Wildcards** — `*.example.com` matches any subdomain (any depth).
