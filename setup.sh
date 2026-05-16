#!/usr/bin/env bash
# OrbWall setup: install deps, configure OrbStack, seed allowlist.
set -euo pipefail

CONFIG_DIR="${HOME}/.orbwall"
ALLOWLIST="${CONFIG_DIR}/allowlist.txt"
BLOCKLIST="${CONFIG_DIR}/blocklist.txt"

echo "[1/4] Installing rumps…"
python3 -m pip install --user --upgrade rumps >/dev/null

echo "[2/4] Configuring OrbStack to use SOCKS5 proxy on 127.0.0.1:1080…"
if command -v orb >/dev/null 2>&1; then
  orb config set network_proxy socks5://127.0.0.1:1080
else
  echo "  ! 'orb' CLI not found. Install OrbStack first, then run:"
  echo "      orb config set network_proxy socks5://127.0.0.1:1080"
fi

echo "[3/4] Creating ${CONFIG_DIR}…"
mkdir -p "${CONFIG_DIR}"

if [ ! -f "${ALLOWLIST}" ]; then
  cat > "${ALLOWLIST}" <<'EOF'
# OrbWall allowlist. One domain per line. Wildcards: *.example.com
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
EOF
  echo "  ✓ Seeded ${ALLOWLIST}"
else
  echo "  • ${ALLOWLIST} already exists, leaving untouched"
fi

if [ ! -f "${BLOCKLIST}" ]; then
  : > "${BLOCKLIST}"
  echo "  ✓ Created empty ${BLOCKLIST}"
fi

echo "[4/4] Done."
echo
echo "Launch OrbWall with:"
echo "    python3 orbwall.py"
echo
echo "To disable the firewall later:"
echo "    orb config set network_proxy auto"
