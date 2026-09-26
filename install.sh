#!/usr/bin/env bash
#
# install.sh — link keyvault and secret into a directory on PATH (default ~/.local/bin).
# Links, not copies: `git pull` in this checkout is the upgrade.
#
#   ./install.sh                 # ~/.local/bin
#   PREFIX=/opt/homebrew ./install.sh
#
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${PREFIX:-$HOME/.local}/bin"
mkdir -p "$BIN"
for t in keyvault secret; do
    ln -sfn "$HERE/$t" "$BIN/$t"
    echo "linked $BIN/$t -> $HERE/$t"
done
for dep in age jq; do
    command -v "$dep" >/dev/null || echo "! $dep is missing: brew install $dep"
done
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "! $BIN is not on your PATH; add it to your shell profile" ;;
esac
echo
echo "Next: keyvault init"
