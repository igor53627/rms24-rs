#!/usr/bin/env sh
# Installs git hooks for this repository.
# Usage: ./scripts/install-hooks.sh

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "Installing git hooks..."

cp "$REPO_ROOT/scripts/commit-msg-hook.sh" "$HOOKS_DIR/commit-msg"
chmod +x "$HOOKS_DIR/commit-msg"

echo "Done. commit-msg hook installed."
