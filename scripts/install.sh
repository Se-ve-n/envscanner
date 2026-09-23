#!/usr/bin/env bash
#
# envscanner — source installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Se-ve-n/envscanner/main/scripts/install.sh | bash
#
# or from a local clone:
#   ./scripts/install.sh
#
set -euo pipefail

REPO_URL="https://github.com/Se-ve-n/envscanner"
BRANCH="${ENVSCANNER_BRANCH:-main}"
PREFIX="${ENVSCANNER_PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
BUILD_DIR="$(mktemp -d)"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

# --- Prereqs ---
command -v cargo >/dev/null 2>&1 || die "cargo not found. Install Rust: https://rustup.rs"
command -v git   >/dev/null 2>&1 || die "git not found."
command -v tar   >/dev/null 2>&1 || die "tar not found."

# --- Fetch source ---
log "Cloning $REPO_URL ($BRANCH)"
git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$BUILD_DIR/envscanner"

# --- Build ---
log "Building release binary (this may take a minute)"
(
  cd "$BUILD_DIR/envscanner"
  cargo build --release --locked
)

# --- Install ---
mkdir -p "$BIN_DIR"
install -m 0755 "$BUILD_DIR/envscanner/target/release/envscanner" "$BIN_DIR/envscanner"

log "Installed to $BIN_DIR/envscanner"

# --- PATH check ---
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    warn "$BIN_DIR is not on your \$PATH."
    warn "Add this to your shell rc (~/.bashrc, ~/.zshrc, …):"
    warn ""
    warn "    export PATH=\"$BIN_DIR:\$PATH\""
    warn ""
    ;;
esac

# --- Verify ---
if command -v envscanner >/dev/null 2>&1; then
  log "Success: $(envscanner --version)"
else
  log "Binary installed. Open a new shell or update PATH, then run: envscanner --version"
fi