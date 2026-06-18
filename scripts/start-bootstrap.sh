#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"
NODE_VERSION="${NODE_VERSION:-v20.18.3}"
NODE_DIST_BASE="${NODE_DIST_BASE:-https://nodejs.org/dist}"
NODE_DIR="$ROOT_DIR/runtime/node"
NODE_EXE="$NODE_DIR/bin/node"
NPM_CMD="$NODE_DIR/bin/npm"

log() { printf '[1Shell] %s\n' "$*"; }
err() { printf '[ERROR] %s\n' "$*" >&2; }

detect_platform() {
  case "$(uname -s)" in
    Linux) printf 'linux' ;;
    Darwin) printf 'darwin' ;;
    *) err "Unsupported OS: $(uname -s)"; return 1 ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'x64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *) err "Unsupported CPU architecture: $(uname -m)"; return 1 ;;
  esac
}

download() {
  local url="$1"
  local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 5 --retry-delay 2 -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$out" "$url"
  else
    err "Neither curl nor wget is available. Install one or preinstall Node.js 18+."
    return 1
  fi
}

download_node() {
  local platform
  platform="$(detect_platform)"
  local arch
  arch="$(detect_arch)"
  local archive
  local extract_flag
  archive="node-${NODE_VERSION}-${platform}-${arch}.tar.xz"
  extract_flag="-xJf"
  if [ "$platform" = "darwin" ]; then
    archive="node-${NODE_VERSION}-${platform}-${arch}.tar.gz"
    extract_flag="-xzf"
  fi
  local node_url="${NODE_DIST_BASE%/}/${NODE_VERSION}/${archive}"
  local sha_url="${NODE_DIST_BASE%/}/${NODE_VERSION}/SHASUMS256.txt"
  local work_dir
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/1shell-node.XXXXXX")"
  trap 'rm -rf "$work_dir"' RETURN

  log "Portable Node.js not found. Downloading ${NODE_VERSION}..."
  download "$sha_url" "$work_dir/SHASUMS256.txt"
  download "$node_url" "$work_dir/$archive"

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$work_dir" && grep "  ${archive}$" SHASUMS256.txt | sha256sum -c -)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$work_dir" && grep "  ${archive}$" SHASUMS256.txt | shasum -a 256 -c -)
  fi
  tar ${extract_flag/-x/-t} "$work_dir/$archive" >/dev/null
  mkdir -p "$(dirname "$NODE_DIR")"
  rm -rf "$NODE_DIR"
  tar "$extract_flag" "$work_dir/$archive" -C "$work_dir"
  mv "$work_dir/node-${NODE_VERSION}-${platform}-${arch}" "$NODE_DIR"
}

try_system_node() {
  command -v node >/dev/null 2>&1 || return 1
  command -v npm >/dev/null 2>&1 || return 1
  major="$(node -p "process.versions.node.split('.')[0]" 2>/dev/null || true)"
  [ -n "$major" ] || return 1
  [ "$major" -ge 18 ] || return 1
  NODE_EXE="$(command -v node)"
  NPM_CMD="$(command -v npm)"
}

log "1Shell v4.1.0 starter package"
if [ ! -x "$NODE_EXE" ]; then
  if [ "${ONE_SHELL_USE_SYSTEM_NODE:-0}" = "1" ] && try_system_node; then
    :
  else
    download_node
    NODE_EXE="$NODE_DIR/bin/node"
    NPM_CMD="$NODE_DIR/bin/npm"
  fi
fi

export PATH="$(dirname "$NODE_EXE"):$PATH"
log "Node: $("$NODE_EXE" -v)"

if [ ! -x "$NPM_CMD" ] && ! command -v "$NPM_CMD" >/dev/null 2>&1; then
  err "npm not found beside Node.js."
  exit 1
fi

if [ ! -d "$ROOT_DIR/node_modules" ] || ! "$NODE_EXE" -e "require('better-sqlite3'); require('node-pty'); require.resolve('express')" >/dev/null 2>&1; then
  log "Installing backend production dependencies..."
  "$NPM_CMD" ci --omit=dev --include=optional --no-audit --fund=false
  "$NODE_EXE" -e "require('better-sqlite3'); require('node-pty'); console.log('native modules ok')"
fi

if [ ! -f "$ROOT_DIR/frontend/dist/index.html" ]; then
  log "Frontend bundle missing. Building it now..."
  (cd "$ROOT_DIR/frontend" && "$NPM_CMD" ci --include=dev --include=optional --no-audit --fund=false && "$NPM_CMD" run build)
fi

if [ ! -f "$ROOT_DIR/.env" ] && [ -f "$ROOT_DIR/.env.example" ]; then
  cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
  chmod 600 "$ROOT_DIR/.env" || true
  log "Created .env from .env.example."
fi

log "Starting server..."
log "URL: http://localhost:${PORT:-3301}"
log "Press Ctrl+C to stop."
echo
exec "$NODE_EXE" server.js
