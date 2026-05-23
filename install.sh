#!/usr/bin/env sh
# cspm-scanner installer — Linux / macOS
#
#   curl -fsSL https://raw.githubusercontent.com/mohidev-tech/cspm-scanner/main/install.sh | sh
#
# Vars you can override:
#   CSPM_VERSION   default: latest release tag, or "main" if no releases yet
#   CSPM_PREFIX    default: $HOME/.local/bin (no sudo)
set -eu

REPO="mohidev-tech/cspm-scanner"
PREFIX="${CSPM_PREFIX:-$HOME/.local/bin}"
VERSION="${CSPM_VERSION:-}"

# Detect OS + arch
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux|darwin) ;;
  *) echo "unsupported OS: $os"; exit 1 ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported arch: $arch"; exit 1 ;;
esac

mkdir -p "$PREFIX"

# Resolve latest release tag if not pinned.
if [ -z "$VERSION" ]; then
  if command -v curl >/dev/null 2>&1; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
      | grep '"tag_name"' | head -n1 | cut -d '"' -f4 || true)
  fi
fi

if [ -n "$VERSION" ]; then
  url="https://github.com/$REPO/releases/download/$VERSION/cspm_${VERSION#v}_${os}_${arch}.tar.gz"
  echo "==> Downloading $url"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL "$url" -o "$tmp/cspm.tgz"
  tar -xzf "$tmp/cspm.tgz" -C "$tmp"
  install -m 0755 "$tmp/cspm" "$PREFIX/cspm"
else
  echo "==> No releases yet — building from source via 'go install'"
  if ! command -v go >/dev/null 2>&1; then
    echo "go is required to install from source. See https://go.dev/dl/"
    exit 1
  fi
  GOBIN="$PREFIX" go install "github.com/$REPO/cmd/cspm@latest"
fi

echo "==> Installed: $PREFIX/cspm"

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) echo "==> Add $PREFIX to PATH (e.g. in ~/.bashrc or ~/.zshrc):"
     echo "    export PATH=\"$PREFIX:\$PATH\"" ;;
esac

echo ""
"$PREFIX/cspm" version || true
echo ""
echo "Try: cspm scan ./your/terraform"
