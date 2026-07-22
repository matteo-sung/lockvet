#!/bin/sh
# lockvet installer — downloads the latest release binary for your platform.
#   curl -fsSL https://raw.githubusercontent.com/matteo-sung/lockvet/main/install.sh | sh
set -eu

REPO="matteo-sung/lockvet"
INSTALL_DIR="${LOCKVET_INSTALL_DIR:-/usr/local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux|darwin) ;;
  *) echo "install.sh supports Linux and macOS; on Windows grab a zip from https://github.com/$REPO/releases" >&2; exit 1 ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$tag" ] || { echo "could not determine latest release" >&2; exit 1; }

name="lockvet_${tag}_${os}_${arch}"
url="https://github.com/$REPO/releases/download/$tag/$name.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading lockvet $tag ($os/$arch)..."
curl -fsSL "$url" | tar -xz -C "$tmp"

dest="$INSTALL_DIR/lockvet"
if [ -w "$INSTALL_DIR" ]; then
  install -m 755 "$tmp/$name/lockvet" "$dest"
else
  echo "Need sudo to write to $INSTALL_DIR"
  sudo install -m 755 "$tmp/$name/lockvet" "$dest"
fi
echo "Installed: $dest"
"$dest" -version
