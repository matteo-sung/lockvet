#!/bin/sh
# lockvet installer — downloads the latest release binary for your platform
# and verifies it against the release's checksums.txt before installing.
#   curl -fsSL https://raw.githubusercontent.com/matteo-sung/lockvet/main/install.sh | sh
# Options (after `sh -s --`):
#   -b DIR   install into DIR (default /usr/local/bin, or $LOCKVET_INSTALL_DIR)
#   -v TAG   install a specific release tag (default: latest)
set -eu

REPO="matteo-sung/lockvet"
INSTALL_DIR="${LOCKVET_INSTALL_DIR:-/usr/local/bin}"
tag=""

while [ $# -gt 0 ]; do
  case "$1" in
    -b) INSTALL_DIR="$2"; shift 2 ;;
    -v) tag="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

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

if [ -z "$tag" ]; then
  tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
fi
[ -n "$tag" ] || { echo "could not determine latest release" >&2; exit 1; }

name="lockvet_${tag}_${os}_${arch}"
base="https://github.com/$REPO/releases/download/$tag"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading lockvet $tag ($os/$arch)..."
curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt"

want=$(grep " $name.tar.gz\$" "$tmp/checksums.txt" | cut -d' ' -f1)
[ -n "$want" ] || { echo "checksums.txt has no entry for $name.tar.gz" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)
else
  got=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)
fi
if [ "$got" != "$want" ]; then
  echo "checksum mismatch for $name.tar.gz" >&2
  echo "  expected: $want" >&2
  echo "  got:      $got" >&2
  exit 1
fi
echo "Checksum OK."

tar -xz -C "$tmp" -f "$tmp/$name.tar.gz"

dest="$INSTALL_DIR/lockvet"
if [ -w "$INSTALL_DIR" ]; then
  install -m 755 "$tmp/$name/lockvet" "$dest"
else
  echo "Need sudo to write to $INSTALL_DIR"
  sudo install -m 755 "$tmp/$name/lockvet" "$dest"
fi
echo "Installed: $dest"
"$dest" -version
