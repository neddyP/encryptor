#!/bin/sh
# Installs encryptor (the encryptor, encrypt and decrypt commands) from its
# latest GitHub release into /usr/local/bin, with sudo unless run as root.
# Linux on x64, x86, arm64 or arm, or macOS on x64 or arm64. Needs only curl
# or wget.
#
#   curl -fsSL https://raw.githubusercontent.com/neddyp/encryptor/master/install.sh | sh
#
# or download this file and run `sh install.sh`. To update, run
# `encryptor update`, which runs this script again. To uninstall:
#   cd /usr/local/bin && sudo rm encryptor encrypt decrypt
set -eu

die() { echo "encryptor was not installed: $*" >&2; exit 1; }

case $(uname -s) in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "there's no build for $(uname -s)" ;;
esac
case $(uname -m) in
  x86_64 | amd64) arch=x64 ;;
  i?86) arch=x86 ;;
  aarch64 | arm64) arch=arm64 ;;
  arm*) arch=arm ;;
  *) die "there's no build for $(uname -m)" ;;
esac

url=https://github.com/neddyp/encryptor/releases/latest/download/encryptor-$os-$arch
dir=/usr/local/bin
sudo=
[ "$(id -u)" = 0 ] || sudo=sudo

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
trap 'exit 130' HUP INT TERM
if command -v curl >/dev/null; then
  curl -fsSL --proto '=https' "$url" >"$tmp"
elif command -v wget >/dev/null; then
  wget -qO- "$url" >"$tmp"
else
  die "it needs curl or wget to download it"
fi || die "couldn't download $url"

# Copied in under another name and renamed over the old one, so neither a
# running encryptor nor macOS's check of its signature sees a partial file.
$sudo mkdir -p "$dir"
$sudo cp "$tmp" "$dir/.encryptor.new"
$sudo chmod 755 "$dir/.encryptor.new"
$sudo mv -f "$dir/.encryptor.new" "$dir/encryptor"
# The binary does what it's run as.
$sudo ln -sf encryptor "$dir/encrypt"
$sudo ln -sf encryptor "$dir/decrypt"
echo "encryptor installed in $dir: run encrypt, decrypt or encryptor"
