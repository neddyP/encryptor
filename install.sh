#!/usr/bin/env bash
# Installs @neddyp/encryptor globally with npm, installing Node.js (which
# includes npm) first if npm is missing. Linux or macOS, x64 or arm64.
set -euo pipefail

sudo=; [ "$(id -u)" = 0 ] || sudo="sudo -H"

if ! command -v node >/dev/null || ! command -v npm >/dev/null; then
  if command -v apk >/dev/null; then  # Alpine: nodejs.org only builds for glibc
    $sudo apk add nodejs npm
  else
    case "$(uname -s)-$(uname -m)" in
      Linux-x86_64)  p=linux-x64 ;;
      Linux-aarch64) p=linux-arm64 ;;
      Darwin-x86_64) p=darwin-x64 ;;
      Darwin-arm64)  p=darwin-arm64 ;;
      *) echo "unsupported platform: need Linux or macOS on x64 or arm64" >&2; exit 1 ;;
    esac
    url=https://nodejs.org/dist/latest-v24.x
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    curl -fsSL "$url/SHASUMS256.txt" -o "$tmp/sums"
    file=$(grep -m1 -o "node-v[0-9.]*-$p\.tar\.gz" "$tmp/sums")
    curl -fsSL "$url/$file" -o "$tmp/$file"
    sum=$( (sha256sum "$tmp/$file" 2>/dev/null || shasum -a 256 "$tmp/$file") | cut -d' ' -f1)
    grep -q "^$sum  $file\$" "$tmp/sums" || { echo "checksum mismatch for $file" >&2; exit 1; }
    $sudo mkdir -p /usr/local
    $sudo tar -xzf "$tmp/$file" -C /usr/local --strip-components=1 --no-same-owner \
      "${file%.tar.gz}"/{bin,include,lib,share}
    export PATH=/usr/local/bin:$PATH
  fi
fi

# Without sudo first, for user-owned prefixes (nvm, Homebrew). sudo can reset
# PATH, and npm needs node on it.
npm install -g @neddyp/encryptor || $sudo env "PATH=$PATH" npm install -g @neddyp/encryptor
