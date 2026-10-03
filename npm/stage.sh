#!/usr/bin/env bash
# Prepares npm/ for packing: checks the versions agree, then copies in the
# release binaries, the README and the license.
#
#   npm/stage.sh <binaries-dir>
#
# <binaries-dir> must hold aes256-linux-x64, aes256-linux-arm64,
# aes256-darwin-x64 and aes256-darwin-arm64.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
src="${1:?usage: npm/stage.sh <binaries-dir>}"

cargo_version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n1)
npm_version=$(node -p "require('$here/package.json').version")
if [ "$cargo_version" != "$npm_version" ]; then
  echo "version mismatch: Cargo.toml has $cargo_version, npm/package.json has $npm_version" >&2
  exit 1
fi

rm -rf "$here/vendor"
for platform in linux-x64 linux-arm64 darwin-x64 darwin-arm64; do
  mkdir -p "$here/vendor/$platform"
  cp "$src/aes256-$platform" "$here/vendor/$platform/aes256"
  chmod 755 "$here/vendor/$platform/aes256"
done
cp "$root/README.md" "$root/LICENSE" "$here/"
echo "staged @neddyp/encryptor $npm_version"
