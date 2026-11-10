#!/usr/bin/env bash
# Sets the package's version in Cargo.toml, Cargo.lock and npm/package.json.
# Run from the repository root. Uses perl rather than sed, whose in-place
# editing differs between GNU (Linux) and BSD (macOS).
#
#   .github/set-version.sh <version>
set -euo pipefail

VERSION="${1:?usage: .github/set-version.sh <version>}"
export VERSION
case "$VERSION" in
  *[!0-9.]* | "" ) echo "not a version: $VERSION" >&2; exit 1 ;;
esac

# Only the first match in each: the package's own version.
perl -0777 -pi -e 's/^version = ".*"$/version = "$ENV{VERSION}"/m' Cargo.toml
perl -0777 -pi -e 's/^(name = "encryptor"\nversion = )".*"$/$1"$ENV{VERSION}"/m' Cargo.lock
perl -0777 -pi -e 's/^(  "version": )".*"/$1"$ENV{VERSION}"/m' npm/package.json
