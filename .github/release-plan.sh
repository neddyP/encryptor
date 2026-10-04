#!/usr/bin/env bash
# Decides what a run of the release workflow does, and for monthly runs
# prepares the release commit and tag. Run from the repository root.
#
# Writes three outputs (to stdout, and to $GITHUB_OUTPUT in CI):
#   mode     publish | dry-run | skip
#   version  the version being released
#   ref      the git ref to build from
#
# By event:
#   push (v* tag)       publish that version, unless npm already has it
#   workflow_dispatch   dry run of the current commit, as the next patch
#                       version if this one is already on npm, as a monthly
#                       run would. The jobs set it in their own copies with
#                       set-version.sh; nothing is committed.
#   schedule            if files that go into the package changed since the
#                       newest v* tag, bump the patch version (unless it was
#                       already raised by hand), commit and tag it locally,
#                       and publish. The workflow pushes the commit and tag.
set -euo pipefail

PACKAGE=@neddyp/encryptor
PACKAGE_FILES=(src Cargo.toml Cargo.lock npm README.md LICENSE)

cargo_version() { sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1; }
npm_version() { node -p "require('./npm/package.json').version"; }
published() { [ -n "$(npm view "$PACKAGE@$1" version 2>/dev/null)" ]; }
notice() { echo "::notice::$1"; }
fail() { echo "::error::$1"; exit 1; }

finish() {
  for line in "mode=$1" "version=$2" "ref=$3"; do
    echo "$line"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "$line" >> "$GITHUB_OUTPUT"; fi
  done
  exit 0
}

next_patch() {
  IFS=. read -r major minor patch <<< "$1"
  echo "$major.$minor.$((patch + 1))"
}

version=$(cargo_version)
[ "$version" = "$(npm_version)" ] ||
  fail "Cargo.toml ($version) and npm/package.json ($(npm_version)) versions differ"

case "${GITHUB_EVENT_NAME:?}" in
  workflow_dispatch)
    if published "$version"; then
      notice "$PACKAGE@$version is already on npm; dry run as $(next_patch "$version")"
      version=$(next_patch "$version")
    fi
    finish dry-run "$version" "$(git rev-parse HEAD)"
    ;;

  push)
    [ "${GITHUB_REF_NAME:?}" = "v$version" ] ||
      fail "tag $GITHUB_REF_NAME does not match version $version"
    if published "$version"; then
      notice "$PACKAGE@$version is already on npm; nothing to publish"
      finish skip "$version" "$GITHUB_REF_NAME"
    fi
    finish publish "$version" "$GITHUB_REF_NAME"
    ;;

  schedule)
    last=$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)
    if [ -z "$last" ]; then
      notice "no v* release tag yet; the first release has to be published by hand"
      finish skip "$version" ""
    fi
    if git diff --quiet "$last" HEAD -- "${PACKAGE_FILES[@]}"; then
      notice "no package changes since $last"
      finish skip "$version" ""
    fi

    # Keep a version that was raised by hand and not yet released; otherwise
    # take the next patch version.
    if [ "v$version" = "$last" ] || published "$version"; then
      version=$(next_patch "$version")
      .github/set-version.sh "$version"
      git -c user.name="github-actions[bot]" \
          -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
          commit -q -m "Release v$version" -- Cargo.toml Cargo.lock npm/package.json
    fi
    git tag "v$version"
    notice "releasing $PACKAGE@$version (changes since $last)"
    finish publish "$version" "v$version"
    ;;

  *)
    fail "unexpected event $GITHUB_EVENT_NAME"
    ;;
esac
