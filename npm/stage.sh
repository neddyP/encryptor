#!/usr/bin/env bash
# Prepares the npm packages for packing: checks the versions agree, copies
# the README and the license into npm/, and makes one package for each
# platform in npm/platforms/<platform>, holding that platform's binary.
#
#   npm/stage.sh <binaries-dir>
#
# <binaries-dir> must hold encryptor-linux-x64, encryptor-linux-arm64,
# encryptor-darwin-x64 and encryptor-darwin-arm64.
#
# @neddyp/encryptor names the platform packages as optional dependencies,
# each limited by its `os` and `cpu` to the systems it runs on, so npm
# installs only the one for the system it's installing on.
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

rm -rf "$here/platforms" "$here/vendor"
for platform in linux-x64 linux-arm64 darwin-x64 darwin-arm64; do
  dir="$here/platforms/$platform"
  mkdir -p "$dir"
  cp "$src/encryptor-$platform" "$dir/encryptor"
  chmod 755 "$dir/encryptor"
  cp "$root/LICENSE" "$dir/"
  PLATFORM=$platform node - "$here/package.json" "$dir" <<'EOF'
const fs = require("node:fs");
const path = require("node:path");
const [main, dir] = process.argv.slice(2);
const pkg = JSON.parse(fs.readFileSync(main, "utf8"));
const platform = process.env.PLATFORM;
const [os, cpu] = platform.split("-");
const name = `${pkg.name}-${platform}`;
if (pkg.optionalDependencies?.[name] !== pkg.version) {
  console.error(`npm/package.json should have "${name}": "${pkg.version}" in optionalDependencies`);
  process.exit(1);
}
const out = {
  name,
  version: pkg.version,
  description: `The ${platform} binary for ${pkg.name}`,
  license: pkg.license,
  repository: pkg.repository,
  os: [os],
  cpu: [cpu],
  files: ["encryptor"],
  publishConfig: pkg.publishConfig,
};
fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify(out, null, 2) + "\n");
fs.writeFileSync(
  path.join(dir, "README.md"),
  `# ${name}\n\nThe ${platform} binary for [${pkg.name}](https://www.npmjs.com/package/${pkg.name}), ` +
    `which installs it for you. Install that instead:\n\n    npm install -g ${pkg.name}\n`
);
EOF
done
cp "$root/README.md" "$root/LICENSE" "$here/"
echo "staged $(node -p "require('$here/package.json').name") $npm_version and its platform packages"
