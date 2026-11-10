"use strict";

// Runs the prebuilt encryptor binary for this platform with the user's
// arguments, under `name`: encrypt, decrypt or encryptor. The
// binary tells from its name what to do, as it does when run through a link.
//
// Each platform's binary is in a package of its own, such as
// @neddyp/encryptor-linux-x64, which npm installs only on that platform.

const { spawn } = require("node:child_process");
const path = require("node:path");

const SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"];
const PLATFORMS = ["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"];

function binaryFor(platform) {
  if (!PLATFORMS.includes(platform)) {
    console.error(
      `encryptor: no binary for ${platform}. Supported: Linux and macOS on x64 and arm64.`
    );
    process.exit(1);
  }
  const pkg = `@neddyp/encryptor-${platform}`;
  try {
    return path.join(path.dirname(require.resolve(`${pkg}/package.json`)), "encryptor");
  } catch {
    console.error(
      `encryptor: ${pkg}, which holds the binary for this system, isn't installed. ` +
        `npm leaves it out when optional dependencies are turned off ` +
        `(--omit=optional, or optional=false in .npmrc). Install again with them on:\n` +
        `  npm install -g @neddyp/encryptor`
    );
    process.exit(1);
  }
}

module.exports = function run(name) {
  const binary = binaryFor(`${process.platform}-${process.arch}`);

  // `encryptor update` uses the npm beside this Node.js.
  const env = { ...process.env, ENCRYPTOR_NODE: process.execPath };
  const child = spawn(binary, process.argv.slice(2), { stdio: "inherit", argv0: name, env });

  // The binary handles Ctrl-C and similar signals itself, wiping keys and
  // removing partial files before it exits. Stay alive until it has, passing
  // on any signal sent only to this process.
  for (const signal of SIGNALS) {
    process.on(signal, () => child.kill(signal));
  }

  child.on("error", (error) => {
    console.error(`encryptor: could not run ${binary}: ${error.message}`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      // Die from the same signal so the shell sees it, as if the binary had
      // been run directly.
      process.removeAllListeners(signal);
      process.kill(process.pid, signal);
    }
    process.exit(code ?? 1);
  });
};
