"use strict";

// Runs the prebuilt aes256 binary for this platform with the user's arguments,
// preceded by `command` (`encrypt` or `decrypt`) when one is given.

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

module.exports = function run(command) {
  const platform = `${process.platform}-${process.arch}`;
  const binary = path.join(__dirname, "..", "vendor", platform, "aes256");
  if (!fs.existsSync(binary)) {
    console.error(
      `encryptor: no binary for ${platform}. Supported: Linux and macOS on x64 and arm64.`
    );
    process.exit(1);
  }

  const args = process.argv.slice(2);
  if (command) {
    args.unshift(command);
  }

  const result = spawnSync(binary, args, { stdio: "inherit" });
  if (result.error) {
    console.error(`encryptor: could not run ${binary}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.signal) {
    // Die from the same signal (e.g. Ctrl-C) so the shell sees it and restores
    // the terminal, exactly as if the binary had been run directly.
    process.kill(process.pid, result.signal);
  }
  process.exit(result.status ?? 1);
};
